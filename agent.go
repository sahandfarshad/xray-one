package main

// Tunnel agent: runs on a middle server. `xray-one agent install <join>`
// sets it up; `xray-one agent run` keeps a heartbeat with the main panel
// (through the tunnel itself) and applies the relay config it gets back.

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	agentDir     = "/etc/xray-one-agent"
	agentXrayDir = "/usr/local/lib/xray-one-agent"
	agentRelay   = "xray-one-relay"
	agentUnit    = "xray-one-agent"
)

type agentState struct {
	Join  joinInfo `json:"join"`
	Token string   `json:"token,omitempty"`
	Hash  string   `json:"hash,omitempty"`
	Ctl   int      `json:"ctl,omitempty"`
}

func agentMain(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: xray-one agent [install <join>|run|status|remove]")
		os.Exit(2)
	}
	var err error
	switch args[0] {
	case "install":
		if len(args) < 2 {
			err = errors.New("missing join code")
		} else {
			err = agentInstall(args[1])
		}
	case "run":
		agentRun()
	case "status":
		agentStatus()
	case "remove":
		_, _ = run(20*time.Second, "systemctl", "disable", "--now", agentUnit, agentRelay)
		_ = os.Remove("/etc/systemd/system/" + agentUnit + ".service")
		_ = os.Remove("/etc/systemd/system/" + agentRelay + ".service")
		_ = os.RemoveAll(agentDir)
		_ = os.RemoveAll(agentXrayDir)
		_, _ = run(20*time.Second, "systemctl", "daemon-reload")
		fmt.Println("Tunnel agent removed.")
	default:
		err = errors.New("unknown agent command")
	}
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func decodeJoin(s string) (joinInfo, error) {
	var j joinInfo
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return j, errors.New("invalid join code")
	}
	if err := json.Unmarshal(b, &j); err != nil || j.ID == "" || j.Domain == "" || j.UUID == "" {
		return j, errors.New("invalid join code")
	}
	return j, nil
}

func agentXray() string { return filepath.Join(agentXrayDir, "xray") }

func agentInstall(code string) error {
	j, err := decodeJoin(code)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("run as root")
	}
	step := func(n int, s string) { fmt.Printf("[%d/5] %s\n", n, s) }
	step(1, "Xray core")
	if _, err := os.Stat(agentXray()); err != nil {
		if err := downloadXray(agentXrayDir); err != nil {
			return fmt.Errorf("could not download Xray: %v", err)
		}
	}
	step(2, "relay config")
	if err := os.MkdirAll(agentDir, 0o700); err != nil {
		return err
	}
	st := agentState{Join: j}
	if old, err := loadAgent(); err == nil && old.Ctl > 0 {
		st.Ctl = old.Ctl
		_, _ = run(20*time.Second, "systemctl", "stop", agentRelay)
	}
	if st.Ctl == 0 || !portFree(st.Ctl) {
		st.Ctl = agentCtlPort
		for i := 0; i < 50 && !portFree(st.Ctl); i++ {
			st.Ctl = suggestPort()
		}
	}
	cfg := relayXrayConfig(j, nil, st.Ctl)
	if err := os.WriteFile(filepath.Join(agentDir, "xray.json"), cfg, 0o600); err != nil {
		return err
	}
	if err := saveAgent(st); err != nil {
		return err
	}
	if out, err := run(30*time.Second, agentXray(), "run", "-test", "-config", filepath.Join(agentDir, "xray.json")); err != nil {
		return fmt.Errorf("xray rejected the relay config: %s", out)
	}
	step(3, "services")
	self, _ := os.Executable()
	units := map[string]string{
		agentRelay: "[Unit]\nDescription=XRay One tunnel relay (xray)\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart=" +
			agentXray() + " run -config " + agentDir + "/xray.json\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n",
		agentUnit: "[Unit]\nDescription=XRay One tunnel agent (heartbeat)\nAfter=network-online.target " + agentRelay + ".service\nWants=network-online.target\n\n[Service]\nExecStart=" +
			self + " agent run\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n",
	}
	for n, u := range units {
		if err := os.WriteFile("/etc/systemd/system/"+n+".service", []byte(u), 0o644); err != nil {
			return err
		}
	}
	_, _ = run(20*time.Second, "systemctl", "daemon-reload")
	for _, n := range []string{agentRelay, agentUnit} {
		_, _ = run(20*time.Second, "systemctl", "enable", n)
		if out, err := run(30*time.Second, "systemctl", "restart", n); err != nil {
			return fmt.Errorf("could not start %s: %s", n, out)
		}
	}
	step(4, "connecting to the main server")
	for i := 0; i < 20; i++ {
		time.Sleep(3 * time.Second)
		if s, err := loadAgent(); err == nil && s.Token != "" {
			step(5, "connected. The tunnel shows green in the panel.")
			return nil
		}
	}
	step(5, "installed, still waiting for the main server. Check: xray-one agent status")
	return nil
}

func saveAgent(s agentState) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := filepath.Join(agentDir, "agent.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(agentDir, "agent.json"))
}

func loadAgent() (agentState, error) {
	var s agentState
	b, err := os.ReadFile(filepath.Join(agentDir, "agent.json"))
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}

func agentStatus() {
	s, err := loadAgent()
	if err != nil {
		fmt.Println("Tunnel agent is not installed.")
		return
	}
	relay, _ := run(5*time.Second, "systemctl", "is-active", agentRelay)
	ag, _ := run(5*time.Second, "systemctl", "is-active", agentUnit)
	fmt.Printf("main server: %s:%d\nrelay: %s\nagent: %s\njoined: %v\n", s.Join.Domain, s.Join.Port, relay, ag, s.Token != "")
}

func agentRun() {
	st, err := loadAgent()
	if err != nil {
		fmt.Println("agent not installed:", err)
		os.Exit(1)
	}
	if st.Ctl == 0 {
		st.Ctl = agentCtlPort
	}
	proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", st.Ctl))
	cl := &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy),
		// the hop runs inside the authenticated VLESS+TLS tunnel to 127.0.0.1
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	every := beatEvery
	var ip string
	var ipAt time.Time
	lastErr := ""
	fails, lastFail := 0, ""
	for {
		if time.Since(ipAt) > time.Hour || ip == "" {
			if v := publicIP(); v != "" {
				ip = v
			}
			ipAt = time.Now()
		}
		active, _ := run(5*time.Second, "systemctl", "is-active", agentRelay)
		req := beatReq{Version: version, PublicIP: ip, XrayOK: active == "active", XrayErr: lastErr, Applied: st.Hash, CtlPort: st.Ctl, Busy: busyPorts(st.Ctl),
			Wait: true, Fails: fails, LastFail: lastFail}
		body, _ := json.Marshal(req)
		hr, _ := http.NewRequest("POST", strings.TrimSuffix(st.Join.Panel, "/")+"/api/agent/beat", bytes.NewReader(body))
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("X-Agent-ID", st.Join.ID)
		tok := st.Token
		if tok == "" {
			tok = st.Join.Join
		}
		hr.Header.Set("X-Agent-Token", tok)
		resp, err := cl.Do(hr)
		next := every
		if err != nil {
			fmt.Println("heartbeat failed:", err)
			fails++
			lastFail = time.Now().UTC().Format("15:04:05Z ") + err.Error()
			next = 5 * time.Second
			// self-heal: restart the relay after 3 failures in a row
			if fails%3 == 0 {
				_, _ = run(30*time.Second, "systemctl", "restart", agentRelay)
			}
		} else {
			var br beatResp
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			if resp.StatusCode != 200 || json.Unmarshal(b, &br) != nil {
				fmt.Println("heartbeat rejected:", resp.StatusCode, strings.TrimSpace(string(b)))
				fails++
				lastFail = time.Now().UTC().Format("15:04:05Z ") + fmt.Sprintf("HTTP %d", resp.StatusCode)
				next = 10 * time.Second
			} else {
				fails = 0
				if br.Token != "" {
					st.Token = br.Token
					_ = saveAgent(st)
				}
				if len(br.Config) > 0 && br.Hash != st.Hash {
					if e := applyRelayConfig(br.Config); e != nil {
						lastErr = e.Error()
						fmt.Println(lastErr)
					} else {
						lastErr = ""
						st.Hash = br.Hash
						_ = saveAgent(st)
					}
				}
				if br.Every >= 10 && br.Every <= 600 {
					every = time.Duration(br.Every) * time.Second
				}
				next = every
				if br.Held || br.Probe {
					next = 200 * time.Millisecond
				}
			}
		}
		time.Sleep(next)
	}
}

// applyRelayConfig tests and applies a new relay config, rolling back when
// xray rejects it or fails to start.
func applyRelayConfig(cfg []byte) error {
	p := filepath.Join(agentDir, "xray.json")
	old, _ := os.ReadFile(p)
	tmp := filepath.Join(agentDir, "xray.next.json") // xray needs a .json name
	if err := os.WriteFile(tmp, cfg, 0o600); err != nil {
		return err
	}
	if out, err := run(30*time.Second, agentXray(), "run", "-test", "-config", tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("relay config rejected: %s", trimTo(out, 300))
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	_, _ = run(30*time.Second, "systemctl", "restart", agentRelay)
	time.Sleep(2 * time.Second)
	if a, _ := run(5*time.Second, "systemctl", "is-active", agentRelay); a != "active" {
		j, _ := run(5*time.Second, "journalctl", "-u", agentRelay, "-n", "5", "--no-pager")
		_ = os.WriteFile(p, old, 0o600)
		_, _ = run(30*time.Second, "systemctl", "restart", agentRelay)
		return fmt.Errorf("relay failed to start (port busy?): %s", trimTo(j, 300))
	}
	return nil
}

func downloadXray(dir string) error {
	name := "Xray-linux-64.zip"
	if runtime.GOARCH == "arm64" {
		name = "Xray-linux-arm64-v8a.zip"
	}
	c := &http.Client{Timeout: 3 * time.Minute}
	resp, err := c.Get("https://github.com/XTLS/Xray-core/releases/latest/download/" + name)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range zr.File {
		if f.Name != "xray" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "xray"), b, 0o755); err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		fmt.Printf("      xray downloaded (%x)\n", sum[:6])
		return nil
	}
	return errors.New("xray binary not found in archive")
}

// busyPorts lists ports listening on this server that are not our relay's
// own, so the panel never asks the relay to take a busy port.
func busyPorts(ctl int) []int {
	own := map[int]bool{ctl: true}
	if b, err := os.ReadFile(filepath.Join(agentDir, "xray.json")); err == nil {
		var c struct {
			Inbounds []struct {
				Port any `json:"port"`
			} `json:"inbounds"`
		}
		if json.Unmarshal(b, &c) == nil {
			for _, ib := range c.Inbounds {
				if f, ok := ib.Port.(float64); ok {
					own[int(f)] = true
				}
			}
		}
	}
	seen := map[int]bool{}
	var out []int
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile("/proc/net/" + f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 4 {
				continue
			}
			if strings.HasPrefix(f, "tcp") && fs[3] != "0A" { // LISTEN
				continue
			}
			k := strings.LastIndex(fs[1], ":")
			if k < 0 {
				continue
			}
			var port int
			if _, err := fmt.Sscanf(fs[1][k+1:], "%X", &port); err != nil || port == 0 || own[port] || seen[port] {
				continue
			}
			seen[port] = true
			out = append(out, port)
		}
	}
	sort.Ints(out)
	return out
}
