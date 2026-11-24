package main

// Tunnel agent: runs on a middle server. `xray-one agent install <join>`
// sets it up; `xray-one agent run` keeps a heartbeat with the main panel
// (through the tunnel itself) and applies the relay config it gets back.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
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
	// trying a new config (e.g. another tunnel method): when the panel can't
	// be reached with it for methodTrial, go back to the previous one
	PendingAt  int64  `json:"pendingAt,omitempty"`
	PrevHash   string `json:"prevHash,omitempty"`
	Rejected   string `json:"rejected,omitempty"`
	RejectedAt int64  `json:"rejectedAt,omitempty"`
	// path to the main server: "" forward (we dial it), "rev" reverse (it dials us)
	Mode   string `json:"mode,omitempty"`
	ModeAt int64  `json:"modeAt,omitempty"`
	Via    string `json:"via,omitempty"` // forward: way found by searching ("" the admin's method)
	// Let's Encrypt certificate for this server's own domain
	CertDomain string `json:"certDomain,omitempty"`
	CertExp    int64  `json:"certExp,omitempty"`
	CertErr    string `json:"certErr,omitempty"`
	CertTried  string `json:"certTried,omitempty"`
	CertTryAt  int64  `json:"certTryAt,omitempty"`
}

// revertPending puts the previous wanted config back.
func revertPending(st *agentState, rc *reconciler) {
	prev, err := os.ReadFile(filepath.Join(agentDir, "xray.prev.json"))
	if err != nil || len(prev) == 0 {
		st.PendingAt = 0
		_ = saveAgent(*st)
		return
	}
	_ = os.WriteFile(filepath.Join(agentDir, "xray.want.json"), prev, 0o600)
	st.Rejected, st.RejectedAt = st.Hash, time.Now().Unix()
	st.Hash, st.PendingAt = st.PrevHash, 0
	rc.failed = ""
	_ = saveAgent(*st)
	fmt.Println("new relay config did not work; went back to the previous one")
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
		agentCarriersRemove()
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
	} else if v := agentXrayVersion(agentXray()); v == "" || versionLess(v, minKCPXray) {
		// too old for the dedicated mKCP tunnel: get the current one (the
		// old one stays when the download fails)
		fmt.Printf("      Xray %s is old; updating\n", orDefault(v, "(unknown)"))
		if err := downloadXray(agentXrayDir); err != nil {
			fmt.Println("      could not update Xray, keeping the old one:", err)
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
	cfg := relayXrayConfig(j, nil, st.Ctl, nil)
	if err := os.WriteFile(filepath.Join(agentDir, "xray.json"), cfg, 0o600); err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(agentDir, "xray.want.json"), cfg, 0o600)
	if err := saveAgent(st); err != nil {
		return err
	}
	if out, err := run(30*time.Second, agentXray(), "run", "-test", "-config", filepath.Join(agentDir, "xray.json")); err != nil {
		return fmt.Errorf("xray rejected the relay config: %s", out)
	}
	if j.Method == tunnelMethodGRE && j.GRemote != "" && j.GAddr != "" {
		// starting on GRE: our end of the link comes up before the relay
		fmt.Println("      GRE link to", j.GRemote)
		if err := greLink("xo-gre", j.GRemote, j.GAddr, greMain); err != nil {
			return fmt.Errorf("could not bring up the GRE link: %v", err)
		}
	}
	step(3, "services (starting relay and agent)")
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
	step(4, "connecting to the main server (up to 60 s)")
	tty := isTTY()
	for i := 0; i < 20; i++ {
		time.Sleep(3 * time.Second)
		if s, err := loadAgent(); err == nil && s.Token != "" {
			if tty {
				fmt.Println()
			}
			step(5, "connected. The tunnel shows green in the panel.")
			return nil
		}
		if tty {
			fmt.Printf("\r      waiting for the main server... %2d s left ", 60-3*(i+1))
		} else if (i+1)%5 == 0 {
			fmt.Printf("      waiting for the main server... %d s left\n", 60-3*(i+1))
		}
	}
	if tty {
		fmt.Println()
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
	client := func(port int, to time.Duration) *http.Client {
		proxy, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
		return &http.Client{Timeout: to, Transport: &http.Transport{Proxy: http.ProxyURL(proxy),
			// the hop runs inside the authenticated VLESS tunnel to 127.0.0.1
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	// forward path (we dial the main server) and reverse path (a connection
	// the main server opened to us), each with a long timeout for held
	// heartbeats and a short one while searching
	cl, clShort := client(st.Ctl, 75*time.Second), client(st.Ctl, 20*time.Second)
	rv, rvShort := client(st.Ctl+1, 75*time.Second), client(st.Ctl+1, 12*time.Second)
	probeDirect := false // just left the reverse path: one short, unheld try
	clProbe := client(st.Ctl, probeLimit)
	var probeAt time.Time
	probeFails := 0
	every := beatEvery
	var ip string
	var ipAt time.Time
	lastErr := ""
	fails, lastFail := 0, ""
	var rc reconciler
	var sr agentSearch
	certCh := make(chan certResult, 1)
	certBusy := false
	xrayVer := agentXrayVersion(agentXray())
	for {
		select {
		case c := <-certCh:
			certBusy = false
			st.CertTried, st.CertTryAt, st.CertErr = c.domain, time.Now().Unix(), c.err
			if c.err == "" {
				st.CertDomain, st.CertExp = c.domain, c.exp
				fmt.Println("certificate ready for", c.domain)
			}
			_ = saveAgent(st)
		default:
		}
		ways := wantWays()
		if (st.Mode == "rev" && !wantHasRev()) || (st.Via != "" && !contains(ways, st.Via)) {
			st.Mode, st.Via, st.ModeAt = "", "", time.Now().Unix()
			_ = saveAgent(st)
		}
		rc.route = routeOf(st)
		if time.Since(ipAt) > time.Hour || ip == "" {
			if v := publicIP(); v != "" {
				ip = v
			}
			if v := agentXrayVersion(agentXray()); v != "" {
				xrayVer = v
			}
			ipAt = time.Now()
		}
		pstate, busy, rerr := rc.run()
		if st.PendingAt > 0 && rc.failed != "" { // the new config does not even start
			revertPending(&st, &rc)
			pstate, busy, rerr = rc.run()
		}
		if rerr != "" {
			lastErr = rerr
		} else if fails == 0 {
			lastErr = ""
		}
		active, _ := run(5*time.Second, "systemctl", "is-active", agentRelay)
		mkReq := func(mode string, wait bool) []byte {
			req := beatReq{Version: version, PublicIP: ip, XrayOK: active == "active", XrayErr: lastErr, Applied: st.Hash, CtlPort: st.Ctl, Busy: busy,
				Wait: wait, Fails: fails, LastFail: lastFail, PortState: pstate, Rejected: st.Rejected, Pending: st.PendingAt > 0,
				Mode: mode, Via: st.Via, CertDom: st.CertDomain, CertExp: st.CertExp, CertErr: st.CertErr, CertBusy: certBusy, CertFor: st.CertTried, CState: agentCarrierState(), SSHHost: agentHostPub(),
				XrayVer: xrayVer}
			req.SniErr, req.SniList, req.SniSeen = sniSvc.Report()
			req.SniN = len(req.SniList)
			if mode == "rev" {
				req.Via = ""
			}
			b, _ := json.Marshal(req)
			return b
		}
		wasPending := st.PendingAt > 0
		resting := !sr.active && time.Now().Before(sr.cool)
		var br *beatResp
		reached, ferr := false, "resting"
		if !resting {
			c := cl
			if st.Mode == "rev" {
				c = rv
			}
			if fails > 0 || probeDirect {
				c = clShort
				if st.Mode == "rev" {
					c = rvShort
				}
			}
			br, reached, ferr = sendBeat(c, st, mkReq(st.Mode, fails == 0 && !probeDirect))
			probeDirect = false
		}
		// the heartbeat got through; does real traffic? (see dataprobe.go)
		probeBad := false
		if br != nil && st.Mode != "rev" && st.Token != "" && (sr.active || fails > 0 || time.Since(probeAt) > probeEvery) {
			probeAt = time.Now()
			if ok, msg := agentProbe(clProbe, st); ok {
				probeFails = 0
			} else {
				probeFails++
				fmt.Println(msg)
				if probeFails >= 2 || sr.active {
					// this way is broken for real traffic: count it as a failed
					// round and move on to the next way
					br, reached, ferr, probeBad = nil, false, msg, true
					probeFails = 0
					fails = max(fails, searchTries-1)
					if sr.active {
						sr.tries = searchTries - 1
					}
				} else {
					probeAt = time.Time{} // test again next round
				}
			}
		}
		// meanwhile the main server searches for us too: if a connection it
		// opened is here, that path wins
		if br == nil && !reached && !probeBad && st.Mode != "rev" && st.PendingAt == 0 && wantHasRev() {
			if b2, _, _ := sendBeat(rvShort, st, mkReq("rev", false)); b2 != nil {
				fmt.Println("the main server reached us (reverse path); using it")
				st.Mode, st.Via, st.ModeAt = "rev", "", time.Now().Unix()
				_ = saveAgent(st)
				br = b2
			}
		}
		next := every
		if br == nil {
			if !resting {
				fmt.Println("heartbeat failed:", ferr)
				fails++
				lastFail = time.Now().UTC().Format("15:04:05Z ") + ferr
			}
			// back off while the main server can't be reached: 5, 10, 20, 40, 60, 60 … s
			next = 5 * time.Second << min(max(fails, 1)-1, 4)
			if next > time.Minute {
				next = time.Minute
			}
			if reached { // it answered but refused: searching would not help
				next = 10 * time.Second
			}
			if st.PendingAt > 0 && next > 10*time.Second { // trying a new method: decide quickly
				next = 10 * time.Second
			}
			if st.PendingAt > 0 && time.Since(time.Unix(st.PendingAt, 0)) > methodTrial {
				revertPending(&st, &rc)
				next = 200 * time.Millisecond
			}
			canSearch := !reached && st.PendingAt == 0 && (len(ways) > 1 || wantHasRev())
			switch {
			case !canSearch:
				// self-heal: restart the relay after 3 failures in a row
				if fails > 0 && fails%3 == 0 {
					_, _ = run(30*time.Second, "systemctl", "restart", agentRelay)
				}
			case resting:
				next = 10 * time.Second // only listening for the main server
			case !sr.active && (fails >= searchTries || sr.fromStart):
				// our way failed a few times: try the next ones, one by one
				fromStart := sr.fromStart
				sr = agentSearch{active: true, ways: ways}
				if !fromStart && st.Mode != "rev" {
					sr.idx = index(ways, st.Via) + 1
				}
				sr.step(&st)
				next = searchGap
			case sr.active:
				sr.tries++
				if sr.tries >= searchTries {
					sr.idx++
					sr.step(&st)
				}
				next = searchGap
			}
			if !sr.active && !resting && time.Now().Before(sr.cool) {
				next = 10 * time.Second
			}
		} else {
			if fails > 0 {
				fmt.Printf("connected again (%s)\n", pathName(st))
			}
			fails, sr = 0, agentSearch{}
			if br.Domain != "" && !certBusy && needCert(st, br.Domain) {
				certBusy = true
				if st.CertTried != br.Domain { // the old domain's error is not this one's
					st.CertErr = ""
				}
				go func(d string) {
					r := certResult{domain: d}
					cf, err := obtainCertAgent(d)
					if err != nil {
						r.err = trimTo(err.Error(), 300)
					} else if exp, _, e := certExpiry(cf); e == nil {
						r.exp = exp.Unix()
					}
					certCh <- r
				}(br.Domain)
			}
			if br.Token != "" {
				st.Token = br.Token
				_ = saveAgent(st)
			}
			agentStartTest(br.Test, st) // a manual tunnel test, in the background
			agentStartRCheck(br.RCheck, st)
			agentCarriers(br.Carriers, st)
			agentSni(br.Sni, st)
			newCfg := false
			if wasPending && st.PendingAt > 0 { // reached the panel with the new config
				st.PendingAt = 0
				_ = saveAgent(st)
			}
			if st.Rejected != "" && br.Hash != st.Rejected {
				st.Rejected, st.RejectedAt = "", 0
				_ = saveAgent(st)
			}
			if st.Rejected != "" && br.Hash == st.Rejected && time.Since(time.Unix(st.RejectedAt, 0)) < 10*time.Minute {
				br.Config = nil // just went back from it
			}
			if len(br.Config) > 0 && br.Hash != st.Hash {
				if cur, e := os.ReadFile(filepath.Join(agentDir, "xray.want.json")); e == nil && st.Hash != "" {
					_ = os.WriteFile(filepath.Join(agentDir, "xray.prev.json"), cur, 0o600)
					st.PrevHash, st.PendingAt = st.Hash, time.Now().Unix()
				}
				// keep what the panel wants; rc.run() applies it minus busy ports
				if e := os.WriteFile(filepath.Join(agentDir, "xray.want.json"), br.Config, 0o600); e == nil {
					st.Hash = br.Hash
					// a method the admin picked starts on its own way; on the
					// reverse path we leave it to try the new method directly
					// (on failure the trial reverts and the reverse path takes over)
					if st.Mode == "rev" {
						fmt.Println("new method from the panel: leaving the reverse path to try it")
						st.Mode, st.ModeAt = "", time.Now().Unix()
						probeDirect = true
					}
					st.Via = ""
					_ = saveAgent(st)
					rc.failed = ""
					newCfg = true
				}
			}
			// on the reverse path: try the direct path again now and then, so
			// the middle server does not stay there after the direct way heals
			// (a failed try costs one short heartbeat; the reverse path is
			// taken back in the same round)
			if !newCfg && st.Mode == "rev" && st.PendingAt == 0 && time.Since(time.Unix(st.ModeAt, 0)) > revRetry {
				fmt.Println("on the reverse path for a while: trying the direct path again")
				st.Mode, st.Via, st.ModeAt = "", "", time.Now().Unix()
				_ = saveAgent(st)
				probeDirect = true
			}
			if br.Every >= 10 && br.Every <= 600 {
				every = time.Duration(br.Every) * time.Second
			}
			next = every
			if br.Held || br.Probe || newCfg {
				next = 200 * time.Millisecond
			}
		}
		time.Sleep(next)
	}
}

// agentSearch: the middle server trying its ways to the main server one by
// one, then resting.
type agentSearch struct {
	active    bool
	ways      []string // "" = the method the admin picked, then the others
	idx       int
	tries     int
	cool      time.Time
	fromStart bool // rested: next search starts from the first way
}

func (sr *agentSearch) step(st *agentState) {
	sr.tries = 0
	st.Mode, st.ModeAt = "", time.Now().Unix()
	if sr.idx >= len(sr.ways) {
		*sr = agentSearch{cool: time.Now().Add(revCool), fromStart: true}
		st.Via = ""
		fmt.Printf("no way to the main server worked; resting %v (still listening for it)\n", revCool)
	} else {
		st.Via = sr.ways[sr.idx]
		fmt.Printf("trying way %d/%d to the main server: %s\n", sr.idx+1, len(sr.ways), orDefault(st.Via, "its own method"))
	}
	_ = saveAgent(*st)
}

func pathName(st agentState) string {
	if st.Mode == "rev" {
		return "reverse path"
	}
	return "direct, " + orDefault(st.Via, "own method")
}

// sendBeat posts one heartbeat. reached: the panel answered (even with an error).
func sendBeat(c *http.Client, st agentState, body []byte) (*beatResp, bool, string) {
	hr, _ := http.NewRequest("POST", strings.TrimSuffix(st.Join.Panel, "/")+"/api/agent/beat", bytes.NewReader(body))
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("X-Agent-ID", st.Join.ID)
	tok := st.Token
	if tok == "" {
		tok = st.Join.Join
	}
	hr.Header.Set("X-Agent-Token", tok)
	resp, err := c.Do(hr)
	if err != nil {
		return nil, false, err.Error()
	}
	var br beatResp
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != 200 || json.Unmarshal(b, &br) != nil {
		fmt.Println("heartbeat rejected:", resp.StatusCode, strings.TrimSpace(string(b)))
		return nil, true, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return &br, true, ""
}

func routeOf(st agentState) string {
	switch {
	case st.Mode == "rev":
		return relayRevOut
	case st.Via != "":
		return relayAltPrefix + st.Via
	}
	return ""
}

func contains(l []string, s string) bool { return index(l, s) >= 0 }

func index(l []string, s string) int {
	for i, x := range l {
		if x == s {
			return i
		}
	}
	return -1
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

// downloadXray gets the Xray core: GitHub (3 tries, 3 s apart), then the main
// server's own xray binary when its architecture matches (checked against the
// mirror's SHA256SUMS), then GitHub once more. No step can hang: 10 s to
// connect, 20 s for an answer, and a transfer stalled for 30 s is dropped.
func downloadXray(dir string) error {
	name := "Xray-linux-64.zip"
	arch := runtime.GOARCH
	if arch == "arm64" {
		name = "Xray-linux-arm64-v8a.zip"
	}
	gh := os.Getenv("XO_XRAY_BASE")
	if gh == "" {
		gh = "https://github.com/XTLS/Xray-core/releases/latest/download"
	}
	mirror := strings.TrimRight(os.Getenv("XO_MIRROR"), "/")
	fromZip := func(data []byte) ([]byte, error) {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if f.Name != "xray" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(rc)
			rc.Close()
			return b, err
		}
		return nil, errors.New("xray binary not found in archive")
	}
	github := func(label string) ([]byte, error) {
		data, err := dlProgress(label, gh+"/"+name, 200<<20)
		if err != nil {
			return nil, err
		}
		return fromZip(data)
	}
	fromMirror := func() ([]byte, error) {
		file := "xray-linux-" + arch
		sums, err := dlProgress("", mirror+"/SHA256SUMS", 1<<16)
		if err != nil {
			return nil, err
		}
		want := ""
		for _, l := range strings.Split(string(sums), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[1] == file {
				want = f[0]
			}
		}
		if want == "" {
			return nil, errors.New("the main server has no Xray for " + arch)
		}
		b, err := dlProgress("main server", mirror+"/"+file, 200<<20)
		if err != nil {
			return nil, err
		}
		if s := sha256.Sum256(b); fmt.Sprintf("%x", s) != want {
			return nil, errors.New("checksum mismatch")
		}
		fmt.Println("      checksum verified")
		return b, nil
	}
	var b []byte
	var err error
	for i := 1; i <= 3 && b == nil; i++ {
		if i > 1 {
			fmt.Println("      waiting 3 s...")
			time.Sleep(3 * time.Second)
		}
		if b, err = github(fmt.Sprintf("GitHub (try %d/3)", i)); err != nil {
			fmt.Println("      GitHub failed:", err)
			b = nil
		}
	}
	if b == nil && mirror != "" {
		fmt.Println("      GitHub did not answer; trying the main server (backup)...")
		if b, err = fromMirror(); err != nil {
			fmt.Println("      main server failed:", err)
			b = nil
		}
	}
	if b == nil {
		fmt.Println("      trying GitHub again...")
		if b, err = github("GitHub again"); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "xray.tmp")
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "xray")); err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	fmt.Printf("      xray downloaded (%x)\n", sum[:6])
	return nil
}

// dlProgress downloads u with a percent line (label "" = quiet). A dead
// connection fails in 10 s, a missing answer in 20 s, a stall in 30 s.
func dlProgress(label, u string, limit int64) ([]byte, error) {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	if label != "" {
		fmt.Printf("      %s: connecting...\n", label)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tty := isTTY()
	total := resp.ContentLength
	var buf bytes.Buffer
	chunk := make([]byte, 64<<10)
	stall := time.AfterFunc(30*time.Second, cancel)
	defer stall.Stop()
	last := -1
	for {
		n, rerr := resp.Body.Read(chunk)
		if n > 0 {
			stall.Reset(30 * time.Second)
			buf.Write(chunk[:n])
			if int64(buf.Len()) > limit {
				return nil, errors.New("file too large")
			}
			if label != "" {
				pct := -1
				if total > 0 {
					pct = int(int64(buf.Len()) * 100 / total)
				}
				switch {
				case tty && pct >= 0 && pct != last:
					fmt.Printf("\r      %s: %3d%%  %.1f / %.1f MB", label, pct, float64(buf.Len())/1e6, float64(total)/1e6)
				case tty && pct < 0:
					fmt.Printf("\r      %s: %.1f MB", label, float64(buf.Len())/1e6)
				case !tty && pct >= 0 && pct/25 != last/25:
					fmt.Printf("      %s: %d%%\n", label, pct)
				}
				if pct >= 0 {
					last = pct
				}
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			if tty && label != "" {
				fmt.Println()
			}
			if ctx.Err() != nil {
				return nil, errors.New("download stalled or too slow")
			}
			return nil, rerr
		}
	}
	if tty && label != "" {
		fmt.Println()
	}
	if total > 0 && int64(buf.Len()) != total {
		return nil, errors.New("download incomplete")
	}
	return buf.Bytes(), nil
}

func isTTY() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// ---------- ports on the middle server ----------

type listener struct {
	inode string
	tcp   bool
}

// scanListeners maps each listening TCP port / bound UDP port to its sockets.
func scanListeners() map[int][]listener {
	out := map[int][]listener{}
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile("/proc/net/" + f)
		if err != nil {
			continue
		}
		tcp := strings.HasPrefix(f, "tcp")
		for i, line := range strings.Split(string(b), "\n") {
			fs := strings.Fields(line)
			if i == 0 || len(fs) < 10 {
				continue
			}
			if tcp && fs[3] != "0A" { // LISTEN
				continue
			}
			k := strings.LastIndex(fs[1], ":")
			if k < 0 {
				continue
			}
			var port int
			if _, err := fmt.Sscanf(fs[1][k+1:], "%X", &port); err != nil || port == 0 {
				continue
			}
			out[port] = append(out[port], listener{inode: fs[9], tcp: tcp})
		}
	}
	return out
}

// relayInodes: sockets held by the running relay xray.
func relayInodes() map[string]bool {
	own := map[string]bool{}
	pid, _ := run(5*time.Second, "systemctl", "show", "-p", "MainPID", "--value", agentRelay)
	pid = strings.TrimSpace(pid)
	if pid == "" || pid == "0" {
		return own
	}
	ents, err := os.ReadDir("/proc/" + pid + "/fd")
	if err != nil {
		return own
	}
	for _, e := range ents {
		l, err := os.Readlink("/proc/" + pid + "/fd/" + e.Name())
		if err == nil && strings.HasPrefix(l, "socket:[") {
			own[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	return own
}

// portView answers, per port, whether another program holds it and whether
// our relay listens on it.
type portView struct {
	ls  map[int][]listener
	own map[string]bool
}

func newPortView() portView { return portView{ls: scanListeners(), own: relayInodes()} }

func (v portView) foreign(p int) bool {
	for _, l := range v.ls[p] {
		if !v.own[l.inode] && l.inode != "0" {
			return true
		}
	}
	return false
}

func (v portView) ours(p int) bool {
	for _, l := range v.ls[p] {
		if l.tcp && v.own[l.inode] {
			return true
		}
	}
	return false
}

// busy: every port another program uses (the panel avoids them).
func (v portView) busy() []int {
	var out []int
	for p := range v.ls {
		if v.foreign(p) {
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

// fwdPorts lists the forwarded ports of a relay config.
func fwdPorts(cfg []byte) []int {
	var c struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
			Port     any    `json:"port"`
		} `json:"inbounds"`
	}
	var out []int
	if json.Unmarshal(cfg, &c) == nil {
		for _, ib := range c.Inbounds {
			if f, ok := ib.Port.(float64); ok && ib.Protocol == "dokodemo-door" {
				out = append(out, int(f))
			}
		}
	}
	return out
}

// dropPorts removes forwarded inbounds on the given ports from a relay config.
func dropPorts(cfg []byte, drop map[int]bool) []byte {
	if len(drop) == 0 {
		return cfg
	}
	v, err := ParseOrdered(cfg)
	if err != nil {
		return cfg
	}
	root := asMap(v)
	var keep []any
	for _, x := range asArr(root.Get("inbounds")) {
		ib := asMap(x)
		if ib != nil && asStr(ib.Get("protocol")) == "dokodemo-door" {
			if n, err := strconv.Atoi(fmt.Sprint(ib.Get("port"))); err == nil && drop[n] {
				continue
			}
		}
		keep = append(keep, x)
	}
	root.Set("inbounds", keep)
	return EncodeIndent(root)
}

// reconciler keeps the relay running the wanted config minus ports another
// program holds, and reports every wanted port as ok / busy / down.
type reconciler struct {
	failed   string // config that failed to start
	failedAt time.Time
	route    string // outbound all traffic takes ("" the main one)
}

func (r *reconciler) run() (state map[string]string, busy []int, errMsg string) {
	want, err := os.ReadFile(filepath.Join(agentDir, "xray.want.json"))
	if err != nil { // agents older than 0.5.1 kept only xray.json
		want, _ = os.ReadFile(filepath.Join(agentDir, "xray.json"))
	}
	pv := newPortView()
	drop := map[int]bool{}
	for _, p := range fwdPorts(want) {
		if pv.foreign(p) {
			drop[p] = true
		}
	}
	if len(want) > 0 {
		next := dropPorts(want, drop)
		next = setPathRule(next, r.route)
		cur, _ := os.ReadFile(filepath.Join(agentDir, "xray.json"))
		if !bytes.Equal(next, cur) && !(string(next) == r.failed && time.Since(r.failedAt) < 10*time.Minute) {
			if e := applyRelayConfig(next); e != nil {
				r.failed, r.failedAt = string(next), time.Now()
				errMsg = e.Error()
			} else {
				r.failed = ""
			}
			pv = newPortView()
		} else if string(next) == r.failed {
			errMsg = "relay config failed to start; retrying in a few minutes"
		}
	}
	state = map[string]string{}
	for _, p := range fwdPorts(want) {
		switch {
		case drop[p] || pv.foreign(p):
			state[strconv.Itoa(p)] = "busy"
		case pv.ours(p):
			state[strconv.Itoa(p)] = "ok"
		default:
			state[strconv.Itoa(p)] = "down"
		}
	}
	return state, pv.busy(), errMsg
}

type certResult struct {
	domain, err string
	exp         int64
}

// needCert: no valid certificate for the domain yet (or under 30 days left),
// retrying a failed attempt every 30 minutes.
func needCert(st agentState, d string) bool {
	if st.CertDomain == d && time.Until(time.Unix(st.CertExp, 0)) > 30*24*time.Hour {
		return false
	}
	if st.CertTried == d && st.CertErr != "" && time.Since(time.Unix(st.CertTryAt, 0)) < 30*time.Minute {
		return false
	}
	if st.CertTried == d && st.CertErr == "" && st.CertDomain == d && time.Since(time.Unix(st.CertTryAt, 0)) < 12*time.Hour {
		return false
	}
	return true
}

// wantHasRev: the wanted relay config has the reverse path.
func wantHasRev() bool {
	b, err := os.ReadFile(filepath.Join(agentDir, "xray.want.json"))
	return err == nil && relayHasRule(b, relayCtlRev)
}

// wantWays: our ways to the main server: "" (the admin's method) and the
// other methods the panel offers.
func wantWays() []string {
	w := []string{""}
	b, err := os.ReadFile(filepath.Join(agentDir, "xray.want.json"))
	if err != nil {
		return w
	}
	var c struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(b, &c) == nil {
		for _, o := range c.Outbounds {
			if strings.HasPrefix(o.Tag, relayAltPrefix) {
				w = append(w, strings.TrimPrefix(o.Tag, relayAltPrefix))
			}
		}
	}
	return w
}

// setPathRule sends all traffic (heartbeat and forwarded ports) to outbound
// tag; "" leaves it on the main one.
func setPathRule(cfg []byte, tag string) []byte {
	if tag == "" {
		return cfg
	}
	v, err := ParseOrdered(cfg)
	if err != nil {
		return cfg
	}
	root := asMap(v)
	var tags []any
	for _, x := range asArr(root.Get("inbounds")) {
		t := asStr(asMap(x).Get("tag"))
		if t == "ctl" || strings.HasPrefix(t, "fwd-") {
			tags = append(tags, t)
		}
	}
	rt := asMap(root.Get("routing"))
	if rt == nil {
		rt = om()
		root.Set("routing", rt)
	}
	rules := append([]any{om("type", "field", "ruleTag", relayPathRule, "inboundTag", tags, "outboundTag", tag)}, asArr(rt.Get("rules"))...)
	rt.Set("rules", rules)
	return EncodeIndent(root)
}

// obtainCertAgent gets the Let's Encrypt certificate on the middle server.
// When a web server holds port 80, it is stopped for the moment it takes and
// started again; tunnel programs are never stopped.
func obtainCertAgent(d string) (string, error) {
	if !portFree(80) {
		unit := port80Unit()
		if unit == "" {
			return "", errors.New("port 80 is busy and the program holding it is not a service that can be paused; free port 80 for a minute")
		}
		low := strings.ToLower(unit)
		for _, no := range []string{"xray", "muse", "x-ui", "3x-ui", "marzban", "sing-box", "hysteria", "docker", "containerd", "sshd"} {
			if strings.Contains(low, no) {
				return "", fmt.Errorf("port 80 is used by %s, which is not paused; free port 80 for a minute", unit)
			}
		}
		fmt.Printf("pausing %s for a moment to get the certificate (port 80)\n", unit)
		if out, err := run(30*time.Second, "systemctl", "stop", unit); err != nil {
			return "", fmt.Errorf("could not pause %s: %s", unit, trimTo(out, 200))
		}
		defer func() {
			if out, err := run(30*time.Second, "systemctl", "start", unit); err != nil {
				fmt.Printf("could not start %s again: %s\n", unit, out)
			} else {
				fmt.Println(unit, "started again")
			}
		}()
		for i := 0; i < 20 && !portFree(80); i++ {
			time.Sleep(250 * time.Millisecond)
		}
	}
	cf, _, err := ObtainCert(agentDir, d, "", func(string, ...any) {})
	return cf, err
}

// port80Unit: the systemd service listening on port 80, if any.
func port80Unit() string { return portUnit(80) }

// portUnit: the systemd service listening on port p, if any.
func portUnit(p int) string {
	inodes := map[string]bool{}
	for _, l := range scanListeners()[p] {
		if l.inode != "0" {
			inodes["socket:["+l.inode+"]"] = true
		}
	}
	procs, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range procs {
		fds, _ := os.ReadDir(filepath.Join(p, "fd"))
		for _, fd := range fds {
			if l, err := os.Readlink(filepath.Join(p, "fd", fd.Name())); err == nil && inodes[l] {
				cg, _ := os.ReadFile(filepath.Join(p, "cgroup"))
				for _, part := range strings.Split(strings.TrimSpace(string(cg)), "/") {
					if strings.HasSuffix(part, ".service") {
						return part
					}
				}
				return ""
			}
		}
	}
	return ""
}
