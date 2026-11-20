package main

// Detection of the Xray core and safe, minimal edits to its config.
// XRay One never replaces the binary or the systemd unit: config.json stays
// the single source of truth, so Xray keeps working headless without us.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultConfig = "/usr/local/etc/xray/config.json"

type Core struct {
	Installed  bool   `json:"installed"`
	Bin        string `json:"bin"`
	Version    string `json:"version"`
	Service    string `json:"service"`
	Active     string `json:"active"`
	ConfigPath string `json:"configPath"`
	ConfDir    string `json:"confDir"`
	ConfigOK   bool   `json:"configOk"`
	ConfigErr  string `json:"configErr"`
	APIAddr    string `json:"apiAddr"`
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

var reArgv = regexp.MustCompile(`argv\[\]=([^;]+)`)

func DetectCore() Core {
	c := Core{Service: "xray"}
	if p, err := exec.LookPath("xray"); err == nil {
		c.Bin = p
	} else {
		for _, p := range []string{"/usr/local/bin/xray", "/usr/bin/xray"} {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				c.Bin = p
				break
			}
		}
	}
	if c.Bin == "" {
		return c
	}
	c.Installed = true
	if out, err := run(5*time.Second, c.Bin, "version"); err == nil {
		f := strings.Fields(strings.SplitN(out, "\n", 2)[0])
		if len(f) >= 2 {
			c.Version = f[1]
		}
	}
	c.Active, _ = run(5*time.Second, "systemctl", "is-active", c.Service)
	c.ConfigPath = defaultConfig
	if exe, err := run(5*time.Second, "systemctl", "show", c.Service, "-p", "ExecStart", "--value"); err == nil {
		if m := reArgv.FindStringSubmatch(exe); m != nil {
			args := strings.Fields(m[1])
			for i := 0; i < len(args); i++ {
				a := args[i]
				val := func() string {
					if strings.Contains(a, "=") {
						return strings.SplitN(a, "=", 2)[1]
					}
					if i+1 < len(args) {
						i++
						return args[i]
					}
					return ""
				}
				switch {
				case a == "-config" || a == "-c" || strings.HasPrefix(a, "-config="):
					c.ConfigPath = val()
				case a == "-confdir" || strings.HasPrefix(a, "-confdir="):
					c.ConfDir = val()
				}
			}
		}
	}
	if p := os.Getenv("XRAY_ONE_XRAY_CONFIG"); p != "" {
		c.ConfigPath = p
	}
	if c.ConfDir != "" {
		// pick the file in confdir that holds the inbounds
		files, _ := filepath.Glob(filepath.Join(c.ConfDir, "*.json"))
		sort.Strings(files)
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if v, err := ParseOrdered(data); err == nil && asMap(v).Has("inbounds") {
				c.ConfigPath = f
				break
			}
		}
	}
	if data, err := os.ReadFile(c.ConfigPath); err != nil {
		c.ConfigErr = err.Error()
	} else if v, err := ParseOrdered(data); err != nil || asMap(v) == nil {
		c.ConfigErr = "config is not plain JSON (comments or invalid); XRay One will only read it"
	} else {
		c.ConfigOK = true
		c.APIAddr = apiAddr(asMap(v))
	}
	return c
}

// ---------- config store ----------

type ConfigStore struct {
	mu        sync.Mutex
	backupDir string
}

func (s *ConfigStore) Load() (*OMap, Core, error) {
	core := DetectCore()
	if !core.Installed {
		return nil, core, errors.New("xray is not installed")
	}
	data, err := os.ReadFile(core.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return NewOMap(), core, nil
		}
		return nil, core, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return NewOMap(), core, nil
	}
	v, err := ParseOrdered(data)
	if err != nil {
		return nil, core, fmt.Errorf("cannot parse config: %w", err)
	}
	root := asMap(v)
	if root == nil {
		return nil, core, errors.New("config root is not an object")
	}
	return root, core, nil
}

// Mutate reads the config fresh, applies fn, backs up, writes atomically,
// validates with `xray run -test` and restarts the service. On a failed test
// the original file is restored untouched.
func (s *ConfigStore) Mutate(fn func(root *OMap) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	root, core, err := s.Load()
	if err != nil {
		return err
	}
	orig, _ := os.ReadFile(core.ConfigPath)
	if err := fn(root); err != nil {
		return err
	}
	out := EncodeIndent(root)
	if bytes.Equal(out, orig) {
		return nil
	}
	if err := s.backup(orig); err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}
	if err := writeAtomic(core.ConfigPath, out); err != nil {
		return err
	}
	if err := testConfig(core); err != nil {
		_ = writeAtomic(core.ConfigPath, orig)
		return fmt.Errorf("xray rejected the new config, nothing changed: %v", err)
	}
	return restartCore(core)
}

func (s *ConfigStore) RestoreRaw(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	core := DetectCore()
	if _, err := ParseOrdered(data); err != nil {
		return err
	}
	orig, _ := os.ReadFile(core.ConfigPath)
	if err := s.backup(orig); err != nil {
		return err
	}
	if err := writeAtomic(core.ConfigPath, data); err != nil {
		return err
	}
	if err := testConfig(core); err != nil {
		_ = writeAtomic(core.ConfigPath, orig)
		return fmt.Errorf("xray rejected this backup: %v", err)
	}
	return restartCore(core)
}

func (s *ConfigStore) backup(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if err := os.MkdirAll(s.backupDir, 0o700); err != nil {
		return err
	}
	name := filepath.Join(s.backupDir, "config-"+time.Now().Format("20060102-150405.000")+".json")
	if err := os.WriteFile(name, data, 0o600); err != nil {
		return err
	}
	files, _ := filepath.Glob(filepath.Join(s.backupDir, "config-*.json"))
	sort.Strings(files)
	for len(files) > 40 {
		os.Remove(files[0])
		files = files[1:]
	}
	return nil
}

func (s *ConfigStore) Backups() []string {
	files, _ := filepath.Glob(filepath.Join(s.backupDir, "config-*.json"))
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	out := []string{}
	for _, f := range files {
		out = append(out, filepath.Base(f))
	}
	return out
}

func writeAtomic(p string, data []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(p); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".xray-one.tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func testConfig(core Core) error {
	args := []string{"run", "-test"}
	if core.ConfDir != "" {
		args = append(args, "-confdir", core.ConfDir)
	} else {
		args = append(args, "-config", core.ConfigPath)
	}
	out, err := run(20*time.Second, core.Bin, args...)
	if err != nil {
		lines := strings.Split(out, "\n")
		if len(lines) > 6 {
			lines = lines[len(lines)-6:]
		}
		return errors.New(strings.Join(lines, " | "))
	}
	return nil
}

func restartCore(core Core) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	if out, err := run(30*time.Second, "systemctl", "restart", core.Service); err != nil {
		return fmt.Errorf("config saved but restart failed: %s", out)
	}
	return nil
}

// ---------- inbounds & clients ----------

type ClientView struct {
	Email    string      `json:"email"`
	Secret   string      `json:"secret"`
	Flow     string      `json:"flow,omitempty"`
	Link     string      `json:"link"`
	Meta     *ClientMeta `json:"meta,omitempty"`
	Disabled bool        `json:"disabled"`
}

type InboundView struct {
	ID       string       `json:"id"`
	Tag      string       `json:"tag"`
	Protocol string       `json:"protocol"`
	Port     string       `json:"port"`
	Listen   string       `json:"listen"`
	Network  string       `json:"network"`
	Security string       `json:"security"`
	Managed  bool         `json:"managed"` // supports clients
	System   bool         `json:"system"`  // api inbound etc.
	Clients  []ClientView `json:"clients"`
}

func inboundID(ib *OMap, i int) string {
	if t := asStr(ib.Get("tag")); t != "" {
		return t
	}
	return "#" + strconv.Itoa(i)
}

func findInbound(root *OMap, id string) (*OMap, int) {
	for i, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		if ib != nil && inboundID(ib, i) == id {
			return ib, i
		}
	}
	return nil, -1
}

func supportsClients(ib *OMap) bool {
	switch asStr(ib.Get("protocol")) {
	case "vless", "vmess", "trojan":
		return true
	case "shadowsocks":
		return path(ib, "settings", "clients") != nil
	}
	return false
}

func clientSecret(proto string, c *OMap) string {
	if proto == "vless" || proto == "vmess" {
		return asStr(c.Get("id"))
	}
	return asStr(c.Get("password"))
}

func streamInfo(ib *OMap) (network, security string) {
	ss := asMap(ib.Get("streamSettings"))
	network = asStr(ss.Get("network"))
	if network == "" {
		network = "tcp"
	}
	security = asStr(ss.Get("security"))
	if security == "" {
		security = "none"
	}
	return
}

func apiTag(root *OMap) string { return pathStr(root, "api", "tag") }

func apiAddr(root *OMap) string {
	if l := pathStr(root, "api", "listen"); l != "" {
		return l
	}
	tag := apiTag(root)
	if tag == "" {
		return ""
	}
	for _, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		p := asStr(ib.Get("protocol"))
		if asStr(ib.Get("tag")) == tag && (p == "dokodemo-door" || p == "tunnel") {
			l := asStr(ib.Get("listen"))
			if l == "" {
				l = "127.0.0.1"
			}
			return l + ":" + asStr(ib.Get("port"))
		}
	}
	return ""
}

func usedPorts(root *OMap) map[string]bool {
	m := map[string]bool{}
	for _, v := range asArr(root.Get("inbounds")) {
		m[asStr(asMap(v).Get("port"))] = true
	}
	return m
}

// EnableAPI adds the stats/handler API on 127.0.0.1 so traffic can be read.
// It only adds what is missing and never rewrites existing sections.
func EnableAPI(root *OMap) error {
	if apiAddr(root) != "" {
		return nil
	}
	if !root.Has("stats") {
		root.Set("stats", NewOMap())
	}
	if !root.Has("api") {
		root.Set("api", om("tag", "api", "services", []any{"HandlerService", "StatsService"}))
	}
	tag := apiTag(root)
	pol := asMap(root.Get("policy"))
	if pol == nil {
		pol = NewOMap()
		root.Set("policy", pol)
	}
	levels := asMap(pol.Get("levels"))
	if levels == nil {
		levels = NewOMap()
		pol.Set("levels", levels)
	}
	l0 := asMap(levels.Get("0"))
	if l0 == nil {
		l0 = NewOMap()
		levels.Set("0", l0)
	}
	l0.Set("statsUserUplink", true)
	l0.Set("statsUserDownlink", true)
	port := 10085
	used := usedPorts(root)
	for used[strconv.Itoa(port)] {
		port++
	}
	inb := asArr(root.Get("inbounds"))
	inb = append(inb, om("tag", tag, "listen", "127.0.0.1", "port", port, "protocol", "dokodemo-door",
		"settings", om("address", "127.0.0.1")))
	root.Set("inbounds", inb)
	routing := asMap(root.Get("routing"))
	if routing == nil {
		routing = NewOMap()
		root.Set("routing", routing)
	}
	rules := asArr(routing.Get("rules"))
	rule := om("type", "field", "inboundTag", []any{tag}, "outboundTag", tag)
	routing.Set("rules", append([]any{rule}, rules...))
	return nil
}

func ensureOutbounds(root *OMap) {
	if len(asArr(root.Get("outbounds"))) == 0 {
		root.Set("outbounds", []any{
			om("protocol", "freedom", "tag", "direct"),
			om("protocol", "blackhole", "tag", "block"),
		})
	}
}

type NewInbound struct {
	Protocol    string `json:"protocol"`
	Port        int    `json:"port"`
	Tag         string `json:"tag"`
	Network     string `json:"network"`
	Security    string `json:"security"`
	Path        string `json:"path"`
	ServiceName string `json:"serviceName"`
	ServerName  string `json:"serverName"`
	CertFile    string `json:"certFile"`
	KeyFile     string `json:"keyFile"`
	Dest        string `json:"dest"`
}

func BuildInbound(root *OMap, n NewInbound) (*OMap, error) {
	if n.Port < 1 || n.Port > 65535 {
		return nil, errors.New("invalid port")
	}
	if usedPorts(root)[strconv.Itoa(n.Port)] {
		return nil, fmt.Errorf("port %d is already used by another inbound", n.Port)
	}
	if n.Tag == "" {
		n.Tag = fmt.Sprintf("%s-%d", n.Protocol, n.Port)
	}
	if ib, _ := findInbound(root, n.Tag); ib != nil {
		return nil, fmt.Errorf("tag %q already exists", n.Tag)
	}
	var settings *OMap
	switch n.Protocol {
	case "vless":
		settings = om("clients", []any{}, "decryption", "none")
	case "vmess", "trojan":
		settings = om("clients", []any{})
	case "shadowsocks":
		settings = om("method", "2022-blake3-aes-128-gcm", "password", randB64(16), "clients", []any{}, "network", "tcp,udp")
	default:
		return nil, errors.New("unsupported protocol")
	}
	if n.Network == "" {
		n.Network = "tcp"
	}
	if n.Security == "" {
		n.Security = "none"
	}
	stream := om("network", n.Network, "security", n.Security)
	switch n.Network {
	case "tcp", "raw":
	case "ws":
		stream.Set("wsSettings", om("path", orDefault(n.Path, "/"+randHex(4))))
	case "grpc":
		stream.Set("grpcSettings", om("serviceName", orDefault(n.ServiceName, randHex(4))))
	case "xhttp":
		stream.Set("xhttpSettings", om("path", orDefault(n.Path, "/"+randHex(4))))
	case "httpupgrade":
		stream.Set("httpupgradeSettings", om("path", orDefault(n.Path, "/"+randHex(4))))
	default:
		return nil, errors.New("unsupported network")
	}
	switch n.Security {
	case "none":
	case "tls":
		if n.CertFile == "" || n.KeyFile == "" {
			return nil, errors.New("TLS needs certificate and key file paths")
		}
		stream.Set("tlsSettings", om("serverName", n.ServerName,
			"certificates", []any{om("certificateFile", n.CertFile, "keyFile", n.KeyFile)}))
	case "reality":
		if n.Protocol != "vless" && n.Protocol != "trojan" {
			return nil, errors.New("REALITY works with VLESS or Trojan")
		}
		priv, _, err := genX25519()
		if err != nil {
			return nil, err
		}
		dest := orDefault(n.Dest, "www.microsoft.com:443")
		sn := n.ServerName
		if sn == "" {
			sn = strings.Split(dest, ":")[0]
		}
		stream.Set("realitySettings", om("show", false, "dest", dest, "xver", 0,
			"serverNames", []any{sn}, "privateKey", priv, "shortIds", []any{randHex(4)}))
	default:
		return nil, errors.New("unsupported security")
	}
	ib := om("tag", n.Tag, "listen", "0.0.0.0", "port", n.Port, "protocol", n.Protocol,
		"settings", settings, "streamSettings", stream,
		"sniffing", om("enabled", true, "destOverride", []any{"http", "tls", "quic"}))
	return ib, nil
}

func NewClient(ib *OMap, email string) (*OMap, error) {
	proto := asStr(ib.Get("protocol"))
	network, security := streamInfo(ib)
	switch proto {
	case "vless":
		c := om("id", newUUID(), "email", email, "level", 0)
		if (network == "tcp" || network == "raw") && (security == "reality" || security == "tls") {
			c.Set("flow", "xtls-rprx-vision")
		}
		return c, nil
	case "vmess":
		return om("id", newUUID(), "email", email, "level", 0), nil
	case "trojan":
		return om("password", randHex(12), "email", email, "level", 0), nil
	case "shadowsocks":
		method := pathStr(ib, "settings", "method")
		switch method {
		case "2022-blake3-aes-128-gcm":
			return om("password", randB64(16), "email", email, "level", 0), nil
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
			return om("password", randB64(32), "email", email, "level", 0), nil
		}
		return om("method", method, "password", randHex(12), "email", email, "level", 0), nil
	}
	return nil, errors.New("this inbound does not take clients")
}

var reEmail = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,64}$`)

func clientsOf(ib *OMap) []any { return asArr(path(ib, "settings", "clients")) }

func setClients(ib *OMap, cl []any) {
	s := asMap(ib.Get("settings"))
	if s == nil {
		s = NewOMap()
		ib.Set("settings", s)
	}
	s.Set("clients", cl)
}

func removeClient(ib *OMap, email string) (*OMap, bool) {
	cl := clientsOf(ib)
	for i, v := range cl {
		c := asMap(v)
		if c != nil && asStr(c.Get("email")) == email {
			setClients(ib, append(append([]any{}, cl[:i]...), cl[i+1:]...))
			return c, true
		}
	}
	return nil, false
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// statsQuery reads per-user traffic through `xray api statsquery` and resets
// the counters, so XRay One can accumulate totals across core restarts.
func statsQuery(core Core, addr string) (map[string][2]int64, error) {
	out, err := run(10*time.Second, core.Bin, "api", "statsquery", "--server="+addr, "-pattern", "user>>>", "-reset")
	if err != nil {
		return nil, fmt.Errorf("statsquery: %s", out)
	}
	var res struct {
		Stat []struct {
			Name  string `json:"name"`
			Value any    `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		return nil, err
	}
	m := map[string][2]int64{}
	for _, s := range res.Stat {
		p := strings.Split(s.Name, ">>>")
		if len(p) != 4 {
			continue
		}
		var v int64
		switch t := s.Value.(type) {
		case float64:
			v = int64(t)
		case string:
			v, _ = strconv.ParseInt(t, 10, 64)
		}
		cur := m[p[1]]
		if p[3] == "uplink" {
			cur[0] += v
		} else {
			cur[1] += v
		}
		m[p[1]] = cur
	}
	return m, nil
}
