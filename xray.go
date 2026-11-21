package main

// Detection of the Xray core and safe, minimal edits to its config.
// XRay One never replaces the binary or the systemd unit: config.json stays
// the single source of truth, so Xray keeps working headless without us.

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"syscall"
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
	procCfg, procDir := runningXrayArgs()
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
	// a running xray process is the most reliable source (custom units, Muse99, screen…)
	if procCfg != "" || procDir != "" {
		c.ConfigPath, c.ConfDir = orDefault(procCfg, c.ConfigPath), procDir
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
	return restartOrRollback(core, orig)
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
	return restartOrRollback(core, orig)
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
	uid, gid := -1, -1
	if st, err := os.Stat(p); err == nil {
		mode = st.Mode().Perm()
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(sys.Uid), int(sys.Gid)
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".xray-one.tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	_ = os.Chmod(tmp, mode) // umask-proof
	if uid >= 0 {
		// keep the original owner so a non-root xray service can still read it
		_ = os.Chown(tmp, uid, gid)
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
	name, full := core.Bin, args
	if u := serviceUser(core); u != "" && u != "root" {
		// test the way the service will read it: as its own user
		if rp, err := exec.LookPath("runuser"); err == nil {
			name, full = rp, append([]string{"-u", u, "--", core.Bin}, args...)
		}
	}
	out, err := run(20*time.Second, name, full...)
	if err != nil {
		lines := strings.Split(out, "\n")
		if len(lines) > 6 {
			lines = lines[len(lines)-6:]
		}
		return errors.New(strings.Join(lines, " | "))
	}
	return nil
}

// serviceUser returns the User= of the xray unit ("" when unknown/root).
func serviceUser(core Core) string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return ""
	}
	out, err := run(5*time.Second, "systemctl", "show", "-p", "User", "--value", core.Service)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func serviceActive(core Core) bool {
	out, _ := run(5*time.Second, "systemctl", "is-active", core.Service)
	return strings.TrimSpace(out) == "active"
}

// restartOrRollback restarts xray and makes sure it stays up. If it was up
// before and does not come back, the previous config is restored and xray is
// restarted again, so the panel can never leave the core dead.
func restartOrRollback(core Core, orig []byte) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	wasActive := serviceActive(core)
	rerr := restartCore(core)
	if rerr == nil {
		time.Sleep(2 * time.Second)
		if serviceActive(core) {
			return nil
		}
	}
	if !wasActive || len(orig) == 0 {
		if rerr != nil {
			return rerr
		}
		return errors.New("config saved, but xray is not running (it was not running before either); check: journalctl -u " + core.Service)
	}
	logs, _ := run(5*time.Second, "journalctl", "-u", core.Service, "-n", "5", "--no-pager", "-o", "cat")
	_ = writeAtomic(core.ConfigPath, orig)
	_ = restartCore(core)
	return fmt.Errorf("xray did not start with the new config, previous config restored: %s", strings.ReplaceAll(logs, "\n", " | "))
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
	Relays   []string    `json:"relayLinks,omitempty"`
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
	Relays   []Relay      `json:"relays"`
	Single   string       `json:"singleLink,omitempty"` // single-user shadowsocks
	Tunnels  []TunnelLink `json:"tunnels"`
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
	case "vless", "vmess", "trojan", "hysteria", "wireguard":
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
	if proto == "hysteria" {
		return asStr(c.Get("auth"))
	}
	if proto == "wireguard" {
		return asStr(c.Get("privateKey"))
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
	Protocol    string       `json:"protocol"`
	Port        int          `json:"port"`
	Tag         string       `json:"tag"`
	Network     string       `json:"network"`
	Security    string       `json:"security"`
	Path        string       `json:"path"`
	ServiceName string       `json:"serviceName"`
	ServerName  string       `json:"serverName"`
	CertFile    string       `json:"certFile"`
	KeyFile     string       `json:"keyFile"`
	Dest        string       `json:"dest"`
	Method      string       `json:"method"` // shadowsocks
	HeaderType  string       `json:"headerType"`
	Flow        string       `json:"-"`
	Reality     *RealityOpts `json:"reality,omitempty"`
	VlessEnc    string       `json:"vlessEnc,omitempty"` // "" / none / mlkem768x25519plus
}

const vlessEncName = "mlkem768x25519plus"

// newVlessDecryption: VLESS Encryption (ML-KEM-768 + X25519 key exchange, X25519 auth).
func newVlessDecryption() (string, error) {
	priv, _, err := genX25519()
	if err != nil {
		return "", err
	}
	return vlessEncName + ".native.600s." + priv, nil
}

// vlessClientEncryption turns the server's decryption string into the client's.
func vlessClientEncryption(dec string) string {
	if dec == "" || dec == "none" {
		return "none"
	}
	p := strings.Split(dec, ".")
	if len(p) < 4 {
		return "none"
	}
	pub := pubFromPriv(p[len(p)-1])
	if pub == "" {
		return "none" // ML-KEM auth key: public part can't be derived here
	}
	return p[0] + "." + p[1] + ".0rtt." + pub
}

// visionOK: VLESS Vision flow fits raw TCP with TLS, REALITY or VLESS Encryption.
func visionOK(ib *OMap) bool {
	if asStr(ib.Get("protocol")) != "vless" {
		return false
	}
	network, security := streamInfo(ib)
	if network != "tcp" && network != "raw" {
		return false
	}
	dec := pathStr(ib, "settings", "decryption")
	return security == "reality" || security == "tls" || (dec != "" && dec != "none")
}

func wgKeyPair() (priv, pub string, err error) {
	pr, pb, err := genX25519()
	if err != nil {
		return
	}
	a, _ := base64.RawURLEncoding.DecodeString(pr)
	b, _ := base64.RawURLEncoding.DecodeString(pb)
	return base64.StdEncoding.EncodeToString(a), base64.StdEncoding.EncodeToString(b), nil
}

func wgPub(priv string) string {
	k, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(k) != 32 {
		return ""
	}
	p := pubFromPriv(base64.RawURLEncoding.EncodeToString(k))
	b, _ := base64.RawURLEncoding.DecodeString(p)
	if len(b) != 32 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// nextWGAddr: first free 10.66.0.x/32 among the peers.
func nextWGAddr(ib *OMap) string {
	used := map[string]bool{}
	for _, v := range clientsOf(ib) {
		for _, a := range asArr(asMap(v).Get("allowedIPs")) {
			used[asStr(a)] = true
		}
	}
	for i := 2; i < 255; i++ {
		a := fmt.Sprintf("10.66.0.%d/32", i)
		if !used[a] {
			return a
		}
	}
	return ""
}

// RealityOpts: the full REALITY form (like 3x-ui). Empty fields get defaults.
type RealityOpts struct {
	Show         bool     `json:"show"`
	Xver         int      `json:"xver"`
	Fingerprint  string   `json:"fingerprint"`
	Target       string   `json:"target"`
	ServerNames  []string `json:"serverNames"`
	MaxTimeDiff  int64    `json:"maxTimeDiff"`
	MinClientVer string   `json:"minClientVer"`
	MaxClientVer string   `json:"maxClientVer"`
	ShortIDs     []string `json:"shortIds"`
	SpiderX      string   `json:"spiderX"`
	PrivateKey   string   `json:"privateKey"`
}

var reShortID = regexp.MustCompile(`^([0-9a-f]{2}){0,8}$`)
var reClientVer = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func buildReality(n NewInbound) (*OMap, error) {
	o := RealityOpts{}
	if n.Reality != nil {
		o = *n.Reality
	}
	clean := func(in []string) []string {
		var out []string
		for _, v := range in {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	target := strings.TrimSpace(orDefault(o.Target, orDefault(n.Dest, "www.microsoft.com:443")))
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	names := clean(o.ServerNames)
	if len(names) == 0 && n.ServerName != "" {
		names = []string{n.ServerName}
	}
	if len(names) == 0 {
		names = []string{strings.Split(target, ":")[0]}
	}
	priv := strings.TrimSpace(o.PrivateKey)
	pub := ""
	if priv == "" {
		var err error
		if priv, pub, err = genX25519(); err != nil {
			return nil, err
		}
	} else if pub = pubFromPriv(priv); pub == "" {
		return nil, errors.New("REALITY private key is not a valid x25519 key")
	}
	sids := clean(o.ShortIDs)
	hasEmpty := false
	for _, v := range o.ShortIDs {
		if strings.TrimSpace(v) == "" {
			hasEmpty = true
		}
	}
	for i, v := range sids {
		sids[i] = strings.ToLower(v)
		if !reShortID.MatchString(sids[i]) {
			return nil, fmt.Errorf("short ID %q: use 0-16 hex characters, even length", v)
		}
	}
	if hasEmpty {
		sids = append(sids, "")
	}
	if len(sids) == 0 {
		sids = []string{randHex(4)}
	}
	for _, v := range []string{o.MinClientVer, o.MaxClientVer} {
		if v != "" && !reClientVer.MatchString(v) {
			return nil, fmt.Errorf("client version %q: use x.y.z", v)
		}
	}
	if o.Xver < 0 || o.Xver > 2 {
		return nil, errors.New("xver must be 0, 1 or 2")
	}
	fp := orDefault(strings.TrimSpace(o.Fingerprint), "chrome")
	spx := strings.TrimSpace(o.SpiderX)
	if spx == "" {
		spx = "/"
	}
	sidAny := make([]any, len(sids))
	for i, v := range sids {
		sidAny[i] = v
	}
	nameAny := make([]any, len(names))
	for i, v := range names {
		nameAny[i] = v
	}
	rs := om("show", o.Show, "dest", target, "xver", o.Xver, "serverNames", nameAny, "privateKey", priv)
	if o.MinClientVer != "" {
		rs.Set("minClientVer", o.MinClientVer)
	}
	if o.MaxClientVer != "" {
		rs.Set("maxClientVer", o.MaxClientVer)
	}
	if o.MaxTimeDiff > 0 {
		rs.Set("maxTimeDiff", o.MaxTimeDiff)
	}
	rs.Set("shortIds", sidAny)
	// client-side values for links (xray ignores this block; 3x-ui uses the same one)
	rs.Set("settings", om("publicKey", pub, "fingerprint", fp, "serverName", "", "spiderX", spx))
	return rs, nil
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
		dec := "none"
		if n.VlessEnc == vlessEncName {
			var err error
			if dec, err = newVlessDecryption(); err != nil {
				return nil, err
			}
		}
		settings = om("clients", []any{}, "decryption", dec)
	case "vmess", "trojan":
		settings = om("clients", []any{})
	case "shadowsocks":
		method := orDefault(n.Method, "2022-blake3-aes-128-gcm")
		klen := 32
		switch method {
		case "2022-blake3-aes-128-gcm":
			klen = 16
		case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305", "xchacha20-ietf-poly1305":
			klen = 0
		default:
			return nil, errors.New("unsupported shadowsocks method")
		}
		if klen == 0 {
			settings = om("method", method, "clients", []any{}, "network", "tcp,udp")
		} else {
			settings = om("method", method, "password", randB64(klen), "clients", []any{}, "network", "tcp,udp")
		}
	case "hysteria":
		settings = om("version", 2, "clients", []any{})
		n.Network = "hysteria"
		if n.Security != "tls" {
			return nil, errors.New("Hysteria2 needs TLS (a domain certificate)")
		}
	case "wireguard":
		priv, _, err := wgKeyPair()
		if err != nil {
			return nil, err
		}
		settings = om("secretKey", priv, "peers", []any{}, "mtu", 1420)
		n.Network, n.Security = "udp", "none"
	case "socks":
		settings = om("auth", "password", "accounts", []any{om("user", "u"+randHex(3), "pass", randHex(8))}, "udp", true)
		n.Network, n.Security = "tcp", "none"
	case "http":
		settings = om("accounts", []any{om("user", "u"+randHex(3), "pass", randHex(8))})
		n.Network, n.Security = "tcp", "none"
	default:
		return nil, errors.New("unsupported protocol")
	}
	if n.Protocol == "wireguard" {
		return om("tag", n.Tag, "listen", "0.0.0.0", "port", n.Port, "protocol", n.Protocol, "settings", settings), nil
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
		if n.HeaderType == "http" {
			stream.Set("tcpSettings", om("header", om("type", "http",
				"request", om("path", []any{"/"}, "headers", om("Host", []any{"www.bing.com"})))))
		}
	case "kcp":
		stream.Set("kcpSettings", om("header", om("type", "none")))
	case "hysteria":
		stream.Set("hysteriaSettings", om("version", 2))
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
		cf, kf, err := xrayReadableCert(n.CertFile, n.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("cannot prepare certificate for xray: %v", err)
		}
		tlsS := om("serverName", n.ServerName,
			"certificates", []any{om("certificateFile", cf, "keyFile", kf)})
		if n.Network == "hysteria" {
			tlsS.Set("alpn", []any{"h3"})
		}
		stream.Set("tlsSettings", tlsS)
	case "reality":
		if n.Protocol != "vless" && n.Protocol != "trojan" {
			return nil, errors.New("REALITY works with VLESS or Trojan")
		}
		rs, err := buildReality(n)
		if err != nil {
			return nil, err
		}
		stream.Set("realitySettings", rs)
	default:
		return nil, errors.New("unsupported security")
	}
	if n.Protocol == "socks" || n.Protocol == "http" {
		return om("tag", n.Tag, "listen", "0.0.0.0", "port", n.Port, "protocol", n.Protocol,
			"settings", settings,
			"sniffing", om("enabled", true, "destOverride", []any{"http", "tls", "quic"})), nil
	}
	ib := om("tag", n.Tag, "listen", "0.0.0.0", "port", n.Port, "protocol", n.Protocol,
		"settings", settings, "streamSettings", stream,
		"sniffing", om("enabled", true, "destOverride", []any{"http", "tls", "quic"}))
	return ib, nil
}

func NewClient(ib *OMap, email string) (*OMap, error) {
	proto := asStr(ib.Get("protocol"))
	switch proto {
	case "vless":
		c := om("id", newUUID(), "email", email, "level", 0)
		if visionOK(ib) {
			c.Set("flow", "xtls-rprx-vision")
		}
		return c, nil
	case "wireguard":
		priv, pub, err := wgKeyPair()
		if err != nil {
			return nil, err
		}
		addr := nextWGAddr(ib)
		if addr == "" {
			return nil, errors.New("no free WireGuard address left")
		}
		// email and privateKey are kept for the panel (links, names); xray ignores them
		return om("email", email, "publicKey", pub, "privateKey", priv, "allowedIPs", []any{addr}), nil
	case "vmess":
		return om("id", newUUID(), "email", email, "level", 0), nil
	case "trojan":
		return om("password", randHex(12), "email", email, "level", 0), nil
	case "hysteria":
		return om("auth", randHex(12), "email", email, "level", 0), nil
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

func clientsKey(ib *OMap) string {
	if asStr(ib.Get("protocol")) == "wireguard" {
		return "peers"
	}
	return "clients"
}

func clientsOf(ib *OMap) []any { return asArr(path(ib, "settings", clientsKey(ib))) }

func setClients(ib *OMap, cl []any) {
	s := asMap(ib.Get("settings"))
	if s == nil {
		s = NewOMap()
		ib.Set("settings", s)
	}
	s.Set(clientsKey(ib), cl)
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

// runningXrayArgs reads -config / -confdir from a running xray process.
func runningXrayArgs() (cfg, dir string) {
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range procs {
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		if filepath.Base(args[0]) != "xray" {
			continue
		}
		for i := 1; i < len(args); i++ {
			a := args[i]
			next := ""
			if i+1 < len(args) {
				next = args[i+1]
			}
			switch {
			case a == "-config" || a == "-c" || a == "--config":
				cfg = next
			case strings.HasPrefix(a, "-config="):
				cfg = strings.TrimPrefix(a, "-config=")
			case a == "-confdir" || a == "--confdir":
				dir = next
			case strings.HasPrefix(a, "-confdir="):
				dir = strings.TrimPrefix(a, "-confdir=")
			}
		}
		if cfg != "" || dir != "" {
			if cfg != "" && !filepath.IsAbs(cfg) {
				if cwd, err := os.Readlink(filepath.Join(filepath.Dir(p), "cwd")); err == nil {
					cfg = filepath.Join(cwd, cfg)
				}
			}
			return
		}
	}
	return "", ""
}
