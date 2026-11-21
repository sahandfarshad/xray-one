package main

// Panel-only data. Xray never reads this file; removing XRay One leaves the
// core exactly as it is.

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ClientMeta struct {
	Email      string                     `json:"email"`
	SubToken   string                     `json:"subToken"`
	ExpiryUnix int64                      `json:"expiry"`     // 0 = never
	LimitBytes int64                      `json:"limitBytes"` // 0 = unlimited
	Up         int64                      `json:"up"`
	Down       int64                      `json:"down"`
	Note       string                     `json:"note,omitempty"`
	Disabled   bool                       `json:"disabled"`
	Reason     string                     `json:"reason,omitempty"`
	Saved      map[string]json.RawMessage `json:"saved,omitempty"` // inbound id -> client json while disabled
}

type PanelConfig struct {
	Listen     string `json:"listen"`
	BasePath   string `json:"basePath"`
	User       string `json:"user"`
	PassHash   string `json:"passHash"`
	PublicHost string `json:"publicHost"`
	SubBase    string `json:"subBase"`
	Domain     string `json:"domain"`
	CertFile   string `json:"certFile"`
	KeyFile    string `json:"keyFile"`
	Managed    bool   `json:"managed"` // certificate issued and renewed by XRay One
	AcmeEmail  string `json:"acmeEmail"`
}

type Store struct {
	mu      sync.Mutex
	dir     string
	Cfg     PanelConfig            `json:"-"`
	Clients map[string]*ClientMeta `json:"clients"`
	// AllToken is the secret of the subscription that carries every config.
	AllToken string `json:"allToken"`
	// Relays: extra addresses (relay / CDN IPs) per inbound tag.
	Relays map[string][]Relay `json:"relays"`
	// Tunnels: middle servers; TunnelMap: inbound id -> tunnel server ids.
	Tunnels   []*TunnelServer     `json:"tunnels,omitempty"`
	TunnelCfg TunnelSettings      `json:"tunnelCfg"`
	TunnelMap map[string][]string `json:"tunnelMap,omitempty"`
}

type Relay struct {
	Address string `json:"address"`
	Port    int    `json:"port,omitempty"` // 0 = same as inbound
	Name    string `json:"name,omitempty"`
	Tunnel  string `json:"tunnel,omitempty"` // set when the address comes from a tunnel server
}

func (s *Store) RelaysOf(tag string) []Relay {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Relay{}, s.Relays[tag]...)
}

func (s *Store) EditRelays(fn func(m map[string][]Relay)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.Relays)
	return s.saveLocked()
}

func (s *Store) GetAllToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.AllToken
}

func (s *Store) ResetAllToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AllToken = randHex(16)
	_ = s.saveLocked()
	return s.AllToken
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, Clients: map[string]*ClientMeta{}}
	if b, err := os.ReadFile(filepath.Join(dir, "panel.json")); err == nil {
		_ = json.Unmarshal(b, &s.Cfg)
	}
	if s.Cfg.Listen == "" {
		s.Cfg.Listen = "127.0.0.1:2096"
	}
	s.Cfg.BasePath = normBase(s.Cfg.BasePath)
	if b, err := os.ReadFile(filepath.Join(dir, "state.json")); err == nil {
		_ = json.Unmarshal(b, s)
		if s.Clients == nil {
			s.Clients = map[string]*ClientMeta{}
		}
	}
	if s.Relays == nil {
		s.Relays = map[string][]Relay{}
	}
	if s.AllToken == "" {
		s.AllToken = randHex(16)
		_ = s.saveLocked()
	}
	return s, nil
}

func normBase(p string) string {
	p = "/" + strings.Trim(p, "/") + "/"
	if p == "//" {
		return "/"
	}
	return p
}

func (s *Store) SaveCfg() error {
	b, _ := json.MarshalIndent(s.Cfg, "", "  ")
	return writeAtomic(filepath.Join(s.dir, "panel.json"), b)
}

// saveLocked must be called with s.mu held.
func (s *Store) saveLocked() error {
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := filepath.Join(s.dir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, "state.json"))
}

func (s *Store) Meta(email string) *ClientMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.Clients[email]
	if m == nil {
		m = &ClientMeta{Email: email, SubToken: randHex(16)}
		s.Clients[email] = m
		_ = s.saveLocked()
	}
	cp := *m
	return &cp
}

func (s *Store) Update(email string, fn func(m *ClientMeta)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.Clients[email]
	if m == nil {
		m = &ClientMeta{Email: email, SubToken: randHex(16)}
		s.Clients[email] = m
	}
	fn(m)
	_ = s.saveLocked()
}

func (s *Store) Forget(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Clients, email)
	_ = s.saveLocked()
}

func (s *Store) ByToken(tok string) *ClientMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.Clients {
		if m.SubToken == tok && tok != "" {
			cp := *m
			return &cp
		}
	}
	return nil
}

func (s *Store) All() []ClientMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []ClientMeta{}
	for _, m := range s.Clients {
		out = append(out, *m)
	}
	return out
}

// ---------- background install / update job ----------

type Job struct {
	mu      sync.Mutex
	Running bool      `json:"running"`
	Action  string    `json:"action"`
	Log     string    `json:"log"`
	OK      bool      `json:"ok"`
	Done    time.Time `json:"done"`
}

type lockedWriter struct{ j *Job }

func (w lockedWriter) Write(p []byte) (int, error) {
	w.j.mu.Lock()
	defer w.j.mu.Unlock()
	w.j.Log += string(bytes.ReplaceAll(p, []byte("\r"), []byte("\n")))
	if len(w.j.Log) > 200000 {
		w.j.Log = w.j.Log[len(w.j.Log)-200000:]
	}
	return len(p), nil
}

const installScript = "https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

// StartCoreJob installs or updates Xray with the official XTLS script.
// The script keeps the existing config.json, so updating never touches it.
func (j *Job) StartCoreJob(action, version string) bool {
	j.mu.Lock()
	if j.Running {
		j.mu.Unlock()
		return false
	}
	j.Running, j.Action, j.Log, j.OK = true, action, "", false
	j.mu.Unlock()
	go func() {
		cmdline := "set -e; curl -fsSL " + installScript + " -o /tmp/xray-install.sh; bash /tmp/xray-install.sh install"
		if version != "" {
			cmdline += " --version " + version
		}
		cmd := exec.Command("bash", "-c", cmdline)
		w := lockedWriter{j}
		cmd.Stdout, cmd.Stderr = w, w
		err := cmd.Run()
		if err == nil {
			_, _ = run(20*time.Second, "systemctl", "enable", "xray")
			_, _ = run(20*time.Second, "systemctl", "restart", "xray")
		}
		j.mu.Lock()
		j.Running, j.OK, j.Done = false, err == nil, time.Now()
		if err != nil {
			j.Log += "\n" + err.Error()
		}
		j.mu.Unlock()
	}()
	return true
}

func (j *Job) Snapshot() Job {
	j.mu.Lock()
	defer j.mu.Unlock()
	return Job{Running: j.Running, Action: j.Action, Log: j.Log, OK: j.OK, Done: j.Done}
}
