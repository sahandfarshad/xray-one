package main

// Tunnels: middle (relay) servers that forward users to this server.
//
//   user -> middle server :P  (dokodemo-door, raw TCP/UDP pass-through)
//        -> VLESS + WebSocket + TLS to this server's tunnel inbound (xo-tunnel)
//        -> 127.0.0.1:P here, the real inbound -> free internet
//
// The user's own protocol (REALITY, TLS, ...) runs end to end, so links only
// change their address. The agent on the middle server reaches the panel
// through the same tunnel (a local SOCKS inbound), so the panel can stay
// private. Methods are pluggable; "wss" is the first.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	tunnelTag      = "xo-tunnel"
	tunnelDirect   = "xo-direct"
	tunnelBlock    = "xo-block"
	agentCtlPort   = 10885
	beatEvery      = 30 * time.Second
	onlineWindow   = 95 * time.Second
	joinTTL        = 24 * time.Hour
	tunnelInstall  = "https://raw.githubusercontent.com/sahandfarshad/xray-one/main/tunnel.sh"
	tunnelMethodWS = "wss"
)

type TunnelServer struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Method   string `json:"method"`
	Host     string `json:"host,omitempty"` // SSH address / public address
	SSHPort  int    `json:"sshPort,omitempty"`
	SSHUser  string `json:"sshUser,omitempty"`
	HostKey  string `json:"hostKey,omitempty"` // TOFU, "ssh-ed25519 AAAA..."
	KeyOK    bool   `json:"keyInstalled,omitempty"`
	UUID     string `json:"uuid"`
	Token    string `json:"token,omitempty"`
	Join     string `json:"join,omitempty"`
	JoinExp  int64  `json:"joinExp,omitempty"`
	LastSeen int64  `json:"lastSeen,omitempty"`
	PublicIP string `json:"publicIP,omitempty"`
	AgentVer string `json:"agentVer,omitempty"`
	XrayOK   bool   `json:"xrayOk,omitempty"`
	XrayErr  string `json:"xrayErr,omitempty"`
	Applied  string `json:"applied,omitempty"` // config hash the agent runs
	CtlPort  int    `json:"ctlPort,omitempty"` // agent's local control port
	Busy     []int  `json:"busy,omitempty"`    // ports already taken on the middle server
}

// TunnelUse: one inbound goes through one middle server, listening there on
// Port (0 = same port as the inbound).
type TunnelUse struct {
	Server string `json:"server"`
	Port   int    `json:"port,omitempty"`
}

func (u TunnelUse) ListenPort(inboundPort int) int {
	if u.Port > 0 {
		return u.Port
	}
	return inboundPort
}

type TunnelSettings struct {
	Port int    `json:"port,omitempty"`
	Path string `json:"path,omitempty"`
}

// ---------- store ----------

func (s *Store) TunnelsCopy() ([]TunnelServer, TunnelSettings, map[string][]TunnelUse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []TunnelServer{}
	for _, t := range s.Tunnels {
		out = append(out, *t)
	}
	m := map[string][]TunnelUse{}
	for k, v := range s.TunnelUse {
		m[k] = append([]TunnelUse{}, v...)
	}
	return out, s.TunnelCfg, m
}

func (s *Store) EditTunnels(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TunnelUse == nil {
		s.TunnelUse = map[string][]TunnelUse{}
	}
	if err := fn(); err != nil {
		return err
	}
	return s.saveLocked()
}

func (s *Store) tunnelByID(id string) *TunnelServer {
	for _, t := range s.Tunnels {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// ---------- xray config on this server ----------

var cfPorts = []int{2083, 2087, 2096, 8443, 2053}

func (a *App) ensureTunnelSettings(root *OMap) error {
	return a.store.EditTunnels(func() error {
		c := &a.store.TunnelCfg
		if c.Path == "" {
			c.Path = "/" + randHex(6)
		}
		if c.Port == 0 {
			if ib, _ := findInbound(root, tunnelTag); ib != nil {
				c.Port, _ = strconv.Atoi(asStr(ib.Get("port")))
			}
		}
		if c.Port == 0 {
			used := usedPorts(root)
			for _, p := range cfPorts {
				if !used[strconv.Itoa(p)] && portFree(p) {
					c.Port = p
					break
				}
			}
			if c.Port == 0 {
				c.Port = suggestPort()
			}
		}
		if c.Port == 0 {
			return errors.New("no free port for the tunnel")
		}
		return nil
	})
}

// targetOf returns where traffic for a tunneled inbound goes on this server.
func targetOf(ib *OMap) (host string, port int) {
	port, _ = strconv.Atoi(linkPort(ib))
	host = asStr(ib.Get("listen"))
	if host == "" || host == "0.0.0.0" || host == "::" || strings.HasPrefix(host, "/") || strings.HasPrefix(host, "@") {
		host = "127.0.0.1"
	}
	if strings.Contains(asStr(ib.Get("port")), ",") || strings.Contains(asStr(ib.Get("port")), "-") {
		port = 0 // port ranges are not tunneled
	}
	return
}

// applyTunnelConfig writes the tunnel inbound, its clients and the routing
// that only lets tunnel traffic reach the tunneled inbounds and the panel.
func (a *App) applyTunnelConfig(root *OMap) error {
	servers, set, tmap := a.store.TunnelsCopy()
	// remove when unused
	if len(servers) == 0 {
		var keep []any
		for _, v := range asArr(root.Get("inbounds")) {
			if asStr(asMap(v).Get("tag")) != tunnelTag {
				keep = append(keep, v)
			}
		}
		if keep == nil {
			keep = []any{}
		}
		root.Set("inbounds", keep)
		setTunnelRules(root, nil)
		return nil
	}
	cf, kf := a.store.Cfg.CertFile, a.store.Cfg.KeyFile
	dom := a.store.Cfg.Domain
	if cf == "" || kf == "" || dom == "" {
		return errors.New("the WSS tunnel needs this server's domain and SSL: set SSL in the SSH menu first")
	}
	rcf, rkf, err := xrayReadableCert(cf, kf)
	if err != nil {
		return fmt.Errorf("cannot prepare certificate for xray: %v", err)
	}
	var clients []any
	for _, s := range servers {
		clients = append(clients, om("id", s.UUID, "email", "tunnel-"+s.ID, "level", 0))
	}
	ib, _ := findInbound(root, tunnelTag)
	if ib == nil {
		if usedPorts(root)[strconv.Itoa(set.Port)] {
			return fmt.Errorf("tunnel port %d is already used by another inbound", set.Port)
		}
		ib = om("tag", tunnelTag, "listen", "0.0.0.0", "port", set.Port, "protocol", "vless")
		root.Set("inbounds", append(asArr(root.Get("inbounds")), ib))
	}
	ib.Set("port", set.Port)
	ib.Set("protocol", "vless")
	ib.Set("settings", om("clients", clients, "decryption", "none"))
	ib.Set("streamSettings", om("network", "ws", "security", "tls",
		"tlsSettings", om("serverName", dom, "certificates", []any{om("certificateFile", rcf, "keyFile", rkf)}),
		"wsSettings", om("path", set.Path)))
	ib.Delete("sniffing")

	// allowed destinations
	ips := map[string]bool{"127.0.0.1": true}
	ports := map[int]bool{}
	if p, err := strconv.Atoi(strings.TrimPrefix(portOf(a.store.Cfg.Listen), ":")); err == nil {
		ports[p] = true
	}
	for i, v := range asArr(root.Get("inbounds")) {
		x := asMap(v)
		if x == nil || len(tmap[inboundID(x, i)]) == 0 {
			continue
		}
		if h, p := targetOf(x); p > 0 {
			ips[h] = true
			ports[p] = true
		}
	}
	tr := &tunnelRule{ips: keys(ips), ports: intKeys(ports)}
	setTunnelRules(root, tr)
	ensureTaggedOutbounds(root, tr)
	return nil
}

type tunnelRule struct {
	ips   []string
	ports []string
}

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func intKeys(m map[int]bool) []string {
	var n []int
	for k := range m {
		n = append(n, k)
	}
	sort.Ints(n)
	out := []string{}
	for _, k := range n {
		out = append(out, strconv.Itoa(k))
	}
	return out
}

func setTunnelRules(root *OMap, r *tunnelRule) {
	rt := asMap(root.Get("routing"))
	if rt == nil {
		if r == nil {
			return
		}
		rt = NewOMap()
		root.Set("routing", rt)
	}
	var rules []any
	if r != nil {
		var ips []any
		for _, ip := range r.ips {
			ips = append(ips, ip)
		}
		rules = append(rules,
			om("type", "field", "ruleTag", "xo-tunnel-allow", "inboundTag", []any{tunnelTag}, "ip", ips,
				"port", strings.Join(r.ports, ","), "outboundTag", tunnelDirect),
			om("type", "field", "ruleTag", "xo-tunnel-block", "inboundTag", []any{tunnelTag}, "outboundTag", tunnelBlock))
	}
	for _, v := range asArr(rt.Get("rules")) {
		if m := asMap(v); m != nil && strings.HasPrefix(asStr(m.Get("ruleTag")), "xo-tunnel") {
			continue
		}
		rules = append(rules, v)
	}
	if rules == nil {
		rules = []any{}
	}
	rt.Set("rules", rules)
}

// ensureTaggedOutbounds adds our own direct/block outbounds at the end, so the
// default (first) outbound never changes.
func ensureTaggedOutbounds(root *OMap, r *tunnelRule) {
	ensureOutbounds(root)
	have := map[string]bool{}
	for _, v := range asArr(root.Get("outbounds")) {
		have[asStr(asMap(v).Get("tag"))] = true
	}
	obs := asArr(root.Get("outbounds"))
	if !have[tunnelDirect] {
		obs = append(obs, om("protocol", "freedom", "tag", tunnelDirect))
	}
	if !have[tunnelBlock] {
		obs = append(obs, om("protocol", "blackhole", "tag", tunnelBlock))
	}
	// Xray's freedom blocks loopback by default for proxied traffic; allow
	// exactly the tunneled targets (least privilege), nothing else.
	var ips []any
	for _, ip := range r.ips {
		ips = append(ips, ip)
	}
	for _, v := range obs {
		if o := asMap(v); o != nil && asStr(o.Get("tag")) == tunnelDirect {
			o.Set("settings", om("finalRules", []any{
				om("action", "allow", "network", "tcp,udp", "ip", ips, "port", strings.Join(r.ports, ",")),
				om("action", "block")}))
		}
	}
	root.Set("outbounds", obs)
}

// ---------- config for the middle server ----------

type joinInfo struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	Join   string `json:"join"`
	Domain string `json:"domain"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	UUID   string `json:"uuid"`
	Panel  string `json:"panel"` // URL of the panel as seen from this server, e.g. https://127.0.0.1:24995/base/
}

func (a *App) panelLocalURL() string {
	c := a.store.Cfg
	scheme := "http"
	if a.tls {
		scheme = "https"
	}
	return scheme + "://127.0.0.1" + portOf(c.Listen) + c.BasePath
}

func relayXrayConfig(j joinInfo, fwd []fwdPort, ctl int) []byte {
	if ctl == 0 {
		ctl = agentCtlPort
	}
	inbounds := []any{om("tag", "ctl", "listen", "127.0.0.1", "port", ctl, "protocol", "socks",
		"settings", om("auth", "noauth", "udp", false))}
	for _, f := range fwd {
		inbounds = append(inbounds, om("tag", fmt.Sprintf("fwd-%d", f.Listen), "listen", "0.0.0.0", "port", f.Listen,
			"protocol", "dokodemo-door", "settings", om("address", f.Host, "port", f.Port, "network", "tcp,udp")))
	}
	root := om("log", om("loglevel", "warning"),
		"inbounds", inbounds,
		"outbounds", []any{om("tag", "main", "protocol", "vless",
			"settings", om("vnext", []any{om("address", j.Domain, "port", j.Port,
				"users", []any{om("id", j.UUID, "encryption", "none")})}),
			"streamSettings", om("network", "ws", "security", "tls",
				"tlsSettings", om("serverName", j.Domain, "fingerprint", "chrome"),
				"wsSettings", om("path", j.Path, "host", j.Domain)))})
	return EncodeIndent(root)
}

type fwdPort struct {
	Listen int    `json:"listen"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

func (a *App) joinFor(s TunnelServer) joinInfo {
	_, set, _ := a.store.TunnelsCopy()
	return joinInfo{V: 1, ID: s.ID, Join: s.Join, Domain: a.store.Cfg.Domain, Port: set.Port, Path: set.Path,
		UUID: s.UUID, Panel: a.panelLocalURL()}
}

func encodeJoin(j joinInfo) string {
	b, _ := json.Marshal(j)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *App) fwdFor(root *OMap, id string) []fwdPort {
	_, _, tmap := a.store.TunnelsCopy()
	var out []fwdPort
	for i, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		if ib == nil {
			continue
		}
		for _, u := range tmap[inboundID(ib, i)] {
			if u.Server != id {
				continue
			}
			if h, p := targetOf(ib); p > 0 {
				out = append(out, fwdPort{Listen: u.ListenPort(p), Host: h, Port: p})
			}
		}
	}
	return out
}

// relaysFor gives an inbound's link addresses: manual relays plus one per
// middle server it is tunneled through.
func (a *App) relaysFor(id string) []Relay {
	rl := a.store.RelaysOf(id)
	servers, _, tmap := a.store.TunnelsCopy()
	for _, u := range tmap[id] {
		for _, s := range servers {
			if s.ID != u.Server {
				continue
			}
			addr := s.PublicIP
			if addr == "" {
				addr = s.Host
			}
			if addr != "" {
				rl = append(rl, Relay{Address: addr, Port: u.Port, Name: orDefault(s.Name, "tunnel"), Tunnel: s.ID})
			}
		}
	}
	return rl
}

// ---------- handlers ----------

type tunnelView struct {
	TunnelServer
	Online  bool     `json:"online"`
	Command string   `json:"command,omitempty"`
	Inbound []string `json:"inbounds"`
	Remove  string         `json:"remove"`
	Ports   map[string]int `json:"ports"` // inbound id -> chosen port on the middle server (0 = same)
}

func (a *App) handleTunnels(w http.ResponseWriter, r *http.Request) {
	servers, set, tmap := a.store.TunnelsCopy()
	now := time.Now()
	out := []tunnelView{}
	for _, s := range servers {
		v := tunnelView{TunnelServer: s, Online: s.LastSeen > 0 && now.Sub(time.Unix(s.LastSeen, 0)) < onlineWindow, Inbound: []string{}, Ports: map[string]int{}}
		if s.Join != "" && s.JoinExp > now.Unix() {
			v.Command = "bash <(curl -fsSL " + tunnelInstall + ") " + encodeJoin(a.joinFor(s))
		}
		for ibid, us := range tmap {
			for _, u := range us {
				if u.Server == s.ID {
					v.Inbound = append(v.Inbound, ibid)
					v.Ports[ibid] = u.Port
				}
			}
		}
		v.Remove = "xray-one agent remove"
		sort.Strings(v.Inbound)
		v.Token, v.Join, v.UUID = "", "", ""
		out = append(out, v)
	}
	writeJSONResp(w, 200, map[string]any{"servers": out, "port": set.Port, "domain": a.store.Cfg.Domain,
		"ready": a.store.Cfg.Domain != "" && a.store.Cfg.CertFile != "", "methods": []string{tunnelMethodWS}})
}

func (a *App) handleAddTunnel(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name    string `json:"name"`
		Host    string `json:"host"`
		SSHPort int    `json:"sshPort"`
		SSHUser string `json:"sshUser"`
		Method  string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	b.Name, b.Host, b.SSHUser = strings.TrimSpace(b.Name), strings.TrimSpace(b.Host), strings.TrimSpace(b.SSHUser)
	if b.Name == "" {
		b.Name = orDefault(b.Host, "tunnel")
	}
	if b.Method == "" {
		b.Method = tunnelMethodWS
	}
	if b.Method != tunnelMethodWS {
		fail(w, 400, errors.New("unsupported tunnel method"))
		return
	}
	if b.SSHPort == 0 {
		b.SSHPort = 22
	}
	if b.SSHUser == "" {
		b.SSHUser = "root"
	}
	if a.store.Cfg.Domain == "" || a.store.Cfg.CertFile == "" {
		fail(w, 400, errors.New("the WSS tunnel needs this server's domain and SSL: set SSL in the SSH menu first"))
		return
	}
	s := &TunnelServer{ID: randHex(4), Name: b.Name, Method: b.Method, Host: b.Host, SSHPort: b.SSHPort, SSHUser: b.SSHUser,
		UUID: newUUID(), Join: randHex(16), JoinExp: time.Now().Add(joinTTL).Unix()}
	err := a.cfg.Mutate(func(root *OMap) error {
		if err := a.ensureTunnelSettings(root); err != nil {
			return err
		}
		if err := a.store.EditTunnels(func() error { a.store.Tunnels = append(a.store.Tunnels, s); return nil }); err != nil {
			return err
		}
		return a.applyTunnelConfig(root)
	})
	if err != nil {
		_ = a.store.EditTunnels(func() error { a.store.removeTunnel(s.ID); return nil })
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]any{"ok": true, "id": s.ID})
}

func (s *Store) removeTunnel(id string) {
	var keep []*TunnelServer
	for _, t := range s.Tunnels {
		if t.ID != id {
			keep = append(keep, t)
		}
	}
	s.Tunnels = keep
	for k, v := range s.TunnelUse {
		var nv []TunnelUse
		for _, x := range v {
			if x.Server != id {
				nv = append(nv, x)
			}
		}
		if len(nv) == 0 {
			delete(s.TunnelUse, k)
		} else {
			s.TunnelUse[k] = nv
		}
	}
}

func (a *App) handleDelTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = a.store.EditTunnels(func() error { a.store.removeTunnel(id); return nil })
	if err := a.cfg.Mutate(a.applyTunnelConfig); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// handleNewJoin makes a fresh one-time install command (24 h).
func (a *App) handleNewJoin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.store.EditTunnels(func() error {
		s := a.store.tunnelByID(id)
		if s == nil {
			return errors.New("unknown tunnel server")
		}
		s.Join, s.JoinExp = randHex(16), time.Now().Add(joinTTL).Unix()
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// handleTunnelAssign sets which middle servers an inbound uses and the port
// it listens on there.
func (a *App) handleTunnelAssign(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID   string      `json:"id"`
		Uses []TunnelUse `json:"uses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	var prev []TunnelUse
	err := a.cfg.Mutate(func(root *OMap) error {
		ib, _ := findInbound(root, b.ID)
		if ib == nil {
			return errors.New("inbound not found")
		}
		_, ibPort := targetOf(ib)
		if ibPort == 0 && len(b.Uses) > 0 {
			return errors.New("inbounds with a port range cannot be tunneled")
		}
		ibPorts := map[string]int{}
		for i, v := range asArr(root.Get("inbounds")) {
			if x := asMap(v); x != nil {
				_, ibPorts[inboundID(x, i)] = targetOf(x)
			}
		}
		if err := a.store.EditTunnels(func() error {
			prev = a.store.TunnelUse[b.ID]
			var ok []TunnelUse
			seen := map[string]bool{}
			for _, u := range b.Uses {
				srv := a.store.tunnelByID(u.Server)
				if srv == nil || seen[u.Server] {
					continue
				}
				seen[u.Server] = true
				if u.Port < 0 || u.Port > 65535 {
					return errors.New("invalid port")
				}
				if u.Port == ibPort {
					u.Port = 0
				}
				lp := u.ListenPort(ibPort)
				if lp == srv.CtlPort || (srv.CtlPort == 0 && lp == agentCtlPort) {
					return fmt.Errorf("port %d is the agent's own port on %s", lp, srv.Name)
				}
				mine := false
				for k, us := range a.store.TunnelUse {
					for _, x := range us {
						if k != b.ID && x.Server == srv.ID && x.ListenPort(ibPorts[k]) == lp {
							return fmt.Errorf("port %d on %s is already used by another tunneled inbound", lp, srv.Name)
						}
						if k == b.ID && x.Server == srv.ID && x.ListenPort(ibPort) == lp {
							mine = true
						}
					}
				}
				if !mine {
					for _, bp := range srv.Busy {
						if bp == lp {
							return fmt.Errorf("port %d is busy on %s; pick another port", lp, srv.Name)
						}
					}
				}
				ok = append(ok, u)
			}
			if len(ok) == 0 {
				delete(a.store.TunnelUse, b.ID)
			} else {
				a.store.TunnelUse[b.ID] = ok
			}
			return nil
		}); err != nil {
			return err
		}
		return a.applyTunnelConfig(root)
	})
	if err != nil {
		_ = a.store.EditTunnels(func() error {
			if prev == nil {
				delete(a.store.TunnelUse, b.ID)
			} else {
				a.store.TunnelUse[b.ID] = prev
			}
			return nil
		})
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// ---------- agent heartbeat (no login; agent token) ----------

type beatReq struct {
	Version  string `json:"version"`
	PublicIP string `json:"publicIP"`
	XrayOK   bool   `json:"xrayOk"`
	XrayErr  string `json:"xrayErr"`
	Applied  string `json:"applied"`
	CtlPort  int    `json:"ctlPort"`
	Busy     []int  `json:"busy"`
}

type beatResp struct {
	Token  string          `json:"token,omitempty"`
	Hash   string          `json:"hash"`
	Config json.RawMessage `json:"config,omitempty"`
	Every  int             `json:"every"`
}

func (a *App) handleBeat(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-Agent-Token")
	id := r.Header.Get("X-Agent-ID")
	var req beatReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		fail(w, 400, err)
		return
	}
	var resp beatResp
	var srv TunnelServer
	err := a.store.EditTunnels(func() error {
		s := a.store.tunnelByID(id)
		if s == nil || tok == "" {
			return errors.New("unknown agent")
		}
		switch {
		case s.Token != "" && tok == s.Token:
		case s.Join != "" && tok == s.Join && s.JoinExp > time.Now().Unix():
			s.Token = randHex(24)
			s.Join, s.JoinExp = "", 0
			resp.Token = s.Token
		default:
			return errors.New("bad agent token")
		}
		s.LastSeen = time.Now().Unix()
		if ip := net.ParseIP(strings.TrimSpace(req.PublicIP)); ip != nil {
			s.PublicIP = ip.String()
		}
		s.AgentVer, s.XrayOK, s.XrayErr, s.Applied = req.Version, req.XrayOK, trimTo(req.XrayErr, 400), req.Applied
		if req.CtlPort > 0 {
			s.CtlPort = req.CtlPort
		}
		if len(req.Busy) > 2000 {
			req.Busy = req.Busy[:2000]
		}
		s.Busy = req.Busy
		srv = *s
		return nil
	})
	if err != nil {
		time.Sleep(300 * time.Millisecond)
		fail(w, 401, err)
		return
	}
	root, _, lerr := a.cfg.Load()
	var fwd []fwdPort
	if lerr == nil {
		fwd = a.fwdFor(root, srv.ID)
	}
	cfg := relayXrayConfig(a.joinFor(srv), fwd, srv.CtlPort)
	sum := sha256.Sum256(cfg)
	resp.Hash = fmt.Sprintf("%x", sum[:8])
	if req.Applied != resp.Hash {
		resp.Config = cfg
	}
	resp.Every = int(beatEvery / time.Second)
	writeJSONResp(w, 200, resp)
}

func trimTo(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// ---------- SSH deploy ----------

func (a *App) handleDeployTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b)
	var s TunnelServer
	err := a.store.EditTunnels(func() error {
		x := a.store.tunnelByID(id)
		if x == nil {
			return errors.New("unknown tunnel server")
		}
		if x.Host == "" {
			return errors.New("this server has no SSH address; use the quick install command instead")
		}
		if x.Join == "" || x.JoinExp <= time.Now().Unix() {
			x.Join, x.JoinExp = randHex(16), time.Now().Add(joinTTL).Unix()
		}
		s = *x
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	cmd := "curl -fsSL " + tunnelInstall + " -o /tmp/xo-tunnel.sh && bash /tmp/xo-tunnel.sh " + encodeJoin(a.joinFor(s))
	out, hostKey, keyOK, err := sshDeploy(a.store.dir, s, b.Password, cmd)
	_ = a.store.EditTunnels(func() error {
		if x := a.store.tunnelByID(id); x != nil {
			if hostKey != "" {
				x.HostKey = hostKey
			}
			if keyOK {
				x.KeyOK = true
			}
		}
		return nil
	})
	if err != nil {
		writeJSONResp(w, 400, map[string]any{"error": err.Error(), "log": trimTo(out, 6000)})
		return
	}
	writeJSONResp(w, 200, map[string]any{"ok": true, "log": trimTo(out, 6000)})
}

func panelSSHKeyPath(dir string) string { return filepath.Join(dir, "ssh", "id_ed25519") }

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
