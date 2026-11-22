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
	"sync"
	"time"
)

const (
	tunnelTag      = "xo-tunnel"
	tunnelDirect   = "xo-direct"
	tunnelBlock    = "xo-block"
	agentCtlPort   = 10885
	beatEvery      = 30 * time.Second
	onlineWindow   = 130 * time.Second
	joinTTL        = 24 * time.Hour
	tunnelInstall  = "https://raw.githubusercontent.com/sahandfarshad/xray-one/main/tunnel.sh"
	tunnelMethodWS = "wss"
	// XHTTP: same Xray core, its own inbound and port on the main server.
	tunnelTagXH       = "xo-tunnel-xh"
	tunnelMethodXHTTP = "xhttp"
	tunnelTagRT       = "xo-tunnel-rt"
	tunnelMethodRT    = "reality"
	defaultRTarget    = "www.microsoft.com:443"
	// how long a middle server tries a new method before going back
	methodTrial = 90 * time.Second
)

func isTunnelTag(t string) bool {
	return t == tunnelTag || t == tunnelTagXH || t == tunnelTagRT || t == dedTagWG
}

func validMethod(m string) bool {
	return m == tunnelMethodWS || m == tunnelMethodXHTTP || m == tunnelMethodRT
}

// tunnelMethods: the method cards. Ready ones can be switched on per server.
var tunnelMethods = []map[string]any{
	{"id": tunnelMethodWS, "ready": true},
	{"id": tunnelMethodXHTTP, "ready": true},
	{"id": tunnelMethodRT, "ready": true},
	{"id": "grefrp", "ready": false},
	{"id": "backhaul", "ready": false},
	{"id": "frpssh", "ready": false},
}

// minimum agent able to try a method and fall back by itself
const agentMethodVer = "0.6.1"

type TunnelServer struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Method     string            `json:"method"`
	Host       string            `json:"host,omitempty"` // SSH address / public address
	SSHPort    int               `json:"sshPort,omitempty"`
	SSHUser    string            `json:"sshUser,omitempty"`
	HostKey    string            `json:"hostKey,omitempty"` // TOFU, "ssh-ed25519 AAAA..."
	KeyOK      bool              `json:"keyInstalled,omitempty"`
	UUID       string            `json:"uuid"`
	Token      string            `json:"token,omitempty"`
	Join       string            `json:"join,omitempty"`
	JoinExp    int64             `json:"joinExp,omitempty"`
	LastSeen   int64             `json:"lastSeen,omitempty"`
	PublicIP   string            `json:"publicIP,omitempty"`
	AgentVer   string            `json:"agentVer,omitempty"`
	XrayOK     bool              `json:"xrayOk,omitempty"`
	XrayErr    string            `json:"xrayErr,omitempty"`
	PrevMethod string            `json:"prevMethod,omitempty"` // set while a switch is being tried
	SentHash   string            `json:"sentHash,omitempty"`
	SentMethod string            `json:"sentMethod,omitempty"`
	MethodErr  string            `json:"methodErr,omitempty"`
	Applied    string            `json:"applied,omitempty"` // config hash the agent runs
	CtlPort    int               `json:"ctlPort,omitempty"` // agent's local control port
	Busy       []int             `json:"busy,omitempty"`    // ports already taken on the middle server
	Fails      int               `json:"fails,omitempty"`   // heartbeats that failed before the last one got through
	LastFail   string            `json:"lastFail,omitempty"`
	FailAt     int64             `json:"failAt,omitempty"`
	PortState  map[string]string `json:"portState,omitempty"`
	// two-way reconnect (agent 0.6.4+)
	RevPort   int    `json:"revPort,omitempty"` // REALITY listener on the middle server
	RevUUID   string `json:"revUUID,omitempty"`
	RevKey    string `json:"revKey,omitempty"`
	RevPub    string `json:"revPub,omitempty"`
	RevSID    string `json:"revSID,omitempty"`
	Mode      string `json:"mode,omitempty"`   // path the agent uses: "" forward, "rev" reverse
	Bridge    bool   `json:"bridge,omitempty"` // this server is dialing the middle server
	BridgeAt  int64  `json:"bridgeAt,omitempty"`
	BridgeErr string `json:"bridgeErr,omitempty"`
	BridgeVia string `json:"bridgeVia,omitempty"` // method this server dials it with
	RevPortW  int    `json:"revPortW,omitempty"`  // WS+TLS listener (needs the middle server's domain)
	RevPortX  int    `json:"revPortX,omitempty"`  // XHTTP+TLS listener
	RevPath   string `json:"revPath,omitempty"`
	Via       string `json:"via,omitempty"`      // fallback method the agent found when its own failed
	Search    string `json:"search,omitempty"`   // this server looking for it: "search" or "cool"
	SearchAt  int64  `json:"searchAt,omitempty"` // until when it rests
	SearchN   string `json:"searchN,omitempty"`  // "2/3"
	// domain + Let's Encrypt certificate on the middle server
	Domain   string `json:"domain,omitempty"`
	CertOK   bool   `json:"certOk,omitempty"`
	CertExp  int64  `json:"certExp,omitempty"`
	CertErr  string `json:"certErr,omitempty"`
	CertBusy bool   `json:"certBusy,omitempty"`
	// dedicated tunnels (dedicated.go): fixed paths, separate from the above
	Ded []DedTunnel `json:"dedicated,omitempty"`
}

// agentHub wakes held heartbeats (long-poll) and lets a manual test wait for
// the next heartbeat of a middle server.
type agentHub struct {
	mu      sync.Mutex
	poke    map[string]chan struct{}
	waiters map[string][]chan struct{}
}

var hub = &agentHub{poke: map[string]chan struct{}{}, waiters: map[string][]chan struct{}{}}

func (h *agentHub) pokeChan(id string) chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.poke[id]
	if c == nil {
		c = make(chan struct{}, 1)
		h.poke[id] = c
	}
	return c
}

// Poke asks the middle server to send a heartbeat right away.
func (h *agentHub) Poke(id string) {
	select {
	case h.pokeChan(id) <- struct{}{}:
	default:
	}
}

func (h *agentHub) PokeAll(ids []string) {
	for _, id := range ids {
		h.Poke(id)
	}
}

func (h *agentHub) Wait(id string) chan struct{} {
	c := make(chan struct{}, 1)
	h.mu.Lock()
	h.waiters[id] = append(h.waiters[id], c)
	h.mu.Unlock()
	return c
}

func (h *agentHub) Beat(id string) {
	h.mu.Lock()
	ws := h.waiters[id]
	delete(h.waiters, id)
	h.mu.Unlock()
	for _, c := range ws {
		c <- struct{}{}
	}
}

// TunnelUse: one inbound goes through one middle server, listening there on
// Port (0 = same port as the inbound).
type TunnelUse struct {
	Server string `json:"server"`
	Port   int    `json:"port,omitempty"`
	Via    string `json:"via,omitempty"` // "" the rotating tunnel, or a dedicated tunnel type ("wg")
}

func (u TunnelUse) ListenPort(inboundPort int) int {
	if u.Port > 0 {
		return u.Port
	}
	return inboundPort
}

type TunnelSettings struct {
	Port  int    `json:"port,omitempty"`
	Path  string `json:"path,omitempty"`
	XPort int    `json:"xport,omitempty"` // XHTTP inbound
	XPath string `json:"xpath,omitempty"`
	// REALITY inbound
	RPort   int    `json:"rport,omitempty"`
	RTarget string `json:"rtarget,omitempty"` // host:port of the site it looks like
	RKey    string `json:"rkey,omitempty"`    // x25519 private key
	RPub    string `json:"rpub,omitempty"`
	RSID    string `json:"rsid,omitempty"`
	// dedicated WireGuard tunnel (dedicated.go)
	WGPort int    `json:"wgport,omitempty"`
	WGKey  string `json:"wgkey,omitempty"`
	WGPub  string `json:"wgpub,omitempty"`
	WGHost string `json:"wghost,omitempty"` // address middle servers dial (public IP)
}

// armPort returns the port a pre-armed method listens on: the chosen one
// (must be free unless it is already ours) or a free one picked now.
func (a *App) armPort(root *OMap, name string, p int, save func(int), tag string, skip ...int) (int, error) {
	ib, _ := findInbound(root, tag)
	if p != 0 {
		mine := ib != nil && asStr(ib.Get("port")) == strconv.Itoa(p)
		if !mine && (usedPorts(root)[strconv.Itoa(p)] || !portFree(p)) {
			return 0, fmt.Errorf("%s tunnel port %d is busy: choose another port in the Tunnels tab", name, p)
		}
		return p, nil
	}
	p = pickTunnelPort(root, skip...)
	if p == 0 {
		return 0, fmt.Errorf("no free port for the %s tunnel", name)
	}
	_ = a.store.EditTunnels(func() error { save(p); return nil })
	return p, nil
}

// armInbound finds or adds a tunnel inbound and sets its port.
func armInbound(root *OMap, tag string, port int) *OMap {
	ib, _ := findInbound(root, tag)
	if ib == nil {
		ib = om("tag", tag, "listen", "0.0.0.0", "port", port, "protocol", "vless")
		root.Set("inbounds", append(asArr(root.Get("inbounds")), ib))
	}
	ib.Set("port", port)
	ib.Set("protocol", "vless")
	ib.Delete("sniffing")
	return ib
}

// pickTunnelPort: a free Cloudflare-style HTTPS port, else any free port.
func pickTunnelPort(root *OMap, skip ...int) int {
	used := usedPorts(root)
	bad := func(p int) bool {
		for _, x := range skip {
			if x == p {
				return true
			}
		}
		return used[strconv.Itoa(p)]
	}
	for _, p := range cfPorts {
		if !bad(p) && portFree(p) {
			return p
		}
	}
	for i := 0; i < 20; i++ {
		if p := suggestPort(); !bad(p) {
			return p
		}
	}
	return 0
}

func usesMethod(servers []TunnelServer, m string) bool {
	for _, s := range servers {
		if s.Method == m || s.PrevMethod == m {
			return true
		}
	}
	return false
}

// ---------- store ----------

func (s *Store) TunnelsCopy() ([]TunnelServer, TunnelSettings, map[string][]TunnelUse) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []TunnelServer{}
	for _, t := range s.Tunnels {
		c := *t
		c.Ded = append([]DedTunnel(nil), t.Ded...)
		out = append(out, c)
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
		if c.XPath == "" {
			c.XPath = "/" + randHex(6)
		}
		if c.RTarget == "" {
			c.RTarget = defaultRTarget
		}
		if c.RKey == "" || pubFromPriv(c.RKey) == "" {
			pr, pb, err := genX25519()
			if err != nil {
				return err
			}
			c.RKey, c.RPub = pr, pb
		}
		if c.RPub == "" {
			c.RPub = pubFromPriv(c.RKey)
		}
		if c.RSID == "" {
			c.RSID = randHex(4)
		}
		if c.RPort == 0 {
			if ib, _ := findInbound(root, tunnelTagRT); ib != nil {
				c.RPort, _ = strconv.Atoi(asStr(ib.Get("port")))
			}
		}
		if c.XPort == 0 {
			if ib, _ := findInbound(root, tunnelTagXH); ib != nil {
				c.XPort, _ = strconv.Atoi(asStr(ib.Get("port")))
			}
		}
		if c.Port == 0 {
			if ib, _ := findInbound(root, tunnelTag); ib != nil {
				c.Port, _ = strconv.Atoi(asStr(ib.Get("port")))
			}
		}
		if c.Port == 0 {
			c.Port = pickTunnelPort(root)
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
			if !isTunnelTag(asStr(asMap(v).Get("tag"))) {
				keep = append(keep, v)
			}
		}
		if keep == nil {
			keep = []any{}
		}
		root.Set("inbounds", keep)
		setTunnelRules(root, nil)
		dropBridges(root)
		dropDedOutbounds(root)
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

	// every ready method listens all the time (pre-armed), so a middle
	// server can switch at once without touching this server
	xport, err := a.armPort(root, "XHTTP", set.XPort, func(p int) { a.store.TunnelCfg.XPort = p }, tunnelTagXH, set.Port)
	if err != nil {
		return err
	}
	xh := armInbound(root, tunnelTagXH, xport)
	xh.Set("settings", om("clients", clients, "decryption", "none"))
	xh.Set("streamSettings", om("network", "xhttp", "security", "tls",
		"tlsSettings", om("serverName", dom, "alpn", []any{"h2", "http/1.1"}, "certificates", []any{om("certificateFile", rcf, "keyFile", rkf)}),
		"xhttpSettings", om("path", set.XPath, "mode", "auto")))

	rport, err := a.armPort(root, "REALITY", set.RPort, func(p int) { a.store.TunnelCfg.RPort = p }, tunnelTagRT, set.Port, xport)
	if err != nil {
		return err
	}
	var rclients []any
	for _, s := range servers {
		rclients = append(rclients, om("id", s.UUID, "email", "tunnel-"+s.ID, "level", 0, "flow", "xtls-rprx-vision"))
	}
	rt := armInbound(root, tunnelTagRT, rport)
	host, _, _ := strings.Cut(set.RTarget, ":")
	rt.Set("settings", om("clients", rclients, "decryption", "none"))
	rt.Set("streamSettings", om("network", "raw", "security", "reality",
		"realitySettings", om("show", false, "target", set.RTarget, "xver", 0, "serverNames", []any{host},
			"privateKey", set.RKey, "shortIds", []any{set.RSID})))

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
	ensureTaggedOutbounds(root, tr)
	// after ensureTaggedOutbounds, so a bridge is never the default outbound
	tr.extra = a.addBridges(root, servers)
	// dedicated tunnels: their own inbound, outbounds and rules
	if tr.dt, tr.dtTags, err = a.applyDedicated(root, servers, tmap); err != nil {
		return err
	}
	setTunnelRules(root, tr)
	return nil
}

type tunnelRule struct {
	ips   []string
	ports []string
	extra []any // more inbound tags (reverse traffic)
	// dedicated tunnels: their allow rules, and their inbound tags (blocked
	// for anything else)
	dt     []any
	dtTags []any
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
		in := append([]any{tunnelTag, tunnelTagXH, tunnelTagRT}, r.extra...)
		rules = append(rules, r.dt...)
		rules = append(rules,
			om("type", "field", "ruleTag", "xo-tunnel-allow", "inboundTag", in, "ip", ips,
				"port", strings.Join(r.ports, ","), "outboundTag", tunnelDirect),
			om("type", "field", "ruleTag", "xo-tunnel-block", "inboundTag", append(append([]any{}, in...), r.dtTags...), "outboundTag", tunnelBlock))
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
	Method string `json:"method,omitempty"` // wss (default) or xhttp
	XPort  int    `json:"xport,omitempty"`
	XPath  string `json:"xpath,omitempty"`
	RPort  int    `json:"rport,omitempty"`
	RSNI   string `json:"rsni,omitempty"`
	RPub   string `json:"rpub,omitempty"`
	RSID   string `json:"rsid,omitempty"`
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

func relayXrayConfig(j joinInfo, fwd []fwdPort, ctl int, rev *revInfo, ded *dedRelay) []byte {
	if ctl == 0 {
		ctl = agentCtlPort
	}
	inbounds := []any{om("tag", "ctl", "listen", "127.0.0.1", "port", ctl, "protocol", "socks",
		"settings", om("auth", "noauth", "udp", false))}
	for _, f := range fwd {
		if f.Via != "" { // pinned to a dedicated tunnel: only through it
			if ib := relayDedFwd(f, ded); ib != nil {
				inbounds = append(inbounds, ib)
			}
			continue
		}
		inbounds = append(inbounds, om("tag", fmt.Sprintf("fwd-%d", f.Listen), "listen", "0.0.0.0", "port", f.Listen,
			"protocol", "dokodemo-door", "settings", om("address", f.Host, "port", f.Port, "network", "tcp,udp")))
	}
	root := om("log", om("loglevel", "warning"),
		"inbounds", inbounds,
		"outbounds", []any{mainOutbound(j)})
	addRelayReverse(root, rev, ctl)
	addRelayDedicated(root, ded, ctl)
	return EncodeIndent(root)
}

// mainOutbound: how a middle server dials this server with j's method.
func mainOutbound(j joinInfo) *OMap {
	port := j.Port
	stream := om("network", "ws", "security", "tls",
		"tlsSettings", om("serverName", j.Domain, "fingerprint", "chrome"),
		"wsSettings", om("path", j.Path, "host", j.Domain))
	if j.Method == tunnelMethodXHTTP && j.XPort > 0 {
		port = j.XPort
		stream = om("network", "xhttp", "security", "tls",
			"tlsSettings", om("serverName", j.Domain, "fingerprint", "chrome", "alpn", []any{"h2"}),
			"xhttpSettings", om("path", j.XPath, "host", j.Domain, "mode", "auto"))
	}
	user := om("id", j.UUID, "encryption", "none")
	if j.Method == tunnelMethodRT && j.RPort > 0 {
		port = j.RPort
		user.Set("flow", "xtls-rprx-vision")
		stream = om("network", "raw", "security", "reality",
			"realitySettings", om("serverName", j.RSNI, "fingerprint", "chrome", "publicKey", j.RPub, "shortId", j.RSID))
	}
	return om("tag", "main", "protocol", "vless",
		"settings", om("vnext", []any{om("address", j.Domain, "port", port,
			"users", []any{user})}),
		"streamSettings", stream)
}

type fwdPort struct {
	Listen int    `json:"listen"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Via    string `json:"via,omitempty"` // dedicated tunnel type, "" rotating
}

func (a *App) joinFor(s TunnelServer) joinInfo {
	_, set, _ := a.store.TunnelsCopy()
	j := joinInfo{V: 1, ID: s.ID, Join: s.Join, Domain: a.store.Cfg.Domain, Port: set.Port, Path: set.Path,
		UUID: s.UUID, Panel: a.panelLocalURL()}
	switch s.Method {
	case tunnelMethodXHTTP:
		j.Method, j.XPort, j.XPath = s.Method, set.XPort, set.XPath
	case tunnelMethodRT:
		host, _, _ := strings.Cut(set.RTarget, ":")
		j.Method, j.RPort, j.RSNI, j.RPub, j.RSID = s.Method, set.RPort, host, set.RPub, set.RSID
	}
	return j
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
				out = append(out, fwdPort{Listen: u.ListenPort(p), Host: h, Port: p, Via: u.Via})
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
	Online  bool              `json:"online"`
	Command string            `json:"command,omitempty"`
	Inbound []string          `json:"inbounds"`
	Remove  string            `json:"remove"`
	Ports   map[string]int    `json:"ports"` // inbound id -> chosen port on the middle server (0 = same)
	Vias    map[string]string `json:"vias"`  // inbound id -> dedicated tunnel it is pinned to ("" rotating)
	DedView []dedView         `json:"dedView"`
}

type dedView struct {
	Type  string `json:"type"`
	On    bool   `json:"on"`
	State string `json:"state"` // off, offline, pending, up, down
	OkAt  int64  `json:"okAt,omitempty"`
	ChkAt int64  `json:"chkAt,omitempty"`
	Ms    int    `json:"ms,omitempty"`
	Err   string `json:"err,omitempty"`
	Pins  int    `json:"pins"`
}

func (a *App) handleTunnels(w http.ResponseWriter, r *http.Request) {
	servers, set, tmap := a.store.TunnelsCopy()
	now := time.Now()
	out := []tunnelView{}
	for _, s := range servers {
		v := tunnelView{TunnelServer: s, Online: s.LastSeen > 0 && now.Sub(time.Unix(s.LastSeen, 0)) < onlineWindow, Inbound: []string{}, Ports: map[string]int{}, Vias: map[string]string{}, DedView: []dedView{}}
		if s.Join != "" && s.JoinExp > now.Unix() {
			v.Command = "bash <(curl -fsSL " + tunnelInstall + ") " + encodeJoin(a.joinFor(s))
		}
		for ibid, us := range tmap {
			for _, u := range us {
				if u.Server == s.ID {
					v.Inbound = append(v.Inbound, ibid)
					v.Ports[ibid] = u.Port
					if u.Via != "" {
						v.Vias[ibid] = u.Via
					}
				}
			}
		}
		v.Remove = "xray-one agent remove"
		sort.Strings(v.Inbound)
		v.Token, v.Join, v.UUID, v.RevKey, v.RevUUID = "", "", "", "", ""
		for _, d := range s.Ded {
			dv := dedView{Type: d.Type, On: d.On, State: dedState(d, v.Online), OkAt: d.OkAt, ChkAt: d.ChkAt, Ms: d.Ms, Err: d.Err}
			for _, x := range v.Vias {
				if x == d.Type {
					dv.Pins++
				}
			}
			v.DedView = append(v.DedView, dv)
		}
		v.Ded = nil
		out = append(out, v)
	}
	writeJSONResp(w, 200, map[string]any{"servers": out, "port": set.Port, "domain": a.store.Cfg.Domain,
		"ready": a.store.Cfg.Domain != "" && a.store.Cfg.CertFile != "", "methods": tunnelMethods, "xport": set.XPort, "rport": set.RPort, "rtarget": set.RTarget, "methodVer": agentMethodVer, "revVer": agentRevVer,
		"dedTypes": dedTypes, "dedVer": agentDedVer, "wgport": set.WGPort, "wghost": set.WGHost})
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
	if !validMethod(b.Method) {
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
			ok, err := a.store.checkUsesLocked(b.ID, b.Uses, ibPort, ibPorts)
			if err != nil {
				return err
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
	for _, u := range b.Uses {
		hub.Poke(u.Server)
	}
	for _, u := range prev {
		hub.Poke(u.Server)
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// checkUsesLocked validates an inbound's middle servers and ports
// (store lock held).
func (s *Store) checkUsesLocked(id string, uses []TunnelUse, ibPort int, ibPorts map[string]int) ([]TunnelUse, error) {
	var ok []TunnelUse
	seen := map[string]bool{}
	for _, u := range uses {
		srv := s.tunnelByID(u.Server)
		if srv == nil || seen[u.Server] {
			continue
		}
		seen[u.Server] = true
		if u.Port < 0 || u.Port > 65535 {
			return nil, errors.New("invalid port")
		}
		if u.Port == ibPort {
			u.Port = 0
		}
		lp := u.ListenPort(ibPort)
		if lp == srv.CtlPort || (srv.CtlPort == 0 && lp == agentCtlPort) {
			return nil, fmt.Errorf("port %d is the agent's own port on %s", lp, srv.Name)
		}
		if u.Via != "" && !dedOn(*srv, u.Via) {
			return nil, fmt.Errorf("the dedicated tunnel %q is not on for %s; turn it on in the Tunnels tab", u.Via, srv.Name)
		}
		if len(srv.Ded) > 0 && lp == probePort(*srv) {
			for _, d := range srv.Ded {
				if d.On {
					return nil, fmt.Errorf("port %d on %s is used by the dedicated tunnel's status check", lp, srv.Name)
				}
			}
		}
		mine := false
		for k, us := range s.TunnelUse {
			for _, x := range us {
				if k != id && x.Server == srv.ID && x.ListenPort(ibPorts[k]) == lp {
					return nil, fmt.Errorf("port %d on %s is already used by another tunneled inbound", lp, srv.Name)
				}
				if k == id && x.Server == srv.ID && x.ListenPort(ibPort) == lp {
					mine = true
				}
			}
		}
		if !mine {
			for _, bp := range srv.Busy {
				if bp == lp {
					return nil, fmt.Errorf("port %d is busy on %s; pick another port", lp, srv.Name)
				}
			}
		}
		ok = append(ok, u)
	}
	return ok, nil
}

// handleTunnelBulk adds (or removes) one middle server on many inbounds at
// once, each on its own port. Inbounds that cannot be tunneled are skipped
// and reported.
func (a *App) handleTunnelBulk(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs    []string `json:"ids"`
		Server string   `json:"server"`
		Remove bool     `json:"remove"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || len(b.IDs) == 0 || b.Server == "" {
		fail(w, 400, errors.New("pick inbounds and a middle server"))
		return
	}
	type skip struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
	}
	var skipped []skip
	done := 0
	var backup map[string][]TunnelUse
	err := a.cfg.Mutate(func(root *OMap) error {
		ibPorts := map[string]int{}
		ibs := map[string]*OMap{}
		for i, v := range asArr(root.Get("inbounds")) {
			if x := asMap(v); x != nil {
				id := inboundID(x, i)
				_, ibPorts[id] = targetOf(x)
				ibs[id] = x
			}
		}
		if err := a.store.EditTunnels(func() error {
			if a.store.tunnelByID(b.Server) == nil {
				return errors.New("middle server not found")
			}
			backup = map[string][]TunnelUse{}
			for k, v := range a.store.TunnelUse {
				backup[k] = append([]TunnelUse{}, v...)
			}
			if a.store.TunnelUse == nil {
				a.store.TunnelUse = map[string][]TunnelUse{}
			}
			for _, id := range b.IDs {
				ib := ibs[id]
				if ib == nil {
					skipped = append(skipped, skip{id, "inbound not found"})
					continue
				}
				if t := asStr(ib.Get("tag")); isTunnelTag(t) || (apiTag(root) != "" && t == apiTag(root)) {
					skipped = append(skipped, skip{id, "system inbound"})
					continue
				}
				cur := a.store.TunnelUse[id]
				var next []TunnelUse
				has := false
				for _, u := range cur {
					if u.Server == b.Server {
						has = true
						if b.Remove {
							continue
						}
					}
					next = append(next, u)
				}
				if b.Remove {
					if !has {
						continue
					}
				} else {
					if has {
						continue
					}
					if ibPorts[id] == 0 {
						skipped = append(skipped, skip{id, "port range cannot be tunneled"})
						continue
					}
					next = append(next, TunnelUse{Server: b.Server})
				}
				ok, err := a.store.checkUsesLocked(id, next, ibPorts[id], ibPorts)
				if err != nil {
					skipped = append(skipped, skip{id, err.Error()})
					continue
				}
				if len(ok) == 0 {
					delete(a.store.TunnelUse, id)
				} else {
					a.store.TunnelUse[id] = ok
				}
				done++
			}
			return nil
		}); err != nil {
			return err
		}
		return a.applyTunnelConfig(root)
	})
	if err != nil {
		if backup != nil {
			_ = a.store.EditTunnels(func() error { a.store.TunnelUse = backup; return nil })
		}
		fail(w, 400, err)
		return
	}
	hub.Poke(b.Server)
	if skipped == nil {
		skipped = []skip{}
	}
	writeJSONResp(w, 200, map[string]any{"ok": true, "done": done, "skipped": skipped})
}

// ---------- agent heartbeat (no login; agent token) ----------

type beatReq struct {
	Version   string               `json:"version"`
	PublicIP  string               `json:"publicIP"`
	XrayOK    bool                 `json:"xrayOk"`
	XrayErr   string               `json:"xrayErr"`
	Applied   string               `json:"applied"`
	CtlPort   int                  `json:"ctlPort"`
	Busy      []int                `json:"busy"`
	Wait      bool                 `json:"wait"`                // agent accepts a held (long-poll) reply
	Fails     int                  `json:"fails"`               // failed heartbeats since the last good one
	LastFail  string               `json:"lastFail"`            // why the last one failed
	PortState map[string]string    `json:"portState,omitempty"` // forwarded port -> ok / busy / down (0.5.1+)
	Rejected  string               `json:"rejected,omitempty"`  // config hash the agent tried and went back from (0.6.1+)
	Pending   bool                 `json:"pending,omitempty"`   // still trying the newest config
	Mode      string               `json:"mode,omitempty"`      // "rev" when it reached us over the reverse path (0.6.4+)
	Via       string               `json:"via,omitempty"`       // forward method it found by searching (0.6.5+)
	CertDom   string               `json:"certDomain,omitempty"`
	CertExp   int64                `json:"certExp,omitempty"`
	CertErr   string               `json:"certErr,omitempty"`
	CertBusy  bool                 `json:"certBusy,omitempty"`
	Ded       map[string]dedReport `json:"dedicated,omitempty"` // check through each dedicated tunnel (0.6.8+)
}

type beatResp struct {
	Token  string          `json:"token,omitempty"`
	Hash   string          `json:"hash"`
	Config json.RawMessage `json:"config,omitempty"`
	Every  int             `json:"every"`
	Held   bool            `json:"held,omitempty"`   // reply was held; beat again at once
	Probe  bool            `json:"probe,omitempty"`  // beat again at once (test or new config)
	Domain string          `json:"domain,omitempty"` // get a certificate for this domain (0.6.4+)
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
		s.PortState = req.PortState
		if req.Fails > 0 {
			s.Fails, s.LastFail, s.FailAt = req.Fails, trimTo(req.LastFail, 300), time.Now().Unix()
		}
		s.Mode, s.Via = req.Mode, req.Via
		if revCapable(*s) && s.Domain != "" {
			s.CertBusy, s.CertErr = req.CertBusy, trimTo(req.CertErr, 300)
			s.CertOK = req.CertDom == s.Domain && req.CertExp > time.Now().Unix()
			if s.CertOK {
				s.CertExp, s.CertErr = req.CertExp, ""
			}
		}
		saveDedReports(s, req.Ded)
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
	if revCapable(srv) {
		_ = a.store.EditTunnels(func() error {
			if s := a.store.tunnelByID(srv.ID); s != nil {
				// new listener settings: the relay config changes, and our
				// tunnel rules learn this server's reverse inbound tag
				if ensureRevLocked(s, fwd) {
					defer a.reapplyTunnels(s.ID)
				}
				srv = *s
			}
			return nil
		})
	}
	// the first path that got through wins: stop searching, and keep the
	// bridge only while the agent uses it
	a.pathFound(srv, req.Mode == "rev")
	// the agent tried our newest config and could not reach us with it: go
	// back to the method it had
	if req.Rejected != "" && srv.SentHash == req.Rejected && srv.PrevMethod != "" && srv.SentMethod == srv.Method {
		_ = a.store.EditTunnels(func() error {
			if s := a.store.tunnelByID(srv.ID); s != nil && s.PrevMethod != "" {
				s.MethodErr = s.Method + " → " + s.PrevMethod
				s.Method, s.PrevMethod = s.PrevMethod, ""
				srv = *s
			}
			return nil
		})
		go a.refreshTunnelInbounds()
	}
	cfg := relayXrayConfig(a.joinFor(srv), fwd, srv.CtlPort, a.revFor(srv), a.dedFor(root, srv))
	if revCapable(srv) {
		resp.Domain = srv.Domain
	}
	sum := sha256.Sum256(cfg)
	resp.Hash = fmt.Sprintf("%x", sum[:8])
	if req.Applied != resp.Hash {
		resp.Config = cfg
		if srv.SentHash != resp.Hash || srv.SentMethod != srv.Method {
			_ = a.store.EditTunnels(func() error {
				if s := a.store.tunnelByID(srv.ID); s != nil {
					s.SentHash, s.SentMethod = resp.Hash, s.Method
				}
				return nil
			})
		}
	} else if srv.PrevMethod != "" && !req.Pending && srv.SentMethod == srv.Method {
		// the new method works: the agent reached us through it
		_ = a.store.EditTunnels(func() error {
			if s := a.store.tunnelByID(srv.ID); s != nil {
				s.PrevMethod, s.MethodErr = "", ""
			}
			return nil
		})
		go a.refreshTunnelInbounds()
	}
	resp.Every = int(beatEvery / time.Second)
	hub.Beat(srv.ID)
	if req.Wait && resp.Config == nil && resp.Token == "" {
		resp.Held = true
		pc := hub.pokeChan(srv.ID)
		select {
		case <-pc:
			resp.Probe = true
		case <-time.After(holdFor(srv.AgentVer)):
		case <-r.Context().Done():
			return
		}
	}
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

// handleTestTunnel: manual connection test. Wakes the middle server's held
// heartbeat and waits for a fresh one through the tunnel.
func (a *App) handleTestTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	servers, _, _ := a.store.TunnelsCopy()
	var srv *TunnelServer
	for i := range servers {
		if servers[i].ID == id {
			srv = &servers[i]
		}
	}
	if srv == nil {
		fail(w, 404, errors.New("unknown tunnel server"))
		return
	}
	limit := 15 * time.Second
	if srv.AgentVer == "" || versionLess(srv.AgentVer, "0.4.2") {
		limit = 40 * time.Second // old agent: no long-poll, waits for its 30 s beat
	}
	start := time.Now()
	c := hub.Wait(id)
	hub.Poke(id)
	select {
	case <-c:
		servers, _, _ = a.store.TunnelsCopy()
		for _, s := range servers {
			if s.ID == id {
				writeJSONResp(w, 200, map[string]any{"ok": true, "ms": time.Since(start).Milliseconds(),
					"xrayOk": s.XrayOK, "xrayErr": s.XrayErr, "agentVer": s.AgentVer})
				return
			}
		}
	case <-time.After(limit):
	case <-r.Context().Done():
		return
	}
	writeJSONResp(w, 200, map[string]any{"ok": false, "lastSeen": srv.LastSeen, "lastFail": srv.LastFail})
}

func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(pa) {
			fmt.Sscan(pa[i], &x)
		}
		if i < len(pb) {
			fmt.Sscan(pb[i], &y)
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// TunnelLink: one middle server an inbound goes through, with the state the
// agent reported for that port.
type TunnelLink struct {
	Server  string `json:"server"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	State   string `json:"state"` // ok, busy, down, offline, unknown (old agent), pending
	Online  bool   `json:"online"`
	Via     string `json:"via,omitempty"` // pinned dedicated tunnel
}

func (a *App) tunnelStatus(id string, ib *OMap) []TunnelLink {
	servers, _, tmap := a.store.TunnelsCopy()
	_, ibPort := targetOf(ib)
	out := []TunnelLink{}
	now := time.Now()
	for _, u := range tmap[id] {
		for _, s := range servers {
			if s.ID != u.Server {
				continue
			}
			lp := u.ListenPort(ibPort)
			l := TunnelLink{Server: s.ID, Name: orDefault(s.Name, "tunnel"), Address: orDefault(s.PublicIP, s.Host), Port: lp,
				Online: s.LastSeen > 0 && now.Sub(time.Unix(s.LastSeen, 0)) < onlineWindow, Via: u.Via}
			switch {
			case !l.Online:
				l.State = "offline"
			case s.PortState == nil:
				l.State = "unknown"
			default:
				if st, ok := s.PortState[strconv.Itoa(lp)]; ok {
					l.State = st
				} else {
					l.State = "pending"
				}
			}
			out = append(out, l)
		}
	}
	return out
}

// refreshTunnelInbounds: nothing to do now that every method is pre-armed.
func (a *App) refreshTunnelInbounds() {}

// POST /api/tunnels/{id}/method {method}: switch one middle server. The agent
// tries it for a while and goes back by itself when it cannot reach us.
func (a *App) handleTunnelMethod(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		Method string `json:"method"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	if !validMethod(b.Method) {
		fail(w, 400, errors.New("this method is not available yet"))
		return
	}
	var old TunnelServer
	err := a.store.EditTunnels(func() error {
		s := a.store.tunnelByID(id)
		if s == nil {
			return errors.New("middle server not found")
		}
		if s.Method == b.Method {
			return nil
		}
		if s.Mode == "rev" {
			return errors.New("this middle server is connected over the reverse path right now; switch the method when it is back on the direct path")
		}
		if s.LastSeen == 0 || versionLess(s.AgentVer, agentMethodVer) {
			return fmt.Errorf("update the middle server first (agent %s or newer): run the install command again there", agentMethodVer)
		}
		old = *s
		if s.PrevMethod == "" {
			s.PrevMethod = s.Method
		} else if s.PrevMethod == b.Method {
			s.PrevMethod = ""
		}
		s.Method, s.MethodErr = b.Method, ""
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	if old.ID != "" {
		if err := a.cfg.Mutate(func(root *OMap) error {
			if err := a.ensureTunnelSettings(root); err != nil {
				return err
			}
			return a.applyTunnelConfig(root)
		}); err != nil {
			_ = a.store.EditTunnels(func() error {
				if s := a.store.tunnelByID(id); s != nil {
					s.Method, s.PrevMethod = old.Method, old.PrevMethod
				}
				return nil
			})
			fail(w, 400, err)
			return
		}
		hub.Poke(id)
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// POST /api/tunnels/settings {port, xport}: choose each method's port on this
// server. Every new port is checked against the config and the system (TCP+UDP).
func (a *App) handleTunnelSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Port    int    `json:"port"`
		XPort   int    `json:"xport"`
		RPort   int    `json:"rport"`
		RTarget string `json:"rtarget"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	root, _, err := a.cfg.Load()
	if err != nil {
		fail(w, 500, err)
		return
	}
	_, cur, _ := a.store.TunnelsCopy()
	panel, _ := strconv.Atoi(strings.TrimPrefix(portOf(a.store.Cfg.Listen), ":"))
	others := map[string]bool{}
	for _, v := range asArr(root.Get("inbounds")) {
		if x := asMap(v); x != nil && !isTunnelTag(asStr(x.Get("tag"))) {
			others[asStr(x.Get("port"))] = true
		}
	}
	ours := map[int]bool{cur.Port: true, cur.XPort: true, cur.RPort: true}
	pick := func(p, old int) int {
		if p == 0 {
			return old
		}
		return p
	}
	np, nx, nr := pick(b.Port, cur.Port), pick(b.XPort, cur.XPort), pick(b.RPort, cur.RPort)
	check := func(name string, p, old int) error {
		if p == 0 || p == old {
			return nil
		}
		if p < 1 || p > 65535 {
			return fmt.Errorf("%s port %d is not valid", name, p)
		}
		if p == panel {
			return fmt.Errorf("%s port %d is the panel's port", name, p)
		}
		if others[strconv.Itoa(p)] {
			return fmt.Errorf("%s port %d is used by another inbound", name, p)
		}
		if !ours[p] && !portFree(p) {
			return fmt.Errorf("%s port %d is busy on this server (another program uses it)", name, p)
		}
		return nil
	}
	if (np != 0 && (np == nx || np == nr)) || (nx != 0 && nx == nr) {
		fail(w, 400, errors.New("each tunnel method needs its own port"))
		return
	}
	for _, c := range []struct {
		n      string
		p, old int
	}{{"WS", np, cur.Port}, {"XHTTP", nx, cur.XPort}, {"REALITY", nr, cur.RPort}} {
		if err := check(c.n, c.p, c.old); err != nil {
			fail(w, 400, err)
			return
		}
	}
	nt := cur.RTarget
	if t := strings.TrimSpace(b.RTarget); t != "" {
		if !strings.Contains(t, ":") {
			t += ":443"
		}
		h, p, err := net.SplitHostPort(t)
		if err != nil || h == "" || p == "" || strings.ContainsAny(h, "/ ") {
			fail(w, 400, errors.New("REALITY target must look like www.example.com:443"))
			return
		}
		nt = t
	}
	if np == cur.Port && nx == cur.XPort && nr == cur.RPort && nt == cur.RTarget {
		writeJSONResp(w, 200, map[string]bool{"ok": true})
		return
	}
	set := func(c TunnelSettings) {
		_ = a.store.EditTunnels(func() error {
			t := &a.store.TunnelCfg
			t.Port, t.XPort, t.RPort, t.RTarget = c.Port, c.XPort, c.RPort, c.RTarget
			return nil
		})
	}
	set(TunnelSettings{Port: np, XPort: nx, RPort: nr, RTarget: nt})
	servers, _, _ := a.store.TunnelsCopy()
	if len(servers) > 0 {
		if err := a.cfg.Mutate(func(root *OMap) error {
			if err := a.ensureTunnelSettings(root); err != nil {
				return err
			}
			return a.applyTunnelConfig(root)
		}); err != nil {
			set(cur)
			fail(w, 400, err)
			return
		}
		ids := []string{}
		for _, s := range servers {
			ids = append(ids, s.ID)
		}
		hub.PokeAll(ids)
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// holdFor: how long a quiet heartbeat is held open. Agents from 0.6.3 wait up
// to 75 s, older ones only 45 s.
func holdFor(agentVer string) time.Duration {
	if versionLess(agentVer, "0.6.3") {
		return 25 * time.Second
	}
	return 55 * time.Second
}
