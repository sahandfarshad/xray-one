package main

// Dedicated tunnels: fixed paths between this server and a middle server,
// separate from the rotating tunnel (tunnel.go, reverse.go). A dedicated
// tunnel never rotates, never searches and never falls back: inbounds pinned
// to it go only through it, and when it drops they stay down. Its state is
// never read by the rotating side, and the rotating side's state is never
// read here. WireGuard is the first type; more types plug into dedTypes.
//
//   user -> middle :P (dokodemo dfwd-wg-P, target 10.77.1.N:port)
//        -> xo-dt-wg-out (Xray WireGuard outbound, UDP to this server)
//        -> xo-dt-wg (Xray WireGuard inbound here)
//        -> xo-dt-d<N> (freedom, redirect to the real host, same port)
//        -> the pinned inbound
//
// The target goes through a virtual address because the WireGuard netstack
// does not carry 127.0.0.1 through the tunnel.

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dedWG          = "wg"
	dedTagWG       = "xo-dt-wg"     // WireGuard inbound on this server
	dedOutWG       = "xo-dt-wg-out" // WireGuard outbound on the middle server
	dedOutPrefix   = "xo-dt-"       // freedom outbounds here: xo-dt-d<N>
	dedFwdPrefix   = "dfwd-"        // pinned forwarders on the middle server: dfwd-<type>-<port>
	dedProbeSuffix = "-probe"       // dt-<type>-probe: status check on the middle server
	dedRuleTag     = "xo-tunnel-dt-"
	agentDedVer    = "0.6.8"
	dedPeerNet     = "10.77.0." // middle servers' WireGuard addresses (.2 …)
	dedVirtNet     = "10.77.1." // virtual targets (.1 = 127.0.0.1)
	dedWGPortPref  = 51820
	dedReserved    = 2054 // never used (another service's port)
	dedStale       = 3 * time.Minute
)

// dedTypes: the dedicated tunnel cards. Ready ones can be switched on.
var dedTypes = []map[string]any{
	{"id": dedWG, "ready": true},
	{"id": "backhaul", "ready": false},
}

func validDedType(t string) bool { return t == dedWG }

// DedTunnel: one dedicated tunnel of a middle server.
type DedTunnel struct {
	Type  string `json:"type"`
	On    bool   `json:"on"`
	Key   string `json:"key,omitempty"`  // the middle server's WireGuard private key
	Pub   string `json:"pub,omitempty"`  // its public key
	Addr  string `json:"addr,omitempty"` // its address inside the tunnel
	Up    bool   `json:"up,omitempty"`   // last check through it worked
	ChkAt int64  `json:"chkAt,omitempty"`
	OkAt  int64  `json:"okAt,omitempty"`
	Ms    int    `json:"ms,omitempty"`
	Err   string `json:"err,omitempty"`
}

func (s *TunnelServer) dedOf(t string) *DedTunnel {
	for i := range s.Ded {
		if s.Ded[i].Type == t {
			return &s.Ded[i]
		}
	}
	return nil
}

func dedOn(s TunnelServer, t string) bool {
	d := s.dedOf(t)
	return d != nil && d.On
}

func dedCapable(s TunnelServer) bool {
	return s.AgentVer != "" && !versionLess(s.AgentVer, agentDedVer)
}

func probePort(s TunnelServer) int {
	if s.CtlPort > 0 {
		return s.CtlPort + 2
	}
	return agentCtlPort + 2
}

// dedTargets: the hosts pinned inbounds live on (127.0.0.1 first, for the
// status check to the panel), each with its ports. The same list builds both
// ends, so a host's index is its virtual address on both servers.
func (a *App) dedTargets(root *OMap, servers []TunnelServer, tmap map[string][]TunnelUse) ([]string, map[string]map[int]bool) {
	on := map[string]bool{}
	for _, s := range servers {
		if dedOn(s, dedWG) {
			on[s.ID] = true
		}
	}
	ports := map[string]map[int]bool{"127.0.0.1": {}}
	if p, err := strconv.Atoi(strings.TrimPrefix(portOf(a.store.Cfg.Listen), ":")); err == nil {
		ports["127.0.0.1"][p] = true
	}
	for i, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		if ib == nil {
			continue
		}
		for _, u := range tmap[inboundID(ib, i)] {
			if u.Via != dedWG || !on[u.Server] {
				continue
			}
			if h, p := targetOf(ib); p > 0 {
				if ports[h] == nil {
					ports[h] = map[int]bool{}
				}
				ports[h][p] = true
			}
		}
	}
	hosts := []string{}
	for h := range ports {
		if h != "127.0.0.1" {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	return append([]string{"127.0.0.1"}, hosts...), ports
}

func dedVirt(hosts []string, h string) string {
	for i, x := range hosts {
		if x == h {
			return dedVirtNet + strconv.Itoa(i+1)
		}
	}
	return ""
}

// ---------- this server's config ----------

func isDedOut(tag string) bool { return strings.HasPrefix(tag, dedOutPrefix) }

func dropDedOutbounds(root *OMap) {
	if asArr(root.Get("outbounds")) == nil {
		return
	}
	keep := []any{}
	for _, v := range asArr(root.Get("outbounds")) {
		if !isDedOut(asStr(asMap(v).Get("tag"))) {
			keep = append(keep, v)
		}
	}
	root.Set("outbounds", keep)
}

func removeInboundTag(root *OMap, tag string) {
	keep := []any{}
	for _, v := range asArr(root.Get("inbounds")) {
		if asStr(asMap(v).Get("tag")) != tag {
			keep = append(keep, v)
		}
	}
	root.Set("inbounds", keep)
}

// dedPortBad: why port p cannot be the WireGuard port ("" when it can).
func (a *App) dedPortBad(root *OMap, p int, set TunnelSettings) string {
	if p < 1 || p > 65535 {
		return fmt.Sprintf("port %d is not valid", p)
	}
	if p == dedReserved {
		return fmt.Sprintf("port %d is reserved for another service", p)
	}
	if panel, _ := strconv.Atoi(strings.TrimPrefix(portOf(a.store.Cfg.Listen), ":")); p == panel {
		return fmt.Sprintf("port %d is the panel's port", p)
	}
	if p == set.Port || p == set.XPort || p == set.RPort {
		return fmt.Sprintf("port %d is used by the rotating tunnel", p)
	}
	ib, _ := findInbound(root, dedTagWG)
	mine := ib != nil && asStr(ib.Get("port")) == strconv.Itoa(p)
	if mine {
		return ""
	}
	if usedPorts(root)[strconv.Itoa(p)] {
		return fmt.Sprintf("port %d is used by another inbound", p)
	}
	if !portFree(p) {
		return fmt.Sprintf("port %d is busy on this server (TCP or UDP)", p)
	}
	return ""
}

// applyDedicated writes the WireGuard inbound and its outbounds, and returns
// the routing rules that let its traffic reach only the pinned inbounds (and
// the panel, for the status check).
func (a *App) applyDedicated(root *OMap, servers []TunnelServer, tmap map[string][]TunnelUse) ([]any, []any, error) {
	dropDedOutbounds(root)
	var on []TunnelServer
	for _, s := range servers {
		if d := s.dedOf(dedWG); d != nil && d.On && d.Pub != "" && d.Addr != "" {
			on = append(on, s)
		}
	}
	if len(on) == 0 {
		removeInboundTag(root, dedTagWG)
		return nil, nil, nil
	}
	var set TunnelSettings
	err := a.store.EditTunnels(func() error {
		c := &a.store.TunnelCfg
		if c.WGKey == "" || wgPub(c.WGKey) == "" {
			pr, pb, err := wgKeyPair()
			if err != nil {
				return err
			}
			c.WGKey, c.WGPub = pr, pb
		}
		c.WGPub = wgPub(c.WGKey)
		set = *c
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	port := set.WGPort
	if port == 0 {
		if ib, _ := findInbound(root, dedTagWG); ib != nil {
			port, _ = strconv.Atoi(asStr(ib.Get("port")))
		}
		if port == 0 || a.dedPortBad(root, port, set) != "" {
			port = 0
			if a.dedPortBad(root, dedWGPortPref, set) == "" {
				port = dedWGPortPref
			}
			for i := 0; port == 0 && i < 30; i++ {
				if p := suggestPort(); p != 0 && a.dedPortBad(root, p, set) == "" {
					port = p
				}
			}
		}
		if port == 0 {
			return nil, nil, errors.New("no free UDP port for the WireGuard tunnel")
		}
		_ = a.store.EditTunnels(func() error { a.store.TunnelCfg.WGPort = port; return nil })
	} else if why := a.dedPortBad(root, port, set); why != "" {
		return nil, nil, fmt.Errorf("WireGuard tunnel: %s; choose another port in the Tunnels tab", why)
	}
	var peers []any
	for _, s := range on {
		d := s.dedOf(dedWG)
		peers = append(peers, om("publicKey", d.Pub, "allowedIPs", []any{d.Addr + "/32"}))
	}
	ib, _ := findInbound(root, dedTagWG)
	if ib == nil {
		ib = om("tag", dedTagWG, "listen", "0.0.0.0", "port", port, "protocol", "wireguard")
		root.Set("inbounds", append(asArr(root.Get("inbounds")), ib))
	}
	ib.Set("port", port)
	ib.Set("protocol", "wireguard")
	ib.Set("settings", om("secretKey", set.WGKey, "peers", peers, "mtu", 1420))
	ib.Delete("streamSettings")
	ib.Delete("sniffing")

	hosts, ports := a.dedTargets(root, servers, tmap)
	obs := asArr(root.Get("outbounds"))
	var rules []any
	for i, h := range hosts {
		pl := map[int]bool{}
		for p := range ports[h] {
			pl[p] = true
		}
		if len(pl) == 0 {
			continue
		}
		ps := strings.Join(intKeys(pl), ",")
		tag := fmt.Sprintf("%sd%d", dedOutPrefix, i)
		obs = append(obs, om("protocol", "freedom", "tag", tag, "settings", om("redirect", h+":0",
			"finalRules", []any{om("action", "allow", "network", "tcp,udp", "ip", []any{h}, "port", ps), om("action", "block")})))
		rules = append(rules, om("type", "field", "ruleTag", fmt.Sprintf("%s%d", dedRuleTag, i), "inboundTag", []any{dedTagWG},
			"ip", []any{dedVirtNet + strconv.Itoa(i+1)}, "port", ps, "outboundTag", tag))
	}
	root.Set("outbounds", obs)
	return rules, []any{dedTagWG}, nil
}

// ---------- the middle server's config ----------

type dedRelay struct {
	WG *wgRelay
}

type wgRelay struct {
	Key, Addr, Pub, Endpoint string
	Hosts                    []string
	PanelPort                int
}

func (d *dedRelay) has(t string) bool { return d != nil && t == dedWG && d.WG != nil }

// dedFor: the dedicated tunnels a middle server runs (nil for old agents).
func (a *App) dedFor(root *OMap, s TunnelServer) *dedRelay {
	if root == nil || !dedCapable(s) {
		return nil
	}
	d := s.dedOf(dedWG)
	servers, set, tmap := a.store.TunnelsCopy()
	if d == nil || !d.On || d.Key == "" || set.WGPub == "" || set.WGPort == 0 || set.WGHost == "" {
		return nil
	}
	if ib, _ := findInbound(root, dedTagWG); ib == nil {
		return nil
	}
	hosts, _ := a.dedTargets(root, servers, tmap)
	panel, _ := strconv.Atoi(strings.TrimPrefix(portOf(a.store.Cfg.Listen), ":"))
	return &dedRelay{WG: &wgRelay{Key: d.Key, Addr: d.Addr, Pub: set.WGPub,
		Endpoint: net.JoinHostPort(set.WGHost, strconv.Itoa(set.WGPort)), Hosts: hosts, PanelPort: panel}}
}

// relayDedFwd: the forwarder for a pinned port, or nil when its dedicated
// tunnel is not there (then the port stays closed: no fallback).
func relayDedFwd(f fwdPort, ded *dedRelay) *OMap {
	if !ded.has(f.Via) {
		return nil
	}
	v := dedVirt(ded.WG.Hosts, f.Host)
	if v == "" {
		return nil
	}
	return om("tag", fmt.Sprintf("%s%s-%d", dedFwdPrefix, f.Via, f.Listen), "listen", "0.0.0.0", "port", f.Listen,
		"protocol", "dokodemo-door", "settings", om("address", v, "port", f.Port, "network", "tcp,udp"))
}

// addRelayDedicated adds the WireGuard outbound, the status check inbound and
// the rule that sends pinned forwarders only through it.
func addRelayDedicated(root *OMap, ded *dedRelay, ctl int) {
	if !ded.has(dedWG) {
		return
	}
	w := ded.WG
	probe := "dt-" + dedWG + dedProbeSuffix
	tags := []any{}
	ins := asArr(root.Get("inbounds"))
	for _, v := range ins {
		if t := asStr(asMap(v).Get("tag")); strings.HasPrefix(t, dedFwdPrefix+dedWG+"-") {
			tags = append(tags, t)
		}
	}
	ins = append(ins, om("tag", probe, "listen", "127.0.0.1", "port", ctl+2, "protocol", "dokodemo-door",
		"settings", om("address", dedVirtNet+"1", "port", w.PanelPort, "network", "tcp")))
	tags = append(tags, probe)
	root.Set("inbounds", ins)
	root.Set("outbounds", append(asArr(root.Get("outbounds")), om("tag", dedOutWG, "protocol", "wireguard",
		"settings", om("secretKey", w.Key, "address", []any{w.Addr + "/32"},
			"peers", []any{om("publicKey", w.Pub, "endpoint", w.Endpoint, "keepAlive", 25)},
			"mtu", 1420, "noKernelTun", true))))
	rt := asMap(root.Get("routing"))
	if rt == nil {
		rt = om("rules", []any{})
		root.Set("routing", rt)
	}
	rt.Set("rules", append(asArr(rt.Get("rules")), om("type", "field", "ruleTag", "xo-dt-"+dedWG+"-route",
		"inboundTag", tags, "outboundTag", dedOutWG)))
}

// ---------- agent side: status check through each dedicated tunnel ----------

type dedReport struct {
	OK  bool   `json:"ok"`
	Ms  int    `json:"ms,omitempty"`
	Err string `json:"err,omitempty"`
}

type dedProbes struct {
	mu  sync.Mutex
	res map[string]dedReport
}

func (p *dedProbes) snapshot() map[string]dedReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.res) == 0 {
		return nil
	}
	out := map[string]dedReport{}
	for k, v := range p.res {
		out[k] = v
	}
	return out
}

// probeTargets: dedicated type -> local port of its status check inbound.
func probeTargets(cfg []byte) map[string]int {
	var c struct {
		Inbounds []struct {
			Tag  string `json:"tag"`
			Port any    `json:"port"`
		} `json:"inbounds"`
	}
	out := map[string]int{}
	if json.Unmarshal(cfg, &c) == nil {
		for _, ib := range c.Inbounds {
			if f, ok := ib.Port.(float64); ok && strings.HasPrefix(ib.Tag, "dt-") && strings.HasSuffix(ib.Tag, dedProbeSuffix) {
				out[strings.TrimSuffix(strings.TrimPrefix(ib.Tag, "dt-"), dedProbeSuffix)] = int(f)
			}
		}
	}
	return out
}

// dedProbeLoop checks every dedicated tunnel every 30 s: an HTTP request to
// the panel through it. Any HTTP answer means the path works. Runs on its
// own, so it never touches the heartbeat or the rotating tunnel's search.
func dedProbeLoop(p *dedProbes, panel string) {
	u, err := url.Parse(panel)
	if err != nil {
		return
	}
	c := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // the hop ends at the panel on 127.0.0.1, inside the tunnel
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		cfg, _ := os.ReadFile(filepath.Join(agentDir, "xray.json"))
		targets := probeTargets(cfg)
		res := map[string]dedReport{}
		for t, port := range targets {
			start := time.Now()
			pu := *u
			pu.Host = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			r := dedReport{}
			resp, err := c.Get(pu.String())
			if err != nil {
				r.Err = trimTo(err.Error(), 200)
			} else {
				resp.Body.Close()
				r.OK, r.Ms = true, int(time.Since(start).Milliseconds())
			}
			res[t] = r
		}
		p.mu.Lock()
		p.res = res
		p.mu.Unlock()
		time.Sleep(30 * time.Second)
	}
}

// saveDedReports stores what the agent found (store lock held).
func saveDedReports(s *TunnelServer, rep map[string]dedReport) {
	now := time.Now().Unix()
	for i := range s.Ded {
		d := &s.Ded[i]
		r, ok := rep[d.Type]
		if !d.On || !ok {
			continue
		}
		d.Up, d.ChkAt, d.Ms, d.Err = r.OK, now, r.Ms, r.Err
		if r.OK {
			d.OkAt, d.Err = now, ""
		}
	}
}

// ---------- handlers ----------

// dedState: what the panel shows for one dedicated tunnel.
func dedState(d DedTunnel, online bool) string {
	switch {
	case !d.On:
		return "off"
	case !online:
		return "offline"
	case d.ChkAt == 0 || time.Since(time.Unix(d.ChkAt, 0)) > dedStale:
		return "pending"
	case d.Up:
		return "up"
	}
	return "down"
}

func freeDedAddr(servers []*TunnelServer, self string) string {
	used := map[string]bool{}
	for _, s := range servers {
		if s.ID == self {
			continue
		}
		if d := s.dedOf(dedWG); d != nil && d.Addr != "" {
			used[d.Addr] = true
		}
	}
	for n := 2; n < 255; n++ {
		if a := dedPeerNet + strconv.Itoa(n); !used[a] {
			return a
		}
	}
	return ""
}

// POST /api/tunnels/{id}/dedicated {type, on}: switch a dedicated tunnel of a
// middle server on or off. Off puts its pinned inbounds back on the rotating
// tunnel.
func (a *App) handleDedicated(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		Type string `json:"type"`
		On   bool   `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	if !validDedType(b.Type) {
		fail(w, 400, errors.New("this dedicated tunnel type is not available yet"))
		return
	}
	if b.On {
		if err := a.ensureWGHost(); err != nil {
			fail(w, 400, err)
			return
		}
	}
	var backup []byte
	var useBackup map[string][]TunnelUse
	err := a.store.EditTunnels(func() error {
		s := a.store.tunnelByID(id)
		if s == nil {
			return errors.New("middle server not found")
		}
		backup, _ = json.Marshal(s.Ded)
		useBackup = map[string][]TunnelUse{}
		for k, v := range a.store.TunnelUse {
			useBackup[k] = append([]TunnelUse{}, v...)
		}
		d := s.dedOf(b.Type)
		if !b.On {
			if d != nil {
				d.On, d.Up, d.ChkAt, d.Err = false, false, 0, ""
			}
			for k, us := range a.store.TunnelUse {
				for i := range us {
					if us[i].Server == id && us[i].Via == b.Type {
						us[i].Via = ""
					}
				}
				a.store.TunnelUse[k] = us
			}
			return nil
		}
		if s.LastSeen == 0 || !dedCapable(*s) {
			return fmt.Errorf("update the middle server first (agent %s or newer): run the install command again there", agentDedVer)
		}
		pp := probePort(*s)
		for _, bp := range s.Busy {
			if bp == pp {
				return fmt.Errorf("port %d on %s is busy; the dedicated tunnel's status check needs it", pp, s.Name)
			}
		}
		for _, us := range a.store.TunnelUse {
			for _, u := range us {
				if u.Server == id && u.Port == pp {
					return fmt.Errorf("port %d on %s is used by a tunneled inbound; the dedicated tunnel's status check needs it", pp, s.Name)
				}
			}
		}
		if d == nil {
			s.Ded = append(s.Ded, DedTunnel{Type: b.Type})
			d = s.dedOf(b.Type)
		}
		if d.Key == "" || wgPub(d.Key) == "" {
			pr, pb, err := wgKeyPair()
			if err != nil {
				return err
			}
			d.Key, d.Pub = pr, pb
		}
		if d.Addr == "" {
			if d.Addr = freeDedAddr(a.store.Tunnels, id); d.Addr == "" {
				return errors.New("no free WireGuard address left")
			}
		}
		d.On, d.Up, d.ChkAt, d.Err = true, false, 0, ""
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	if err := a.cfg.Mutate(func(root *OMap) error {
		if err := a.ensureTunnelSettings(root); err != nil {
			return err
		}
		return a.applyTunnelConfig(root)
	}); err != nil {
		_ = a.store.EditTunnels(func() error {
			if s := a.store.tunnelByID(id); s != nil {
				var old []DedTunnel
				_ = json.Unmarshal(backup, &old)
				s.Ded = old
			}
			a.store.TunnelUse = useBackup
			return nil
		})
		fail(w, 400, err)
		return
	}
	hub.Poke(id)
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// ensureWGHost: the address middle servers dial for WireGuard. It must reach
// this server directly (UDP), so a public IP is preferred over the domain.
func (a *App) ensureWGHost() error {
	_, set, _ := a.store.TunnelsCopy()
	if set.WGHost != "" {
		return nil
	}
	h := a.store.Cfg.PublicHost
	if net.ParseIP(h) == nil {
		h = publicIP()
	}
	if h == "" {
		return errors.New("could not find this server's public IP: set the WireGuard address in the Tunnels tab")
	}
	return a.store.EditTunnels(func() error { a.store.TunnelCfg.WGHost = h; return nil })
}

// POST /api/tunnels/dtsettings {wgport, wghost}: the WireGuard tunnel's port
// and the address middle servers dial.
func (a *App) handleDedSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		WGPort int    `json:"wgport"`
		WGHost string `json:"wghost"`
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
	servers, cur, _ := a.store.TunnelsCopy()
	np, nh := cur.WGPort, cur.WGHost
	if b.WGPort != 0 && b.WGPort != cur.WGPort {
		if why := a.dedPortBad(root, b.WGPort, cur); why != "" {
			fail(w, 400, errors.New("WireGuard "+why))
			return
		}
		np = b.WGPort
	}
	if h := strings.TrimSpace(b.WGHost); h != "" && h != cur.WGHost {
		if net.ParseIP(h) == nil && !hostRe.MatchString(strings.ToLower(h)) {
			fail(w, 400, errors.New("the WireGuard address must be an IP or a domain that points straight at this server"))
			return
		}
		nh = h
	}
	if np == cur.WGPort && nh == cur.WGHost {
		writeJSONResp(w, 200, map[string]bool{"ok": true})
		return
	}
	set := func(p int, h string) {
		_ = a.store.EditTunnels(func() error { a.store.TunnelCfg.WGPort, a.store.TunnelCfg.WGHost = p, h; return nil })
	}
	set(np, nh)
	var ids []string
	for _, s := range servers {
		if dedOn(s, dedWG) {
			ids = append(ids, s.ID)
		}
	}
	if len(ids) > 0 {
		if err := a.cfg.Mutate(func(root *OMap) error {
			if err := a.ensureTunnelSettings(root); err != nil {
				return err
			}
			return a.applyTunnelConfig(root)
		}); err != nil {
			set(cur.WGPort, cur.WGHost)
			fail(w, 400, err)
			return
		}
		hub.PokeAll(ids)
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}
