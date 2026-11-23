package main

// WireGuard and mKCP: two more methods of the rotating tunnel, like WS, XHTTP
// and REALITY. A middle server uses one method at a time and searches the
// others (in its rotation pool) when it cannot reach this server; nothing is
// pinned to a fixed path any more. Both run over UDP, straight to this
// server's IP.
//
//   mKCP:      middle -> VLESS over mKCP (UDP) -> xo-tunnel-kcp here
//              -> the same allow rule as every other tunnel inbound
//   WireGuard: middle -> VLESS (plain) to 10.77.1.1:V, dialed through its
//              WireGuard outbound (UDP) -> xo-tunnel-wg here (WireGuard)
//              -> xo-dt-wgv (freedom, only 127.0.0.1:V)
//              -> xo-tunnel-wgv (VLESS on 127.0.0.1:V)
//              -> the same allow rule as every other tunnel inbound
//
// VLESS inside WireGuard carries the real target (127.0.0.1:port), which the
// WireGuard netstack alone does not.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const (
	tunnelMethodWG  = "wg"
	tunnelMethodKCP = "kcp"
	tunnelTagWG     = "xo-tunnel-wg"  // WireGuard inbound (UDP)
	tunnelTagWGV    = "xo-tunnel-wgv" // VLESS on 127.0.0.1, reached through WireGuard
	tunnelTagKCP    = "xo-tunnel-kcp" // VLESS + mKCP inbound (UDP)
	wgFreeOut       = "xo-dt-wgv"     // freedom: WireGuard traffic -> 127.0.0.1:V only
	dedOutPrefix    = "xo-dt-"        // our freedom outbounds (dropped and rebuilt on every apply)
	wgRuleTag       = "xo-tunnel-dt-wg"
	wgVirt          = "10.77.1.1" // the address the middle server dials inside WireGuard
	wgPeerNet       = "10.77.0."  // middle servers' WireGuard addresses (.2 …)
	wgTestNet       = "10.77.2."  // their test keys' addresses (same last number)
	wgCarrierPrefix = "xo-c-"     // middle server: the WireGuard outbound a VLESS outbound dials through
	dedWGPortPref   = 51820
	dedReserved     = 2054 // never used (another service's port)
	// tags of the old dedicated tunnels, removed from the config
	oldTagWG  = "xo-dt-wg"
	oldTagKCP = "xo-dt-kcp"
	// agents able to run each method
	agentWGVer  = "0.6.8"
	agentKCPVer = "0.7.0" // reports its Xray version
	// a test outbound made of two outbounds (WireGuard)
	agentWGTestVer = "0.8.0"
	// Xray 26.6.1 replaced kcpSettings seed/header with finalmask "mkcp-legacy"
	minKCPXray = "26.6.1"
)

// kcpStream: mKCP tuned for a low-latency path between two servers, the same
// on both ends. Xray 26 has no congestion/readBufferSize/writeBufferSize any
// more (silently ignored), so only these knobs exist:
//   - mtu 1350: room for the UDP/IP headers and the mask's 28 bytes (nonce + tag) on
//     a 1500 path, and under 1400 so PPPoE/tunnelled links do not fragment.
//   - tti 10 ms (the minimum; default 50): while a connection is busy, KCP
//     sends and acks only on its tick, so each hop can wait up to one tti.
//   - uplinkCapacity 20 / downlinkCapacity 100 (MB/s): a modest send window
//     keeps bursts from flooding a lossy link (mKCP has no congestion
//     control); the big receive window never limits the sender.
//
// Obfuscation: finalmask "mkcp-legacy" with a value = AES-128-GCM over every
// packet, key = SHA-256 of the seed: no fixed header to match, and packets
// without the seed are dropped.
func kcpStream(seed string) *OMap {
	return om("network", "kcp",
		"kcpSettings", om("mtu", 1350, "tti", 10, "uplinkCapacity", 20, "downlinkCapacity", 100),
		"finalmask", om("udp", []any{om("type", "mkcp-legacy", "settings", om("value", seed))}))
}

// DedTunnel: the old dedicated tunnel record, read once to keep a middle
// server's WireGuard keys (see migrateDedicated).
type DedTunnel struct {
	Type string `json:"type"`
	Key  string `json:"key,omitempty"`
	Pub  string `json:"pub,omitempty"`
	Addr string `json:"addr,omitempty"`
}

// dedReport: sent by 0.6.8–0.7.x agents; ignored now.
type dedReport struct {
	OK  bool   `json:"ok"`
	Ms  int    `json:"ms,omitempty"`
	Err string `json:"err,omitempty"`
}

// migrateDedicated: dedicated tunnels are gone; their pins go back to the
// rotating tunnel and a server keeps its WireGuard keys. Store lock held.
func (s *Store) migrateDedicated() bool {
	changed := false
	for _, t := range s.Tunnels {
		for _, d := range t.Ded {
			if d.Type == tunnelMethodWG && t.WGKey == "" && d.Key != "" {
				t.WGKey, t.WGPub, t.WGAddr = d.Key, d.Pub, d.Addr
			}
		}
		if t.Ded != nil {
			t.Ded, changed = nil, true
		}
	}
	for k, us := range s.TunnelUse {
		for i := range us {
			if us[i].Via != "" {
				us[i].Via, changed = "", true
			}
		}
		s.TunnelUse[k] = us
	}
	return changed
}

func isUDPMethod(m string) bool { return m == tunnelMethodWG || m == tunnelMethodKCP }

// methodCapable: the middle server's agent (and its Xray) can run method m.
func methodCapable(s TunnelServer, m string) bool {
	switch m {
	case tunnelMethodWG:
		return s.AgentVer != "" && !versionLess(s.AgentVer, agentWGVer)
	case tunnelMethodKCP:
		return s.AgentVer != "" && !versionLess(s.AgentVer, agentKCPVer) && s.XrayVer != "" && !versionLess(s.XrayVer, minKCPXray)
	}
	return true
}

// inPool: method m is one the middle server may rotate to.
func inPool(s TunnelServer, m string) bool {
	for _, x := range s.Off {
		if x == m {
			return false
		}
	}
	return true
}

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

// dedPortBad: why port p cannot be the port of the UDP inbound tag
// (tunnelTagWG or tunnelTagKCP); "" when it can.
func (a *App) dedPortBad(root *OMap, p int, set TunnelSettings, tag string) string {
	if p < 1 || p > 65535 {
		return fmt.Sprintf("port %d is not valid", p)
	}
	if p == dedReserved {
		return fmt.Sprintf("port %d is reserved for another service", p)
	}
	if panel, _ := strconv.Atoi(strings.TrimPrefix(portOf(a.store.Cfg.Listen), ":")); p == panel {
		return fmt.Sprintf("port %d is the panel's port", p)
	}
	if p == set.Port || p == set.XPort || p == set.RPort || p == set.WGVPort {
		return fmt.Sprintf("port %d is used by another tunnel method", p)
	}
	if tag == tunnelTagWG && set.KPort != 0 && p == set.KPort {
		return fmt.Sprintf("port %d is used by the mKCP method", p)
	}
	if tag == tunnelTagKCP && set.WGPort != 0 && p == set.WGPort {
		return fmt.Sprintf("port %d is used by the WireGuard method", p)
	}
	ib, _ := findInbound(root, tag)
	if ib != nil && asStr(ib.Get("port")) == strconv.Itoa(p) {
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

// dedPort: the port a UDP inbound listens on: the chosen one (checked), else
// the one it has, else pref, else a free one picked now (and saved).
func (a *App) dedPort(root *OMap, set TunnelSettings, tag, name string, chosen, pref int, save func(int)) (int, error) {
	if chosen != 0 {
		if why := a.dedPortBad(root, chosen, set, tag); why != "" {
			return 0, fmt.Errorf("%s tunnel: %s; choose another port in the Tunnels tab", name, why)
		}
		return chosen, nil
	}
	port := 0
	if ib, _ := findInbound(root, tag); ib != nil {
		port, _ = strconv.Atoi(asStr(ib.Get("port")))
	}
	if port == 0 || a.dedPortBad(root, port, set, tag) != "" {
		port = 0
		if pref != 0 && a.dedPortBad(root, pref, set, tag) == "" {
			port = pref
		}
		for i := 0; port == 0 && i < 30; i++ {
			if p := suggestPort(); p != 0 && a.dedPortBad(root, p, set, tag) == "" {
				port = p
			}
		}
	}
	if port == 0 {
		return 0, fmt.Errorf("no free UDP port for the %s tunnel", name)
	}
	_ = a.store.EditTunnels(func() error { save(port); return nil })
	return port, nil
}

func freeWGAddr(servers []*TunnelServer, self string) string {
	used := map[string]bool{}
	for _, s := range servers {
		if s.ID != self && s.WGAddr != "" {
			used[s.WGAddr] = true
		}
	}
	for n := 2; n < 255; n++ {
		if a := wgPeerNet + strconv.Itoa(n); !used[a] {
			return a
		}
	}
	return ""
}

// ensureWGKeys gives every middle server its WireGuard keys and address, and
// a second key for tests (so a test never fights the live path).
func (a *App) ensureWGKeys() error {
	return a.store.EditTunnels(func() error {
		c := &a.store.TunnelCfg
		if c.WGKey == "" || wgPub(c.WGKey) == "" {
			pr, pb, err := wgKeyPair()
			if err != nil {
				return err
			}
			c.WGKey, c.WGPub = pr, pb
		}
		c.WGPub = wgPub(c.WGKey)
		for _, s := range a.store.Tunnels {
			if s.WGKey == "" || wgPub(s.WGKey) == "" {
				pr, pb, err := wgKeyPair()
				if err != nil {
					return err
				}
				s.WGKey, s.WGPub = pr, pb
			}
			if s.WGTKey == "" || wgPub(s.WGTKey) == "" {
				pr, pb, err := wgKeyPair()
				if err != nil {
					return err
				}
				s.WGTKey, s.WGTPub = pr, pb
			}
			if s.WGAddr == "" {
				if s.WGAddr = freeWGAddr(a.store.Tunnels, s.ID); s.WGAddr == "" {
					return errors.New("no free WireGuard address left")
				}
			}
		}
		return nil
	})
}

// wgTestAddr: the address of a server's test key (same last number).
func wgTestAddr(addr string) string {
	if !strings.HasPrefix(addr, wgPeerNet) {
		return ""
	}
	return wgTestNet + strings.TrimPrefix(addr, wgPeerNet)
}

// applyUDPMethods writes the WireGuard and mKCP inbounds (pre-armed, like the
// other methods). It returns the inbound tags that carry tunnel traffic (for
// the allow rule), the WireGuard rule and the WireGuard inbound tag (blocked
// for anything else). A method that cannot run here (no address for middle
// servers to dial, or an Xray too old for mKCP) is left out and shown as not
// ready.
func (a *App) applyUDPMethods(root *OMap, servers []TunnelServer) (in, rules, only []any, err error) {
	dropDedOutbounds(root)
	// the old dedicated inbounds become the methods' inbounds (same ports)
	for old, tag := range map[string]string{oldTagWG: tunnelTagWG, oldTagKCP: tunnelTagKCP} {
		if ib, _ := findInbound(root, old); ib != nil {
			if cur, _ := findInbound(root, tag); cur == nil {
				ib.Set("tag", tag)
			} else {
				removeInboundTag(root, old)
			}
		}
	}
	clear := func() {
		removeInboundTag(root, tunnelTagWG)
		removeInboundTag(root, tunnelTagWGV)
		removeInboundTag(root, tunnelTagKCP)
		_ = a.store.EditTunnels(func() error { a.store.TunnelCfg.WGOn, a.store.TunnelCfg.KOn = false, false; return nil })
	}
	if len(servers) == 0 {
		clear()
		return nil, nil, nil, nil
	}
	_ = a.ensureWGHost()
	if err := a.ensureWGKeys(); err != nil {
		return nil, nil, nil, err
	}
	var set TunnelSettings
	if err := a.store.EditTunnels(func() error {
		c := &a.store.TunnelCfg
		if c.KSeed == "" {
			c.KSeed = randHex(16)
		}
		if c.KDec == "" || checkDecryption(c.KDec) != nil {
			dec, enc, err := newVlessEnc("x25519", "native")
			if err != nil {
				return err
			}
			c.KDec, c.KEnc = dec, enc
		}
		set = a.store.TunnelCfg
		return nil
	}); err != nil {
		return nil, nil, nil, err
	}
	if set.WGHost == "" {
		clear()
		return nil, nil, nil, nil
	}
	servers, _, _ = a.store.TunnelsCopy() // with their keys
	var clients []any
	for _, s := range servers {
		clients = append(clients, om("id", s.UUID, "email", "tunnel-"+s.ID, "level", 0))
	}

	// mKCP: only when this server's Xray has the finalmask mask
	kOn := false
	if v := DetectCore().Version; v != "" && !versionLess(v, minKCPXray) {
		port, err := a.dedPort(root, set, tunnelTagKCP, "mKCP", set.KPort, 0, func(p int) { a.store.TunnelCfg.KPort = p })
		if err != nil {
			return nil, nil, nil, err
		}
		set.KPort = port
		ib := armInbound(root, tunnelTagKCP, port)
		ib.Set("listen", "0.0.0.0")
		ib.Set("settings", om("clients", clients, "decryption", set.KDec))
		ib.Set("streamSettings", kcpStream(set.KSeed))
		in, kOn = append(in, tunnelTagKCP), true
	} else {
		removeInboundTag(root, tunnelTagKCP)
	}

	// WireGuard: the UDP inbound, the local VLESS inbound behind it, and the
	// one-way door between them
	port, err := a.dedPort(root, set, tunnelTagWG, "WireGuard", set.WGPort, dedWGPortPref, func(p int) { a.store.TunnelCfg.WGPort = p })
	if err != nil {
		return nil, nil, nil, err
	}
	set.WGPort = port
	vport := set.WGVPort
	if ib, _ := findInbound(root, tunnelTagWGV); vport == 0 || ib == nil || asStr(ib.Get("port")) != strconv.Itoa(vport) {
		if vport == 0 || usedPorts(root)[strconv.Itoa(vport)] || !portFree(vport) {
			vport = 0
			for i := 0; vport == 0 && i < 30; i++ {
				if p := suggestPort(); p != 0 && p != port && p != set.KPort && !usedPorts(root)[strconv.Itoa(p)] {
					vport = p
				}
			}
			if vport == 0 {
				return nil, nil, nil, errors.New("no free local port for the WireGuard method")
			}
			_ = a.store.EditTunnels(func() error { a.store.TunnelCfg.WGVPort = vport; return nil })
		}
	}
	var peers []any
	for _, s := range servers {
		peers = append(peers, om("publicKey", s.WGPub, "allowedIPs", []any{s.WGAddr + "/32"}))
		if t := wgTestAddr(s.WGAddr); t != "" && s.WGTPub != "" {
			peers = append(peers, om("publicKey", s.WGTPub, "allowedIPs", []any{t + "/32"}))
		}
	}
	wg := armInbound(root, tunnelTagWG, port)
	wg.Set("listen", "0.0.0.0")
	wg.Set("protocol", "wireguard")
	wg.Set("settings", om("secretKey", set.WGKey, "peers", peers, "mtu", 1420))
	wg.Delete("streamSettings")
	wgv := armInbound(root, tunnelTagWGV, vport)
	wgv.Set("listen", "127.0.0.1")
	wgv.Set("settings", om("clients", clients, "decryption", "none"))
	wgv.Set("streamSettings", om("network", "raw", "security", "none"))
	root.Set("outbounds", append(asArr(root.Get("outbounds")), om("protocol", "freedom", "tag", wgFreeOut,
		"settings", om("redirect", "127.0.0.1:"+strconv.Itoa(vport),
			"finalRules", []any{om("action", "allow", "network", "tcp", "ip", []any{"127.0.0.1"}, "port", strconv.Itoa(vport)), om("action", "block")}))))
	rules = append(rules, om("type", "field", "ruleTag", wgRuleTag, "inboundTag", []any{tunnelTagWG}, "network", "tcp", "outboundTag", wgFreeOut))
	in = append(in, tunnelTagWGV)
	_ = a.store.EditTunnels(func() error { a.store.TunnelCfg.WGOn, a.store.TunnelCfg.KOn = true, kOn; return nil })
	return in, rules, []any{tunnelTagWG}, nil
}

// ---------- the middle server's side ----------

// udpJoin fills j for a UDP method (the server's own keys, this server's
// address and ports); false when the method is not ready here.
func (a *App) udpJoin(j *joinInfo, s TunnelServer, set TunnelSettings, test bool) bool {
	if set.WGHost == "" {
		return false
	}
	j.UHost = set.WGHost
	switch s.Method {
	case tunnelMethodKCP:
		if !set.KOn || set.KPort == 0 || set.KSeed == "" || set.KEnc == "" {
			return false
		}
		j.KPort, j.KSeed, j.KEnc = set.KPort, set.KSeed, set.KEnc
	case tunnelMethodWG:
		if !set.WGOn || set.WGPort == 0 || set.WGVPort == 0 || set.WGPub == "" || s.WGKey == "" || s.WGAddr == "" {
			return false
		}
		j.WPort, j.WVPort, j.WPub, j.WKey, j.WAddr = set.WGPort, set.WGVPort, set.WGPub, s.WGKey, s.WGAddr
		if test {
			if j.WKey, j.WAddr = s.WGTKey, wgTestAddr(s.WGAddr); j.WKey == "" || j.WAddr == "" {
				return false
			}
		}
	default:
		return false
	}
	return true
}

// udpOutbounds: how a middle server dials this server over a UDP method,
// tagged tag. WireGuard is two outbounds: VLESS, dialed through WireGuard.
func udpOutbounds(j joinInfo, tag string) []any {
	user := om("id", j.UUID, "encryption", "none")
	if j.Method == tunnelMethodKCP {
		user.Set("encryption", j.KEnc)
		return []any{om("tag", tag, "protocol", "vless",
			"settings", om("vnext", []any{om("address", j.UHost, "port", j.KPort, "users", []any{user})}),
			"streamSettings", kcpStream(j.KSeed))}
	}
	carrier := wgCarrierPrefix + tag
	return []any{
		om("tag", tag, "protocol", "vless",
			"settings", om("vnext", []any{om("address", wgVirt, "port", j.WVPort, "users", []any{user})}),
			"streamSettings", om("network", "raw", "security", "none", "sockopt", om("dialerProxy", carrier))),
		om("tag", carrier, "protocol", "wireguard",
			"settings", om("secretKey", j.WKey, "address", []any{j.WAddr + "/32"},
				"peers", []any{om("publicKey", j.WPub, "endpoint", net.JoinHostPort(j.UHost, strconv.Itoa(j.WPort)), "keepAlive", 25)},
				"mtu", 1420, "noKernelTun", true)),
	}
}

// tunnelsOnStart: after an update, arm the WireGuard and mKCP methods (and
// turn old dedicated tunnels into them) once; nothing changes when the config
// already matches.
func (a *App) tunnelsOnStart() {
	servers, _, _ := a.store.TunnelsCopy()
	if len(servers) == 0 || a.store.Cfg.Domain == "" || a.store.Cfg.CertFile == "" {
		return
	}
	if err := a.cfg.Mutate(func(root *OMap) error {
		if err := a.ensureTunnelSettings(root); err != nil {
			return err
		}
		return a.applyTunnelConfig(root)
	}); err != nil {
		log.Printf("tunnels: %v", err)
	}
}

// ---------- handlers ----------

// ensureWGHost: the address middle servers dial over UDP. It must reach this
// server directly, so a public IP is preferred over the domain.
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
		return errors.New("could not find this server's public IP: set the UDP address in the Tunnels tab")
	}
	return a.store.EditTunnels(func() error { a.store.TunnelCfg.WGHost = h; return nil })
}

// POST /api/tunnels/{id}/pool {method, on}: put a method in or out of a middle
// server's rotation. The method it uses now always stays in.
func (a *App) handleTunnelPool(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		Method string `json:"method"`
		On     bool   `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	if !validMethod(b.Method) {
		fail(w, 400, errors.New("unknown tunnel method"))
		return
	}
	err := a.store.EditTunnels(func() error {
		s := a.store.tunnelByID(id)
		if s == nil {
			return errors.New("middle server not found")
		}
		if !b.On && (s.Method == b.Method || s.PrevMethod == b.Method) {
			return errors.New("this is the method the middle server uses now; switch to another method first")
		}
		var off []string
		for _, x := range s.Off {
			if x != b.Method {
				off = append(off, x)
			}
		}
		if !b.On {
			off = append(off, b.Method)
		}
		s.Off = off
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	hub.Poke(id) // its next config has the new set of ways
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// POST /api/tunnels/dtsettings {wgport, kport, wghost}: the WireGuard and
// mKCP ports and the address middle servers dial over UDP.
func (a *App) handleDedSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		WGPort int    `json:"wgport"`
		KPort  int    `json:"kport"`
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
	np, nk, nh := cur.WGPort, cur.KPort, cur.WGHost
	if b.WGPort != 0 && b.WGPort != cur.WGPort {
		if why := a.dedPortBad(root, b.WGPort, cur, tunnelTagWG); why != "" {
			fail(w, 400, errors.New("WireGuard "+why))
			return
		}
		np = b.WGPort
	}
	if b.KPort != 0 && b.KPort != cur.KPort {
		c := cur
		c.WGPort = np
		if why := a.dedPortBad(root, b.KPort, c, tunnelTagKCP); why != "" {
			fail(w, 400, errors.New("mKCP "+why))
			return
		}
		nk = b.KPort
	}
	if h := strings.TrimSpace(b.WGHost); h != "" && h != cur.WGHost {
		if net.ParseIP(h) == nil && !hostRe.MatchString(strings.ToLower(h)) {
			fail(w, 400, errors.New("the UDP address must be an IP or a domain that points straight at this server"))
			return
		}
		nh = h
	}
	if np == cur.WGPort && nk == cur.KPort && nh == cur.WGHost {
		writeJSONResp(w, 200, map[string]bool{"ok": true})
		return
	}
	set := func(p, k int, h string) {
		_ = a.store.EditTunnels(func() error {
			a.store.TunnelCfg.WGPort, a.store.TunnelCfg.KPort, a.store.TunnelCfg.WGHost = p, k, h
			return nil
		})
	}
	set(np, nk, nh)
	if len(servers) > 0 {
		if err := a.cfg.Mutate(func(root *OMap) error {
			if err := a.ensureTunnelSettings(root); err != nil {
				return err
			}
			return a.applyTunnelConfig(root)
		}); err != nil {
			set(cur.WGPort, cur.KPort, cur.WGHost)
			fail(w, 400, err)
			return
		}
		var ids []string
		for _, s := range servers {
			ids = append(ids, s.ID)
		}
		hub.PokeAll(ids)
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}
