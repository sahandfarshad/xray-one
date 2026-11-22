package main

// Finding each other in the dark (VLESS Reverse Proxy) and a domain + SSL per
// middle server.
//
// When the two servers lose each other, both search on their own, without
// any message from the other side:
//   - the middle server tries its ways to dial this server (WS, XHTTP,
//     REALITY) one after another, a few tries each, then rests revCool and
//     starts over;
//   - this server tries its ways to dial the middle server (REALITY, and with
//     the middle server's domain also WS+TLS and XHTTP+TLS) one after
//     another, revTry each, then rests revCool and starts over.
// The first connection that gets through, from either side, becomes the path
// for both and all searching stops. The middle server notices a connection
// this server made by sending its heartbeat over it (ctl-rev); this server
// notices one the middle server made by its heartbeat arriving.
//
//   reverse path: user -> middle :P -> xo-rev ==> connection this server
//                 opened -> xo-rin-<id> -> 127.0.0.1:P

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	agentRevVer    = "0.6.5"
	revOutPrefix   = "xo-rout-" // outbound on this server that dials a middle server
	revInPrefix    = "xo-rin-"  // where traffic coming back over it enters routing here
	relayRevIn     = "xo-rin"   // listeners on the middle server
	relayRevOut    = "xo-rev"   // virtual outbound on the middle server
	relayCtlRev    = "ctl-rev"  // heartbeat over the reverse path
	relayAltPrefix = "xo-f-"    // the middle server's other ways to dial us
	relayPathRule  = "xo-path"  // agent-made rule: which way its traffic goes
	// this server starts searching for a middle server unseen this long
	revOffline = 90 * time.Second
	revTry     = 60 * time.Second // per way, this server's side
	revCool    = 5 * time.Minute  // rest after every way failed (both sides)
	// agent side: tries per way and the gap between them
	searchTries = 3
	searchGap   = 8 * time.Second
)

// ports tried for the listeners on the middle server, first free ones win
var revPorts = []int{8443, 2096, 2087, 2083, 2053, 9443, 2443}

type revInfo struct {
	Port, PortW, PortX     int
	UUID, Key, SNI, Target string
	SID, Path              string
	Domain, Cert, CertKey  string // middle server's own domain and its LE files there
	Alts                   []any
}

func revCapable(s TunnelServer) bool {
	return s.AgentVer != "" && !versionLess(s.AgentVer, agentRevVer)
}

func (a *App) revFor(s TunnelServer) *revInfo {
	if !revCapable(s) || s.RevPort == 0 || s.RevKey == "" || s.RevUUID == "" {
		return nil
	}
	_, set, _ := a.store.TunnelsCopy()
	t := set.RTarget
	if t == "" {
		t = defaultRTarget
	}
	host, _, _ := strings.Cut(t, ":")
	r := &revInfo{Port: s.RevPort, UUID: s.RevUUID, Key: s.RevKey, SNI: host, Target: t, SID: s.RevSID, Path: s.RevPath}
	if s.Domain != "" && s.CertOK && s.RevPortW > 0 && s.RevPortX > 0 && s.RevPath != "" {
		dir := filepath.Join(agentDir, "certs", s.Domain)
		r.Domain, r.Cert, r.CertKey = s.Domain, filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
		r.PortW, r.PortX = s.RevPortW, s.RevPortX
	}
	// the other ways the middle server can dial us, for its own search
	for _, m := range []string{tunnelMethodWS, tunnelMethodXHTTP, tunnelMethodRT} {
		if m == orDefault(s.Method, tunnelMethodWS) {
			continue
		}
		t := s
		t.Method = m
		if m == tunnelMethodWS {
			t.Method = ""
		}
		j := a.joinFor(t)
		if m == tunnelMethodWS {
			j.Method = ""
		} else if j.Method != m || (m == tunnelMethodXHTTP && j.XPort == 0) || (m == tunnelMethodRT && (j.RPort == 0 || j.RPub == "")) {
			continue // not ready on this server
		}
		o := mainOutbound(j)
		o.Set("tag", relayAltPrefix+m)
		r.Alts = append(r.Alts, o)
	}
	return r
}

// revWays: how this server can dial a middle server, in search order.
func revWays(r *revInfo) []string {
	w := []string{tunnelMethodRT}
	if r.Domain != "" {
		w = append(w, tunnelMethodWS, tunnelMethodXHTTP)
	}
	return w
}

// ensureRevLocked gives a middle server its listener settings and ports that
// are free there. Call with the store locked.
func ensureRevLocked(s *TunnelServer, fwd []fwdPort) bool {
	if !revCapable(*s) {
		return false
	}
	changed := false
	if s.RevKey == "" || s.RevPub == "" {
		if pr, pb, err := genX25519(); err == nil {
			s.RevKey, s.RevPub, changed = pr, pb, true
		}
	}
	if s.RevUUID == "" {
		s.RevUUID, changed = newUUID(), true
	}
	if s.RevSID == "" {
		s.RevSID, changed = randHex(4), true
	}
	if s.RevPath == "" {
		s.RevPath, changed = "/"+randHex(6), true
	}
	ctl := s.CtlPort
	if ctl == 0 {
		ctl = agentCtlPort
	}
	bad := map[int]bool{ctl: true, ctl + 1: true, 80: true}
	for _, p := range s.Busy {
		bad[p] = true
	}
	for _, f := range fwd {
		bad[f.Listen] = true
	}
	pick := func(cur *int) {
		if *cur != 0 && !bad[*cur] {
			bad[*cur] = true
			return
		}
		p := 0
		for _, c := range revPorts {
			if !bad[c] {
				p = c
				break
			}
		}
		for i := 0; p == 0 && i < 200; i++ {
			if c := 20000 + rand.Intn(30000); !bad[c] {
				p = c
			}
		}
		if p != 0 && p != *cur {
			*cur, changed = p, true
		}
		bad[p] = true
	}
	pick(&s.RevPort)
	pick(&s.RevPortW)
	pick(&s.RevPortX)
	return changed
}

// addRelayReverse adds the listeners this server dials, the heartbeat inbound
// over them, and the middle server's other ways to dial us.
func addRelayReverse(root *OMap, rev *revInfo, ctl int) {
	if rev == nil || rev.Port == 0 {
		return
	}
	cl := func(flow string) []any {
		return []any{om("id", rev.UUID, "flow", flow, "reverse", om("tag", relayRevOut))}
	}
	ins := asArr(root.Get("inbounds"))
	ins = append(ins, om("tag", relayCtlRev, "listen", "127.0.0.1", "port", ctl+1, "protocol", "socks",
		"settings", om("auth", "noauth", "udp", false)))
	ins = append(ins, om("tag", relayRevIn, "listen", "0.0.0.0", "port", rev.Port, "protocol", "vless",
		"settings", om("clients", cl("xtls-rprx-vision"), "decryption", "none"),
		"streamSettings", om("network", "raw", "security", "reality",
			"realitySettings", om("show", false, "target", rev.Target, "xver", 0, "serverNames", []any{rev.SNI},
				"privateKey", rev.Key, "shortIds", []any{rev.SID}))))
	if rev.Domain != "" {
		tls := func(alpn ...any) *OMap {
			return om("serverName", rev.Domain, "alpn", alpn,
				"certificates", []any{om("certificateFile", rev.Cert, "keyFile", rev.CertKey)})
		}
		ins = append(ins, om("tag", relayRevIn+"-ws", "listen", "0.0.0.0", "port", rev.PortW, "protocol", "vless",
			"settings", om("clients", cl(""), "decryption", "none"),
			"streamSettings", om("network", "ws", "security", "tls", "tlsSettings", tls("http/1.1"),
				"wsSettings", om("path", rev.Path))))
		ins = append(ins, om("tag", relayRevIn+"-xh", "listen", "0.0.0.0", "port", rev.PortX, "protocol", "vless",
			"settings", om("clients", cl(""), "decryption", "none"),
			"streamSettings", om("network", "xhttp", "security", "tls", "tlsSettings", tls("h2", "http/1.1"),
				"xhttpSettings", om("path", rev.Path+"x", "mode", "auto"))))
	}
	root.Set("inbounds", ins)
	root.Set("outbounds", append(asArr(root.Get("outbounds")), rev.Alts...))
	root.Set("routing", om("rules", []any{om("type", "field", "inboundTag", []any{relayCtlRev}, "outboundTag", relayRevOut)}))
}

// bridgeOutbound: this server dialing middle server s with way m.
func bridgeOutbound(s TunnelServer, r *revInfo, m string) *OMap {
	addr := orDefault(s.PublicIP, s.Host)
	user := func(port int, flow string) *OMap {
		return om("address", addr, "port", port, "id", r.UUID, "encryption", "none", "flow", flow,
			"reverse", om("tag", revInPrefix+s.ID))
	}
	o := om("tag", revOutPrefix+s.ID, "protocol", "vless")
	switch {
	case m == tunnelMethodWS && r.Domain != "":
		u := user(r.PortW, "")
		u.Set("address", r.Domain)
		o.Set("settings", u)
		o.Set("streamSettings", om("network", "ws", "security", "tls",
			"tlsSettings", om("serverName", r.Domain, "fingerprint", "chrome", "alpn", []any{"http/1.1"}),
			"wsSettings", om("path", r.Path, "host", r.Domain)))
	case m == tunnelMethodXHTTP && r.Domain != "":
		u := user(r.PortX, "")
		u.Set("address", r.Domain)
		o.Set("settings", u)
		o.Set("streamSettings", om("network", "xhttp", "security", "tls",
			"tlsSettings", om("serverName", r.Domain, "fingerprint", "chrome", "alpn", []any{"h2"}),
			"xhttpSettings", om("path", r.Path+"x", "host", r.Domain, "mode", "auto")))
	default:
		o.Set("settings", user(r.Port, "xtls-rprx-vision"))
		o.Set("streamSettings", om("network", "raw", "security", "reality",
			"realitySettings", om("serverName", r.SNI, "fingerprint", "chrome", "publicKey", s.RevPub, "shortId", r.SID)))
	}
	return o
}

// addBridges writes the bridges that are locked in (the path found was the
// reverse one). Returns the inbound tags reverse traffic arrives with, for
// every middle server that can be dialed, so a bridge added at run time
// (while searching) is covered by the tunnel rules too.
func (a *App) addBridges(root *OMap, servers []TunnelServer) []any {
	var keep []any
	for _, v := range asArr(root.Get("outbounds")) {
		if !strings.HasPrefix(asStr(asMap(v).Get("tag")), revOutPrefix) {
			keep = append(keep, v)
		}
	}
	var tags []any
	for _, s := range servers {
		r := a.revFor(s)
		if r == nil || orDefault(s.PublicIP, s.Host) == "" || s.RevPub == "" {
			continue
		}
		tags = append(tags, revInPrefix+s.ID)
		if s.Bridge {
			keep = append(keep, bridgeOutbound(s, r, s.BridgeVia))
		}
	}
	if keep == nil {
		keep = []any{}
	}
	root.Set("outbounds", keep)
	return tags
}

func dropBridges(root *OMap) {
	if asArr(root.Get("outbounds")) == nil {
		return
	}
	var keep []any
	for _, v := range asArr(root.Get("outbounds")) {
		if !strings.HasPrefix(asStr(asMap(v).Get("tag")), revOutPrefix) {
			keep = append(keep, v)
		}
	}
	if keep == nil {
		keep = []any{}
	}
	root.Set("outbounds", keep)
}

var revMu sync.Mutex

// setBridge locks a bridge in (written to config.json) or removes it.
func (a *App) setBridge(id string, on bool, via string) {
	changed := false
	_ = a.store.EditTunnels(func() error {
		if s := a.store.tunnelByID(id); s != nil && (s.Bridge != on || (on && s.BridgeVia != via)) {
			s.Bridge, changed = on, true
			if on {
				s.BridgeAt, s.BridgeVia = time.Now().Unix(), via
			}
		}
		return nil
	})
	if changed {
		a.reapplyTunnels(id)
	}
}

// reapplyTunnels rewrites the tunnel part of this server's config in the
// background (bridge locked in or removed, a listener port changed).
func (a *App) reapplyTunnels(id string) {
	go func() {
		revMu.Lock()
		defer revMu.Unlock()
		err := a.cfg.Mutate(func(root *OMap) error {
			if err := a.ensureTunnelSettings(root); err != nil {
				return err
			}
			return a.applyTunnelConfig(root)
		})
		msg := ""
		if err != nil {
			msg = trimTo(err.Error(), 300)
			log.Printf("tunnel bridge %s: %v", id, err)
		}
		_ = a.store.EditTunnels(func() error {
			if s := a.store.tunnelByID(id); s != nil {
				s.BridgeErr = msg
			}
			return nil
		})
	}()
}

// ---------- this server's search ----------

type revSearch struct {
	idx     int
	at      time.Time // current way started
	cool    time.Time // resting until
	live    string    // way dialing now (added at run time)
	written bool      // the API was not available: written to config.json
}

var (
	searchMu sync.Mutex
	searches = map[string]*revSearch{}
)

// apiOutbound adds (or with o == nil removes) a bridge at run time, without
// restarting xray.
func apiOutbound(tag string, o *OMap) error {
	core := DetectCore()
	if core.Bin == "" || core.APIAddr == "" {
		return errors.New("xray API not available")
	}
	if o == nil {
		_, err := run(10*time.Second, core.Bin, "api", "rmo", "--server="+core.APIAddr, tag)
		return err
	}
	f, err := os.CreateTemp("", "xo-bridge-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	f.Write(EncodeIndent(om("outbounds", []any{o})))
	f.Close()
	out, err := run(10*time.Second, core.Bin, "api", "ado", "--server="+core.APIAddr, f.Name())
	if err != nil {
		return fmt.Errorf("%v: %s", err, trimTo(out, 200))
	}
	return nil
}

// pathFound: a heartbeat arrived, so the two servers found each other. Stop
// searching; keep a bridge only when that heartbeat came over it.
func (a *App) pathFound(s TunnelServer, overRev bool) {
	searchMu.Lock()
	st := searches[s.ID]
	delete(searches, s.ID)
	searchMu.Unlock()
	if s.Search != "" {
		_ = a.store.EditTunnels(func() error {
			if t := a.store.tunnelByID(s.ID); t != nil {
				t.Search, t.SearchAt, t.SearchN = "", 0, ""
			}
			return nil
		})
	}
	if overRev && a.revFor(s) != nil {
		via := s.BridgeVia
		if st != nil && st.live != "" {
			via = st.live
		}
		if via == "" {
			via = tunnelMethodRT
		}
		a.setBridge(s.ID, true, via) // written to config.json, so it survives restarts
		return
	}
	if st != nil && st.live != "" && !st.written {
		_ = apiOutbound(revOutPrefix+s.ID, nil)
	}
	if s.Bridge {
		a.setBridge(s.ID, false, "")
	}
}

// revLoop: this server's side of the search, for every middle server that
// went quiet.
func (a *App) revLoop() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for range t.C {
		servers, _, _ := a.store.TunnelsCopy()
		for _, s := range servers {
			r := a.revFor(s)
			if r == nil || s.PublicIP == "" || s.LastSeen == 0 || s.RevPub == "" {
				continue
			}
			if time.Since(time.Unix(s.LastSeen, 0)) < revOffline {
				continue
			}
			a.searchStep(s, r)
		}
	}
}

func (a *App) searchStep(s TunnelServer, r *revInfo) {
	searchMu.Lock()
	st := searches[s.ID]
	if st == nil {
		st = &revSearch{at: time.Now()}
		searches[s.ID] = st
	}
	searchMu.Unlock()
	tag := revOutPrefix + s.ID
	// a locked-in path went quiet: unlock it and search again
	if s.Bridge && !st.written {
		a.setBridge(s.ID, false, "")
		return
	}
	ways := revWays(r)
	ui := func(state string, at int64, n string) {
		if s.Search == state && s.SearchAt == at && s.SearchN == n {
			return
		}
		_ = a.store.EditTunnels(func() error {
			if t := a.store.tunnelByID(s.ID); t != nil {
				t.Search, t.SearchAt, t.SearchN = state, at, n
			}
			return nil
		})
	}
	stop := func() {
		if st.live != "" {
			if st.written {
				a.setBridge(s.ID, false, "")
			} else {
				_ = apiOutbound(tag, nil)
			}
		}
		st.live, st.written = "", false
	}
	if time.Now().Before(st.cool) {
		stop()
		ui("cool", st.cool.Unix(), "")
		return
	}
	if st.live != "" && time.Since(st.at) > revTry {
		st.idx++
		st.at = time.Now()
		if st.idx >= len(ways) {
			st.idx = 0
			st.cool = time.Now().Add(revCool)
			stop()
			ui("cool", st.cool.Unix(), "")
			return
		}
	}
	if st.idx >= len(ways) {
		st.idx = 0
	}
	m := ways[st.idx]
	o := bridgeOutbound(s, r, m)
	if st.live != m {
		if st.live != "" && !st.written {
			_ = apiOutbound(tag, nil)
		}
		if err := apiOutbound(tag, o); err != nil {
			// no API: write it to config.json instead (restarts xray)
			st.written = true
			a.setBridge(s.ID, true, m)
		} else {
			st.written = false
		}
		st.live, st.at = m, time.Now()
	} else if !st.written {
		_ = apiOutbound(tag, o) // xray restarted meanwhile: add it again (an error just means it is there)
	}
	ui("search", 0, fmt.Sprintf("%s %d/%d", m, st.idx+1, len(ways)))
}

// ---------- domain + SSL on the middle server ----------

var hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// POST /api/tunnels/{id}/domain {domain}: the middle server gets a Let's
// Encrypt certificate for it; empty removes it.
func (a *App) handleTunnelDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(b.Domain)), ".")
	servers, _, _ := a.store.TunnelsCopy()
	var s *TunnelServer
	for i := range servers {
		if servers[i].ID == id {
			s = &servers[i]
		}
	}
	if s == nil {
		fail(w, 404, errors.New("middle server not found"))
		return
	}
	if d != "" {
		if !hostRe.MatchString(d) {
			fail(w, 400, errors.New("this does not look like a domain (example: mid.example.com)"))
			return
		}
		if d == strings.ToLower(a.store.Cfg.Domain) {
			fail(w, 400, errors.New("this is the main server's domain: use a separate one for the middle server"))
			return
		}
		if !revCapable(*s) {
			fail(w, 400, fmt.Errorf("update the middle server first (agent %s or newer): run the install command again there", agentRevVer))
			return
		}
		ips, err := net.LookupHost(d)
		if err != nil || len(ips) == 0 {
			fail(w, 400, fmt.Errorf("%s is not in DNS yet: add an A record to %s and try again in a few minutes", d, orDefault(s.PublicIP, "the middle server's IP")))
			return
		}
		if s.PublicIP != "" {
			ok := false
			for _, ip := range ips {
				if ip == s.PublicIP {
					ok = true
				}
			}
			if !ok {
				fail(w, 400, fmt.Errorf("%s points to %s, not to the middle server (%s). Fix the A record; with Cloudflare, turn the proxy off (gray cloud)", d, strings.Join(ips, ", "), s.PublicIP))
				return
			}
		}
	}
	_ = a.store.EditTunnels(func() error {
		if t := a.store.tunnelByID(id); t != nil && t.Domain != d {
			t.Domain, t.CertOK, t.CertExp, t.CertErr, t.CertBusy = d, false, 0, "", d != ""
		}
		return nil
	})
	hub.Poke(id)
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// ---------- relay config helpers (agent side) ----------

func relayHasRule(cfg []byte, tag string) bool {
	return strings.Contains(string(cfg), `"`+tag+`"`)
}

// stripRule removes a routing rule by its ruleTag.
func stripRule(cfg []byte, tag string) []byte {
	if !relayHasRule(cfg, tag) {
		return cfg
	}
	v, err := ParseOrdered(cfg)
	if err != nil {
		return cfg
	}
	root := asMap(v)
	rt := asMap(root.Get("routing"))
	if rt == nil {
		return cfg
	}
	var keep []any
	for _, x := range asArr(rt.Get("rules")) {
		if m := asMap(x); m != nil && asStr(m.Get("ruleTag")) == tag {
			continue
		}
		keep = append(keep, x)
	}
	if keep == nil {
		keep = []any{}
	}
	rt.Set("rules", keep)
	return EncodeIndent(root)
}
