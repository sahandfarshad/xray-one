package main

// Two-way reconnect (VLESS Reverse Proxy) and a domain + SSL per middle server.
//
// Normally the middle server dials this server (forward path). Every middle
// server (agent 0.6.4+) also keeps a REALITY listener open (xo-rin). When the
// middle server has been unreachable for a while, this server starts dialing
// it (the "bridge") while the middle server, on its side, switches its traffic
// to that reverse path. Whichever path gets through first wins and the other
// side stops trying: the agent reports which path it uses, and the bridge is
// switched off again as soon as the forward path is back.
//
//   rev mode: user -> middle :P -> xo-rev (reverse outbound) ==> bridge
//             connection that this server opened -> xo-rin-<id> -> 127.0.0.1:P

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	agentRevVer  = "0.6.4"
	revOutPrefix = "xo-rout-" // outbound on this server that dials a middle server
	revInPrefix  = "xo-rin-"  // where traffic coming back over it enters routing here
	relayRevIn   = "xo-rin"   // REALITY listener on the middle server
	relayRevOut  = "xo-rev"   // virtual outbound on the middle server
	relayRevRule = "xo-rev-route"
	// this server starts dialing a middle server unseen for this long
	revOffline = 90 * time.Second
	// the agent switches from the forward to the reverse path after this
	// long without reaching us, and back after revDwell on the reverse path
	revAfter = 90 * time.Second
	revDwell = 4 * time.Minute
)

// ports tried for the listener on the middle server, first free one wins
var revPorts = []int{8443, 2096, 2087, 2083, 2053, 9443, 2443}

type revInfo struct {
	Port                   int
	UUID, Key, SNI, Target string
	SID                    string
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
	return &revInfo{Port: s.RevPort, UUID: s.RevUUID, Key: s.RevKey, SNI: host, Target: t, SID: s.RevSID}
}

// ensureRevLocked gives a middle server its reverse listener settings and a
// port that is free there. Call with the store locked.
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
	bad := map[int]bool{s.CtlPort: true, 80: true}
	for _, p := range s.Busy {
		bad[p] = true
	}
	for _, f := range fwd {
		bad[f.Listen] = true
	}
	if s.RevPort == 0 || bad[s.RevPort] {
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
		if p != 0 && p != s.RevPort {
			s.RevPort, changed = p, true
		}
	}
	return changed
}

// addRelayReverse adds the REALITY listener and the (agent-toggled) rule that
// sends everything over the reverse path to a relay config.
func addRelayReverse(root *OMap, rev *revInfo) {
	if rev == nil || rev.Port == 0 {
		return
	}
	var tags []any
	for _, v := range asArr(root.Get("inbounds")) {
		if t := asStr(asMap(v).Get("tag")); t != "" {
			tags = append(tags, t)
		}
	}
	root.Set("inbounds", append(asArr(root.Get("inbounds")), om("tag", relayRevIn, "listen", "0.0.0.0", "port", rev.Port, "protocol", "vless",
		"settings", om("clients", []any{om("id", rev.UUID, "flow", "xtls-rprx-vision", "reverse", om("tag", relayRevOut))}, "decryption", "none"),
		"streamSettings", om("network", "raw", "security", "reality",
			"realitySettings", om("show", false, "target", rev.Target, "xver", 0, "serverNames", []any{rev.SNI},
				"privateKey", rev.Key, "shortIds", []any{rev.SID})))))
	root.Set("routing", om("rules", []any{om("type", "field", "ruleTag", relayRevRule, "inboundTag", tags, "outboundTag", relayRevOut)}))
}

// addBridges makes this server dial every middle server whose bridge is on.
// Returns the inbound tags the reverse traffic arrives with.
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
		addr := orDefault(s.PublicIP, s.Host)
		if !s.Bridge || r == nil || addr == "" || s.RevPub == "" {
			continue
		}
		keep = append(keep, om("tag", revOutPrefix+s.ID, "protocol", "vless",
			"settings", om("address", addr, "port", r.Port, "id", r.UUID, "encryption", "none", "flow", "xtls-rprx-vision",
				"reverse", om("tag", revInPrefix+s.ID)),
			"streamSettings", om("network", "raw", "security", "reality",
				"realitySettings", om("serverName", r.SNI, "fingerprint", "chrome", "publicKey", s.RevPub, "shortId", r.SID))))
		tags = append(tags, revInPrefix+s.ID)
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

// setBridge turns dialing one middle server on or off and applies it.
func (a *App) setBridge(id string, on bool) {
	changed := false
	_ = a.store.EditTunnels(func() error {
		if s := a.store.tunnelByID(id); s != nil && s.Bridge != on {
			s.Bridge, changed = on, true
			if on {
				s.BridgeAt = time.Now().Unix()
			}
		}
		return nil
	})
	if !changed {
		return
	}
	a.reapplyTunnels(id)
}

// reapplyTunnels rewrites the tunnel part of this server's config in the
// background (bridges on/off, a middle server's listener port changed).
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

// revLoop starts dialing middle servers that went quiet.
func (a *App) revLoop() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for range t.C {
		servers, _, _ := a.store.TunnelsCopy()
		for _, s := range servers {
			if s.Bridge || s.LastSeen == 0 || a.revFor(s) == nil || s.PublicIP == "" {
				continue
			}
			if time.Since(time.Unix(s.LastSeen, 0)) > revOffline {
				a.setBridge(s.ID, true)
			}
		}
	}
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
