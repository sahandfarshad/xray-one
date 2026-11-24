package main

// Panel side of the anti-sanction entry (sni.go): settings, the entry on the
// main server, what each middle server runs, and the tunnel rule that lets
// listed domains out of the main server.

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sniOut = "xo-sni-out"

// agentSniVer: the first agent that runs the entry.
const agentSniVer = "0.12.0"

var sniPoke = make(chan struct{}, 1)

func pokeSni() {
	select {
	case sniPoke <- struct{}{}:
	default:
	}
}

func (s *Store) sniCopy() SniSettings {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.Sni
	c.Domains = append([]string{}, s.Sni.Domains...)
	if c.Hours <= 0 {
		c.Hours = sniDefaultHours
	}
	return c
}

// sniKeys: activation keys of every active user.
func (a *App) sniKeys() []string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	var out []string
	for _, m := range a.store.Clients {
		if !m.Disabled && m.SubToken != "" {
			out = append(out, sniKey(m.SubToken))
		}
	}
	return out
}

var (
	sniIPMu sync.Mutex
	sniIP   string
)

// sniMainIP: the address the DNS answers on the main server.
func (a *App) sniMainIP() string {
	_, set, _ := a.store.TunnelsCopy()
	if ip := net.ParseIP(set.WGHost); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	if ip := net.ParseIP(a.store.Cfg.PublicHost); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	sniIPMu.Lock()
	defer sniIPMu.Unlock()
	if sniIP == "" {
		if ip := net.ParseIP(publicIP()); ip != nil && ip.To4() != nil {
			sniIP = ip.String()
		}
	}
	return sniIP
}

var sniMainErr string

// sniLoop runs the entry on the main server while it is switched on.
func (a *App) sniLoop() {
	sniSvc = newSniService(filepath.Join(a.store.dir, "sni-allow.json"), func(h string, p int) (net.Conn, error) {
		return net.DialTimeout("tcp", net.JoinHostPort(h, strconv.Itoa(p)), 10*time.Second)
	})
	for {
		a.sniApplyMain()
		select {
		case <-sniPoke:
		case <-time.After(30 * time.Second):
		}
	}
}

func (a *App) sniApplyMain() {
	set := a.store.sniCopy()
	if !set.Main || len(set.Domains) == 0 {
		sniMainErr = ""
		sniSvc.Update(nil)
		return
	}
	ip := a.sniMainIP()
	if ip == "" {
		sniMainErr = "could not find this server's public IPv4"
		sniSvc.Update(nil)
		return
	}
	sniMainErr = ""
	var avoid []int
	if root, _, err := a.cfg.Load(); err == nil {
		used := usedPorts(root)
		for _, p := range []int{53, 80, 443} {
			if used[strconv.Itoa(p)] {
				avoid = append(avoid, p)
			}
		}
	}
	if p, err := strconv.Atoi(strings.TrimPrefix(portOf(a.store.Cfg.Listen), ":")); err == nil && (p == 80 || p == 443) {
		avoid = append(avoid, p)
	}
	sniSvc.Update(&sniSpec{Domains: set.Domains, Keys: a.sniKeys(), IP: ip, Hours: set.Hours, Avoid: avoid})
}

// sniSpecFor: what a middle server runs (nil: nothing).
func (a *App) sniSpecFor(s TunnelServer) *sniSpec {
	if !s.SniOn || s.PublicIP == "" {
		return nil
	}
	set := a.store.sniCopy()
	if len(set.Domains) == 0 {
		return nil
	}
	return &sniSpec{Domains: set.Domains, Keys: a.sniKeys(), IP: s.PublicIP, Hours: set.Hours}
}

// sniTunnelDomains: the domains the tunnels may carry out of this server
// (only when a middle server is an entry).
func (a *App) sniTunnelDomains(servers []TunnelServer) []string {
	on := false
	for _, s := range servers {
		on = on || s.SniOn
	}
	if !on {
		return nil
	}
	return a.store.sniCopy().Domains
}

// sniRule: listed domains on 80/443 that come in through a tunnel go to the
// internet; everything else keeps the tunnel's own rules.
func sniRule(in []any, doms []string) *OMap {
	var d []any
	for _, x := range doms {
		d = append(d, "domain:"+x)
	}
	return om("type", "field", "ruleTag", "xo-tunnel-sni", "inboundTag", in, "domain", d, "port", "80,443", "outboundTag", sniOut)
}

func setSniOutbound(root *OMap, on bool) {
	var obs []any
	have := false
	for _, v := range asArr(root.Get("outbounds")) {
		if asStr(asMap(v).Get("tag")) == sniOut {
			if !on {
				continue
			}
			have = true
		}
		obs = append(obs, v)
	}
	if on && !have {
		obs = append(obs, om("protocol", "freedom", "tag", sniOut))
	}
	if obs == nil {
		obs = []any{}
	}
	root.Set("outbounds", obs)
}

// sniEntries: where a user activates and what DNS address they set.
type sniEntry struct{ Name, IP string }

func (a *App) sniEntries() []sniEntry {
	set := a.store.sniCopy()
	if len(set.Domains) == 0 {
		return nil
	}
	var out []sniEntry
	if set.Main {
		if ip := a.sniMainIP(); ip != "" {
			out = append(out, sniEntry{Name: "main", IP: ip})
		}
	}
	servers, _, _ := a.store.TunnelsCopy()
	for _, s := range servers {
		if s.SniOn && !s.Pending && s.PublicIP != "" {
			out = append(out, sniEntry{Name: s.Name, IP: s.PublicIP})
		}
	}
	return out
}

func (a *App) sniReapply() error {
	servers, _, _ := a.store.TunnelsCopy()
	if len(servers) == 0 {
		return nil
	}
	revMu.Lock()
	defer revMu.Unlock()
	return a.cfg.Mutate(func(root *OMap) error {
		if err := a.ensureTunnelSettings(root); err != nil {
			return err
		}
		return a.applyTunnelConfig(root)
	})
}

// POST /api/sni {domains, main, hours}
func (a *App) handleSniSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Domains string `json:"domains"`
		Main    bool   `json:"main"`
		Hours   int    `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	if b.Hours < 1 || b.Hours > 720 {
		b.Hours = sniDefaultHours
	}
	doms := sniNormDomains(strings.FieldsFunc(b.Domains, func(c rune) bool { return c == '\n' || c == ',' || c == ' ' || c == '\r' || c == '\t' }))
	if len(doms) > 2000 {
		fail(w, 400, errors.New("too many domains (2000 at most)"))
		return
	}
	old := a.store.sniCopy()
	if err := a.store.EditTunnels(func() error {
		a.store.Sni = SniSettings{Domains: doms, Main: b.Main, Hours: b.Hours}
		return nil
	}); err != nil {
		fail(w, 500, err)
		return
	}
	if strings.Join(old.Domains, ",") != strings.Join(doms, ",") {
		servers, _, _ := a.store.TunnelsCopy()
		if a.sniTunnelDomains(servers) != nil || old.Domains != nil {
			if err := a.sniReapply(); err != nil {
				fail(w, 500, err)
				return
			}
		}
	}
	a.pokeSniServers()
	pokeSni()
	time.Sleep(300 * time.Millisecond)
	writeJSONResp(w, 200, map[string]any{"ok": true, "domains": doms})
}

func (a *App) pokeSniServers() {
	servers, _, _ := a.store.TunnelsCopy()
	var ids []string
	for _, s := range servers {
		ids = append(ids, s.ID)
	}
	hub.PokeAll(ids)
}

// POST /api/tunnels/{id}/sni {on}
func (a *App) handleTunnelSni(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		On bool `json:"on"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	err := a.store.EditTunnels(func() error {
		s := a.store.tunnelByID(id)
		if s == nil {
			return errors.New("middle server not found")
		}
		s.SniOn = b.On
		if !b.On {
			s.SniErr, s.SniN = "", 0
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	if err := a.sniReapply(); err != nil {
		fail(w, 500, err)
		return
	}
	hub.Poke(id)
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) sniView() map[string]any {
	set := a.store.sniCopy()
	e, n := sniSvc.Status()
	if sniMainErr != "" {
		e = sniMainErr
	}
	ip := ""
	if set.Main {
		ip = a.sniMainIP()
	}
	return map[string]any{"domains": set.Domains, "main": set.Main, "hours": set.Hours, "mainErr": e, "mainN": n, "mainIP": ip}
}
