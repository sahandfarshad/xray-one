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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sniOut = "xo-sni-out"

// agentSniVer: the first agent that runs the entry.
const agentSniVer = "0.12.0"

// agentSniLogVer: the first agent that reports its active addresses and the
// names they asked for.
const agentSniLogVer = "0.13.0"

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
	c.Revoke = map[string]int64{}
	for k, v := range s.Sni.Revoke {
		c.Revoke[k] = v
	}
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
	sniApp = a
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
	sniSvc.Update(&sniSpec{Domains: set.Domains, Keys: a.sniKeys(), IP: ip, Hours: set.Hours, Avoid: avoid, Revoke: set.Revoke})
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
	return &sniSpec{Domains: set.Domains, Keys: a.sniKeys(), IP: s.PublicIP, Hours: set.Hours, Revoke: set.Revoke}
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
		a.store.Sni.Domains, a.store.Sni.Main, a.store.Sni.Hours = doms, b.Main, b.Hours
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

// ---------- what the entries report ----------

type sniRemote struct {
	List []sniActive
	Seen []sniSeen
	At   int64
}

var (
	sniRemMu sync.Mutex
	sniRem   = map[string]sniRemote{} // middle server id -> its last report
)

func sniRemoteSet(id string, list []sniActive, seen []sniSeen) {
	if len(list) > 500 {
		list = list[:500]
	}
	if len(seen) > sniSeenReport {
		seen = seen[:sniSeenReport]
	}
	for i := range seen {
		seen[i].Name, seen[i].IP = trimTo(seen[i].Name, 253), trimTo(seen[i].IP, 64)
	}
	sniRemMu.Lock()
	defer sniRemMu.Unlock()
	if list == nil && seen == nil {
		delete(sniRem, id)
		return
	}
	sniRem[id] = sniRemote{List: list, Seen: seen, At: time.Now().Unix()}
}

// sniUserNames: activation key -> user name.
func (a *App) sniUserNames() map[string]string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	out := map[string]string{}
	for _, m := range a.store.Clients {
		if m.SubToken != "" {
			out[sniKey(m.SubToken)] = m.Email
		}
	}
	return out
}

type sniActiveView struct {
	IP     string `json:"ip"`
	User   string `json:"user"`
	Until  int64  `json:"until"`
	Since  int64  `json:"since,omitempty"`
	Entry  string `json:"entry"`
	EntryI string `json:"entryId,omitempty"`
}

type sniSeenView struct {
	sniSeen
	Entry string `json:"entry"`
	User  string `json:"user,omitempty"`
}

// GET /api/sni: settings, entries, active addresses and the names asked.
func (a *App) handleSniGet(w http.ResponseWriter, r *http.Request) {
	set := a.store.sniCopy()
	names := a.sniUserNames()
	var act []sniActiveView
	var seen []sniSeenView
	ipUser := map[string]string{}
	add := func(entry, id string, list []sniActive, ss []sniSeen) {
		for _, x := range list {
			u := names[x.Key]
			ipUser[x.IP] = u
			act = append(act, sniActiveView{IP: x.IP, User: u, Until: x.Until, Since: x.Since, Entry: entry, EntryI: id})
		}
		for _, x := range ss {
			seen = append(seen, sniSeenView{sniSeen: x, Entry: entry})
		}
	}
	mainErr, mainList, mainSeen := sniSvc.Report()
	if sniMainErr != "" {
		mainErr = sniMainErr
	}
	mainIP := ""
	if set.Main {
		mainIP = a.sniMainIP()
		add("main", "", mainList, mainSeen)
	}
	var entries []map[string]any
	servers, _, _ := a.store.TunnelsCopy()
	sniRemMu.Lock()
	for _, s := range servers {
		e := map[string]any{"id": s.ID, "name": s.Name, "ip": s.PublicIP, "on": s.SniOn, "err": s.SniErr, "n": s.SniN,
			"agentVer": s.AgentVer, "online": s.LastSeen > time.Now().Unix()-int64(onlineWindow/time.Second)}
		entries = append(entries, e)
		if s.SniOn {
			if rr, ok := sniRem[s.ID]; ok {
				add(s.Name, s.ID, rr.List, rr.Seen)
			}
		}
	}
	sniRemMu.Unlock()
	for i := range seen {
		seen[i].User = ipUser[seen[i].IP]
	}
	sort.SliceStable(seen, func(i, j int) bool { return seen[i].Last > seen[j].Last })
	if len(seen) > 300 {
		seen = seen[:300]
	}
	writeJSONResp(w, 200, map[string]any{"domains": set.Domains, "main": set.Main, "hours": set.Hours,
		"mainErr": mainErr, "mainIP": mainIP, "mainN": len(mainList), "servers": entries,
		"active": act, "seen": seen, "sniVer": agentSniVer, "sniLogVer": agentSniLogVer, "now": time.Now().Unix()})
}

// POST /api/sni/revoke {ip}: end an address's activation on every entry.
func (a *App) handleSniRevoke(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || net.ParseIP(b.IP) == nil {
		fail(w, 400, errors.New("bad address"))
		return
	}
	now := time.Now().Unix()
	if err := a.store.EditTunnels(func() error {
		if a.store.Sni.Revoke == nil {
			a.store.Sni.Revoke = map[string]int64{}
		}
		for k, v := range a.store.Sni.Revoke {
			if v < now-31*86400 {
				delete(a.store.Sni.Revoke, k)
			}
		}
		a.store.Sni.Revoke[b.IP] = now
		return nil
	}); err != nil {
		fail(w, 500, err)
		return
	}
	pokeSni()
	a.pokeSniServers()
	time.Sleep(300 * time.Millisecond)
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// POST /api/sni/domains {add}: add names to the list.
func (a *App) handleSniAdd(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Add []string `json:"add"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	old := a.store.sniCopy()
	doms := sniNormDomains(append(append([]string{}, old.Domains...), b.Add...))
	if len(doms) > 2000 {
		fail(w, 400, errors.New("too many domains (2000 at most)"))
		return
	}
	if err := a.store.EditTunnels(func() error {
		a.store.Sni.Domains = doms
		return nil
	}); err != nil {
		fail(w, 500, err)
		return
	}
	servers, _, _ := a.store.TunnelsCopy()
	if a.sniTunnelDomains(servers) != nil {
		if err := a.sniReapply(); err != nil {
			fail(w, 500, err)
			return
		}
	}
	a.pokeSniServers()
	pokeSni()
	time.Sleep(300 * time.Millisecond)
	writeJSONResp(w, 200, map[string]any{"ok": true, "domains": doms})
}

// sniCountUse adds unblocker bytes (per activation key) to the subscription
// they belong to, so every address activated with one subscription uses up
// that subscription's data.
func sniCountUse(use map[string][2]int64) {
	if len(use) == 0 || sniApp == nil {
		return
	}
	byKey := map[string]string{}
	for _, m := range sniApp.store.All() {
		if m.SubToken != "" {
			byKey[sniKey(m.SubToken)] = m.Email
		}
	}
	for k, v := range use {
		if email, ok := byKey[k]; ok && v[0]+v[1] > 0 {
			sniApp.store.Update(email, func(m *ClientMeta) { m.Up += v[0]; m.Down += v[1] })
		}
	}
}

var sniApp *App
