package main

// Clients tab: a client is one name (Xray "email") that can sit on many
// inbounds, with one traffic/expiry limit and one subscription link.

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
)

type userView struct {
	ClientMeta
	Inbounds []string `json:"inbounds"`
}

type userInbound struct {
	ID       string `json:"id"`
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Network  string `json:"network"`
	Security string `json:"security"`
}

func (a *App) handleUsers(w http.ResponseWriter, r *http.Request) {
	root, _, err := a.cfg.Load()
	if err != nil {
		fail(w, 409, err)
		return
	}
	atag := apiTag(root)
	on := map[string][]string{}
	ibs := []userInbound{}
	for i, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		if ib == nil {
			continue
		}
		tag := asStr(ib.Get("tag"))
		if !supportsClients(ib) || tag == tunnelTag || (atag != "" && tag == atag) {
			continue
		}
		id := inboundID(ib, i)
		n, s := streamInfo(ib)
		ibs = append(ibs, userInbound{ID: id, Tag: tag, Protocol: asStr(ib.Get("protocol")), Port: asStr(ib.Get("port")), Network: n, Security: s})
		for _, cv := range clientsOf(ib) {
			if e := asStr(asMap(cv).Get("email")); e != "" && !isTunnelEmail(e) {
				on[e] = append(on[e], id)
			}
		}
	}
	for _, m := range a.store.All() {
		if m.Disabled && !isTunnelEmail(m.Email) {
			for id := range m.Saved {
				on[m.Email] = append(on[m.Email], id)
			}
		}
	}
	out := []userView{}
	for email, ids := range on {
		m := a.store.Meta(email)
		m.Saved = nil
		sort.Strings(ids)
		out = append(out, userView{ClientMeta: *m, Inbounds: ids})
	}
	for _, m := range a.store.All() { // clients with no inbound yet
		if _, ok := on[m.Email]; !ok && !isTunnelEmail(m.Email) {
			m.Saved = nil
			out = append(out, userView{ClientMeta: m, Inbounds: []string{}})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	writeJSONResp(w, 200, map[string]any{"clients": out, "inbounds": ibs})
}

type userReq struct {
	clientReq
	Inbounds []string `json:"inbounds"`
}

// setUserInbounds puts the client on exactly the given inbounds.
func (a *App) setUserInbounds(email string, want []string) error {
	if isTunnelEmail(email) {
		return errors.New("tunnel-* names belong to middle servers")
	}
	m := a.store.Meta(email)
	wantSet := map[string]bool{}
	for _, id := range want {
		wantSet[id] = true
	}
	saved := map[string]json.RawMessage{}
	dropSaved := map[string]bool{}
	err := a.cfg.Mutate(func(root *OMap) error {
		has := map[string]bool{}
		for i, v := range asArr(root.Get("inbounds")) {
			ib := asMap(v)
			if ib == nil {
				continue
			}
			id := inboundID(ib, i)
			if asStr(ib.Get("tag")) == tunnelTag {
				if wantSet[id] {
					return errors.New("the tunnel inbound is managed by XRay One")
				}
				has[id] = true
				continue
			}
			present := false
			for _, cv := range clientsOf(ib) {
				if asStr(asMap(cv).Get("email")) == email {
					present = true
				}
			}
			if _, ok := m.Saved[id]; ok && m.Disabled {
				present = true
			}
			has[id] = true
			switch {
			case present && !wantSet[id]:
				removeClient(ib, email)
				dropSaved[id] = true
			case !present && wantSet[id]:
				if !supportsClients(ib) || asStr(ib.Get("tag")) == tunnelTag {
					return errors.New("inbound " + id + " has no client list")
				}
				c, err := NewClient(ib, email)
				if err != nil {
					return err
				}
				if m.Disabled { // paused clients wait in panel state
					saved[id] = json.RawMessage(EncodeIndent(c))
				} else {
					setClients(ib, append(clientsOf(ib), c))
				}
			}
		}
		for id := range wantSet {
			if !has[id] {
				return errors.New("inbound not found: " + id)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	a.store.Update(email, func(x *ClientMeta) {
		if x.Saved == nil {
			x.Saved = map[string]json.RawMessage{}
		}
		for id := range dropSaved {
			delete(x.Saved, id)
		}
		for id, raw := range saved {
			x.Saved[id] = raw
		}
	})
	return nil
}

func (a *App) handleAddUser(w http.ResponseWriter, r *http.Request) {
	var req userReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, 400, err)
		return
	}
	if !reEmail.MatchString(req.Email) || isTunnelEmail(req.Email) {
		fail(w, 400, errors.New("name may use letters, digits and . _ @ + - only"))
		return
	}
	a.store.mu.Lock()
	_, exists := a.store.Clients[req.Email]
	a.store.mu.Unlock()
	if root, _, err := a.cfg.Load(); err == nil && (exists || emailInUse(root, req.Email)) {
		fail(w, 400, errors.New("a client with this name already exists"))
		return
	}
	a.store.Update(req.Email, func(m *ClientMeta) { applyLimits(m, req.clientReq, true) })
	if err := a.setUserInbounds(req.Email, req.Inbounds); err != nil {
		a.store.Forget(req.Email)
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// handleEditUser changes limits and/or the inbound list of a client.
func (a *App) handleEditUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		userReq
		SetInbounds bool `json:"setInbounds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, 400, err)
		return
	}
	if req.Email == "" {
		fail(w, 400, errors.New("missing name"))
		return
	}
	a.store.Update(req.Email, func(m *ClientMeta) { applyLimits(m, req.clientReq, false) })
	if req.SetInbounds {
		if err := a.setUserInbounds(req.Email, req.Inbounds); err != nil {
			fail(w, 400, err)
			return
		}
	}
	if req.Enable {
		if err := a.enableClient(req.Email); err != nil {
			fail(w, 400, err)
			return
		}
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleDelUser(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		fail(w, 400, errors.New("missing name"))
		return
	}
	if err := a.setUserInbounds(email, nil); err != nil {
		fail(w, 400, err)
		return
	}
	a.store.Forget(email)
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// handleDelInbounds removes several inbounds in one config change.
func (a *App) handleDelInbounds(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || len(b.IDs) == 0 {
		fail(w, 400, errors.New("nothing selected"))
		return
	}
	drop := map[string]bool{}
	for _, id := range b.IDs {
		drop[id] = true
	}
	removed := []string{}
	err := a.cfg.Mutate(func(root *OMap) error {
		atag := apiTag(root)
		var keep []any
		for i, v := range asArr(root.Get("inbounds")) {
			ib := asMap(v)
			if ib != nil && drop[inboundID(ib, i)] {
				tag := asStr(ib.Get("tag"))
				if (atag != "" && tag == atag) || tag == tunnelTag {
					keep = append(keep, v) // protected
					continue
				}
				removed = append(removed, inboundID(ib, i))
				continue
			}
			keep = append(keep, v)
		}
		if keep == nil {
			keep = []any{}
		}
		root.Set("inbounds", keep)
		if err := a.store.EditTunnels(func() error {
			for _, id := range removed {
				delete(a.store.TunnelUse, id)
			}
			return nil
		}); err != nil {
			return err
		}
		return a.applyTunnelConfig(root)
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	_ = a.store.EditRelays(func(m map[string][]Relay) {
		for _, id := range removed {
			delete(m, id)
		}
	})
	writeJSONResp(w, 200, map[string]any{"ok": true, "removed": len(removed)})
}

// isTunnelEmail: names XRay One gives middle servers on the tunnel inbound.
func isTunnelEmail(e string) bool { return strings.HasPrefix(e, "tunnel-") }
