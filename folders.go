package main

// Folders: inbounds and clients can be grouped into folders so a long list
// stays tidy (folders open and close in the panel). A client may follow a
// whole inbound folder: it is put on every inbound of that folder, also on
// inbounds that join the folder later.

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
)

type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Store) folderList(kind string) *[]Folder {
	if kind == "cl" {
		return &s.ClFolders
	}
	return &s.InFolders
}

// FolderView: both folder lists and where each inbound sits.
func (s *Store) FolderView() (in, cl []Folder, of map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	of = map[string]string{}
	for k, v := range s.InFolderOf {
		of[k] = v
	}
	return append([]Folder{}, s.InFolders...), append([]Folder{}, s.ClFolders...), of
}

func (s *Store) inboundFolder(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.InFolderOf[id]
}

func folderExists(list []Folder, id string) bool {
	for _, f := range list {
		if f.ID == id {
			return true
		}
	}
	return false
}

func cleanFolderName(n string) (string, error) {
	n = strings.TrimSpace(n)
	if n == "" || len([]rune(n)) > 40 {
		return "", errors.New("folder name: 1 to 40 characters")
	}
	return n, nil
}

func (a *App) handleFolderAdd(w http.ResponseWriter, r *http.Request) {
	var b struct{ Kind, Name string }
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	name, err := cleanFolderName(b.Name)
	if err != nil {
		fail(w, 400, err)
		return
	}
	f := Folder{ID: randHex(6), Name: name}
	s := a.store
	s.mu.Lock()
	l := s.folderList(b.Kind)
	*l = append(*l, f)
	err = s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSONResp(w, 200, f)
}

func (a *App) handleFolderRename(w http.ResponseWriter, r *http.Request) {
	var b struct{ Kind, ID, Name string }
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	name, err := cleanFolderName(b.Name)
	if err != nil {
		fail(w, 400, err)
		return
	}
	s := a.store
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.folderList(b.Kind)
	for i := range *l {
		if (*l)[i].ID == b.ID {
			(*l)[i].Name = name
			_ = s.saveLocked()
			writeJSONResp(w, 200, map[string]bool{"ok": true})
			return
		}
	}
	fail(w, 404, errors.New("folder not found"))
}

// handleFolderDel removes a folder; what was in it stays, without a folder.
// Clients that followed an inbound folder keep the inbounds they have.
func (a *App) handleFolderDel(w http.ResponseWriter, r *http.Request) {
	var b struct{ Kind, ID string }
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	s := a.store
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.folderList(b.Kind)
	keep := (*l)[:0]
	for _, f := range *l {
		if f.ID != b.ID {
			keep = append(keep, f)
		}
	}
	*l = keep
	if b.Kind == "cl" {
		for _, m := range s.Clients {
			if m.Folder == b.ID {
				m.Folder = ""
			}
		}
	} else {
		for k, v := range s.InFolderOf {
			if v == b.ID {
				delete(s.InFolderOf, k)
			}
		}
		for _, m := range s.Clients {
			m.Follow = dropStr(m.Follow, b.ID)
		}
	}
	_ = s.saveLocked()
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func dropStr(l []string, x string) []string {
	var out []string
	for _, v := range l {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

// handleFolderMove puts inbounds or clients into a folder ("" = none).
func (a *App) handleFolderMove(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Kind   string   `json:"kind"`
		Folder string   `json:"folder"`
		IDs    []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	if err := a.moveToFolder(b.Kind, b.Folder, b.IDs); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) moveToFolder(kind, folder string, ids []string) error {
	s := a.store
	s.mu.Lock()
	if folder != "" && !folderExists(*s.folderList(kind), folder) {
		s.mu.Unlock()
		return errors.New("folder not found")
	}
	for _, id := range ids {
		if kind == "cl" {
			if m := s.Clients[id]; m != nil {
				m.Folder = folder
			}
			continue
		}
		if s.InFolderOf == nil {
			s.InFolderOf = map[string]string{}
		}
		if folder == "" {
			delete(s.InFolderOf, id)
		} else {
			s.InFolderOf[id] = folder
		}
	}
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil || kind == "cl" || folder == "" {
		return err
	}
	return a.syncFollowers(folder)
}

// folderInbounds: the inbounds now in the given folders.
func (a *App) folderInbounds(folders []string) []string {
	if len(folders) == 0 {
		return nil
	}
	want := map[string]bool{}
	for _, f := range folders {
		want[f] = true
	}
	root, _, err := a.cfg.Load()
	if err != nil {
		return nil
	}
	_, _, of := a.store.FolderView()
	var out []string
	for i, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		if ib == nil {
			continue
		}
		id := inboundID(ib, i)
		if want[of[id]] && supportsClients(ib) && !isTunnelTag(asStr(ib.Get("tag"))) {
			out = append(out, id)
		}
	}
	return out
}

// userInboundIDs: the inbounds a client is on now (paused ones included).
func (a *App) userInboundIDs(email string) []string {
	root, _, err := a.cfg.Load()
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for i, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		if ib == nil || isTunnelTag(asStr(ib.Get("tag"))) {
			continue
		}
		for _, cv := range clientsOf(ib) {
			if asStr(asMap(cv).Get("email")) == email {
				set[inboundID(ib, i)] = true
			}
		}
	}
	m := a.store.Meta(email)
	if m.Disabled {
		for id := range m.Saved {
			set[id] = true
		}
	}
	out := []string{}
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func unionStr(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range [][]string{a, b} {
		for _, v := range l {
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// syncFollowers adds the folder's inbounds to every client following it.
func (a *App) syncFollowers(folder string) error {
	members := a.folderInbounds([]string{folder})
	if len(members) == 0 {
		return nil
	}
	var errs []string
	for _, m := range a.store.All() {
		follows := false
		for _, f := range m.Follow {
			follows = follows || f == folder
		}
		if !follows || isTunnelEmail(m.Email) {
			continue
		}
		cur := a.userInboundIDs(m.Email)
		want := unionStr(cur, members)
		if len(want) == len(cur) {
			continue
		}
		if err := a.setUserInbounds(m.Email, want); err != nil {
			errs = append(errs, m.Email+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
