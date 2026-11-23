package main

// Checking the tunnel's REALITY site from the middle servers too.
//
// The tunnel's REALITY site is used on this server (the middle server dials
// it with that name) and, on the reverse path, on the middle server (this
// server dials the middle server with that name). So a site that works from
// here can still be a bad pick there: the panel asks each connected middle
// server to probe it (over the heartbeat) and shows both answers.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const agentRCheckVer = "0.8.2"

type rcheckSpec struct {
	ID     string `json:"id"`
	Target string `json:"target"` // host:port
	SNI    string `json:"sni"`
}

type rcheckView struct {
	ID   string         `json:"id"`
	Busy bool           `json:"busy"`
	At   int64          `json:"at"`
	Res  *realityResult `json:"res,omitempty"`
}

type rcheckHub struct {
	mu   sync.Mutex
	want map[string]*rcheckSpec // middle server id -> check to hand out
	view map[string]*rcheckView // middle server id -> latest check
}

var rchecks = &rcheckHub{want: map[string]*rcheckSpec{}, view: map[string]*rcheckView{}}

// take hands a waiting check to its middle server (once).
func (h *rcheckHub) take(s TunnelServer) *rcheckSpec {
	h.mu.Lock()
	defer h.mu.Unlock()
	sp := h.want[s.ID]
	delete(h.want, s.ID)
	return sp
}

// POST /api/tunnels/rcheck {target}: probe the site from this server and ask
// every connected middle server to probe it too.
func (a *App) handleRCheck(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	t := strings.TrimSpace(b.Target)
	if t == "" {
		_, set, _ := a.store.TunnelsCopy()
		t = orDefault(set.RTarget, defaultRTarget)
	}
	host, port := splitTarget(t)
	if host == "" || port == 0 {
		fail(w, 400, errors.New("enter a site like www.example.com:443"))
		return
	}
	target := fmt.Sprintf("%s:%d", host, port)
	sp := &rcheckSpec{ID: randHex(6), Target: target, SNI: host}
	servers, _, _ := a.store.TunnelsCopy()
	now := time.Now()
	asked := []string{}
	rchecks.mu.Lock()
	for _, s := range servers {
		online := s.LastSeen > 0 && now.Sub(time.Unix(s.LastSeen, 0)) < onlineWindow
		if !online || versionLess(s.AgentVer, agentRCheckVer) {
			continue
		}
		rchecks.want[s.ID] = sp
		rchecks.view[s.ID] = &rcheckView{ID: sp.ID, Busy: true, At: now.Unix()}
		asked = append(asked, s.ID)
	}
	rchecks.mu.Unlock()
	for _, id := range asked {
		hub.Poke(id)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	here := probeReality(ctx, target, host)
	writeJSONResp(w, 200, map[string]any{"id": sp.ID, "target": target, "here": here, "asked": asked})
}

// GET /api/tunnels/rcheck?id=: what each middle server answered for check id.
func (a *App) handleRCheckView(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	servers, _, _ := a.store.TunnelsCopy()
	type row struct {
		ID   string         `json:"id"`
		Name string         `json:"name"`
		Busy bool           `json:"busy"`
		Old  bool           `json:"old"`
		Off  bool           `json:"off"`
		Res  *realityResult `json:"res,omitempty"`
	}
	out := []row{}
	now := time.Now()
	rchecks.mu.Lock()
	for _, s := range servers {
		x := row{ID: s.ID, Name: s.Name}
		x.Off = !(s.LastSeen > 0 && now.Sub(time.Unix(s.LastSeen, 0)) < onlineWindow)
		x.Old = versionLess(s.AgentVer, agentRCheckVer)
		if v := rchecks.view[s.ID]; v != nil && v.ID == id {
			x.Busy, x.Res = v.Busy, v.Res
			if x.Busy && now.Sub(time.Unix(v.At, 0)) > 40*time.Second {
				x.Busy, x.Res = false, &realityResult{Reason: "no answer from the middle server"}
			}
		}
		out = append(out, x)
	}
	rchecks.mu.Unlock()
	writeJSONResp(w, 200, map[string]any{"servers": out})
}

// POST /api/agent/rc/res {id, res}: a middle server's answer.
func (a *App) handleRCheckResult(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID  string        `json:"id"`
		Res realityResult `json:"res"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	id, tok := r.Header.Get("X-Agent-ID"), r.Header.Get("X-Agent-Token")
	servers, _, _ := a.store.TunnelsCopy()
	ok := false
	for _, s := range servers {
		if id != "" && tok != "" && s.ID == id && s.Token != "" && subtle.ConstantTimeCompare([]byte(s.Token), []byte(tok)) == 1 {
			ok = true
		}
	}
	if !ok {
		fail(w, 403, errors.New("unknown middle server"))
		return
	}
	b.Res.Reason, b.Res.Cert = trimTo(b.Res.Reason, 200), trimTo(b.Res.Cert, 200)
	rchecks.mu.Lock()
	if v := rchecks.view[id]; v != nil && v.ID == b.ID {
		v.Busy, v.Res = false, &b.Res
	}
	rchecks.mu.Unlock()
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// ---------- agent side ----------

var agentRChecking atomic.Bool

func agentStartRCheck(sp *rcheckSpec, st agentState) {
	if sp == nil || !agentRChecking.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer agentRChecking.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		res := probeReality(ctx, sp.Target, sp.SNI)
		cancel()
		fmt.Printf("REALITY site check %s: feasible=%v %s\n", sp.Target, res.Feasible, res.Reason)
		body, _ := json.Marshal(map[string]any{"id": sp.ID, "res": res})
		if !agentReport(st, "/api/agent/rc/res", body) {
			fmt.Println("REALITY site check: could not report the result")
		}
	}()
}

// agentReport posts to the panel through the tunnel (its control port).
func agentReport(st agentState, path string, body []byte) bool {
	ctl := st.Ctl
	if ctl == 0 {
		ctl = agentCtlPort
	}
	for _, port := range []int{ctl, ctl + 1} {
		pu, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
		c := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // inside the tunnel, to 127.0.0.1
		hr, _ := http.NewRequest("POST", strings.TrimSuffix(st.Join.Panel, "/")+path, bytes.NewReader(body))
		hr.Header.Set("Content-Type", "application/json")
		hr.Header.Set("X-Agent-ID", st.Join.ID)
		hr.Header.Set("X-Agent-Token", st.Token)
		resp, err := c.Do(hr)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return true
			}
		}
	}
	return false
}
