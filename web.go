package main

import (
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

//go:embed web
var webFS embed.FS

type App struct {
	store   *Store
	cfg     *ConfigStore
	job     *Job
	sessMu  sync.Mutex
	sess    map[string]time.Time
	fails   map[string][]time.Time
	tls     bool
	traffic *trafficLog
}

func NewApp(dir string) (*App, error) {
	st, err := OpenStore(dir)
	if err != nil {
		return nil, err
	}
	return &App{store: st, traffic: openTrafficLog(dir), cfg: &ConfigStore{backupDir: filepath.Join(dir, "backups")}, job: &Job{},
		sess: map[string]time.Time{}, fails: map[string][]time.Time{}}, nil
}

// ---------- helpers ----------

func writeJSONResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSONResp(w, code, map[string]string{"error": err.Error()})
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// ---------- auth ----------

const cookieName = "xo_session"

func (a *App) authed(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	exp, ok := a.sess[c.Value]
	if !ok || time.Now().After(exp) {
		delete(a.sess, c.Value)
		return false
	}
	a.sess[c.Value] = time.Now().Add(12 * time.Hour)
	return true
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	a.sessMu.Lock()
	recent := []time.Time{}
	for _, t := range a.fails[ip] {
		if time.Since(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	a.fails[ip] = recent
	a.sessMu.Unlock()
	if len(recent) >= 5 {
		fail(w, 429, errors.New("too many attempts, try again in 10 minutes"))
		return
	}
	var body struct{ User, Pass string }
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	cfg := a.store.Cfg
	okUser := subtle.ConstantTimeCompare([]byte(body.User), []byte(cfg.User)) == 1
	okPass := bcrypt.CompareHashAndPassword([]byte(cfg.PassHash), []byte(body.Pass)) == nil
	if cfg.User == "" || cfg.PassHash == "" || !okUser || !okPass {
		a.sessMu.Lock()
		a.fails[ip] = append(a.fails[ip], time.Now())
		a.sessMu.Unlock()
		time.Sleep(600 * time.Millisecond)
		fail(w, 401, errors.New("wrong username or password"))
		return
	}
	tok := randHex(32)
	a.sessMu.Lock()
	a.sess[tok] = time.Now().Add(12 * time.Hour)
	a.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: a.store.Cfg.BasePath, HttpOnly: true,
		Secure: a.tls, SameSite: http.SameSiteStrictMode, MaxAge: 7 * 24 * 3600})
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.sessMu.Lock()
		delete(a.sess, c.Value)
		a.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: a.store.Cfg.BasePath, MaxAge: -1})
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// api wraps a handler with auth and a CSRF header check on writes.
func (a *App) api(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) {
			fail(w, 401, errors.New("login required"))
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-XO") != "1" {
			fail(w, 403, errors.New("bad request origin"))
			return
		}
		h(w, r)
	}
}

// ---------- routes ----------

func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webFS, "web")
	files := http.FileServer(http.FS(static))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// the files are built into the binary with no date: never let a
		// browser keep an old app.js after an update
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	}))
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", a.handleLogout)
	mux.HandleFunc("GET /api/status", a.api(a.handleStatus))
	mux.HandleFunc("GET /api/inbounds", a.api(a.handleInbounds))
	mux.HandleFunc("POST /api/inbounds", a.api(a.handleAddInbound))
	mux.HandleFunc("DELETE /api/inbounds", a.api(a.handleDelInbound))
	mux.HandleFunc("POST /api/inbounds/delete", a.api(a.handleDelInbounds))
	mux.HandleFunc("GET /api/inbounds/detail", a.api(a.handleInboundDetail))
	mux.HandleFunc("POST /api/inbounds/edit", a.api(a.handleEditInbound))
	mux.HandleFunc("GET /api/users", a.api(a.handleUsers))
	mux.HandleFunc("POST /api/users", a.api(a.handleAddUser))
	mux.HandleFunc("POST /api/users/edit", a.api(a.handleEditUser))
	mux.HandleFunc("DELETE /api/users", a.api(a.handleDelUser))
	mux.HandleFunc("POST /api/clients", a.api(a.handleAddClient))
	mux.HandleFunc("DELETE /api/clients", a.api(a.handleDelClient))
	mux.HandleFunc("POST /api/clients/update", a.api(a.handleUpdateClient))
	mux.HandleFunc("GET /api/qr", a.api(a.handleQR))
	mux.HandleFunc("GET /api/wg", a.api(a.handleWG))
	mux.HandleFunc("POST /api/core/install", a.api(a.handleInstall))
	mux.HandleFunc("GET /api/core/job", a.api(func(w http.ResponseWriter, r *http.Request) { writeJSONResp(w, 200, a.job.Snapshot()) }))
	mux.HandleFunc("POST /api/core/restart", a.api(a.handleRestart))
	mux.HandleFunc("POST /api/core/enable-api", a.api(a.handleEnableAPI))
	mux.HandleFunc("GET /api/config", a.api(a.handleRawConfig))
	mux.HandleFunc("GET /api/xray/latest", a.api(a.handleXrayLatest))
	mux.HandleFunc("POST /api/xray/update", a.api(a.handleXrayUpdate))
	mux.HandleFunc("GET /api/backups", a.api(func(w http.ResponseWriter, r *http.Request) { writeJSONResp(w, 200, a.cfg.Backups()) }))
	mux.HandleFunc("POST /api/backups/restore", a.api(a.handleRestore))
	mux.HandleFunc("POST /api/settings", a.api(a.handleSettings))
	mux.HandleFunc("GET /api/freeport", a.api(func(w http.ResponseWriter, r *http.Request) {
		writeJSONResp(w, 200, map[string]int{"port": suggestPort()})
	}))
	mux.HandleFunc("GET /api/certs", a.api(func(w http.ResponseWriter, r *http.Request) { writeJSONResp(w, 200, FindCerts(a.store.dir)) }))
	mux.HandleFunc("GET /api/presets", a.api(a.handlePresets))
	mux.HandleFunc("POST /api/presets", a.api(a.handleCreatePresets))
	mux.HandleFunc("POST /api/relays", a.api(a.handleAddRelay))
	mux.HandleFunc("DELETE /api/relays", a.api(a.handleDelRelay))
	mux.HandleFunc("POST /api/allsub/reset", a.api(func(w http.ResponseWriter, r *http.Request) {
		writeJSONResp(w, 200, map[string]string{"allToken": a.store.ResetAllToken()})
	}))
	mux.HandleFunc("GET /api/tunnels", a.api(a.handleTunnels))
	mux.HandleFunc("POST /api/tunnels", a.api(a.handleAddTunnel))
	mux.HandleFunc("DELETE /api/tunnels/{id}", a.api(a.handleDelTunnel))
	mux.HandleFunc("POST /api/tunnels/{id}/deploy", a.api(a.handleDeployTunnel))
	mux.HandleFunc("POST /api/tunnels/{id}/join", a.api(a.handleNewJoin))
	mux.HandleFunc("POST /api/tunnels/{id}/test", a.api(a.handleTestTunnel))
	mux.HandleFunc("POST /api/tunnels/{id}/method", a.api(a.handleTunnelMethod))
	mux.HandleFunc("POST /api/tunnels/{id}/domain", a.api(a.handleTunnelDomain))
	mux.HandleFunc("POST /api/tunnels/settings", a.api(a.handleTunnelSettings))
	mux.HandleFunc("POST /api/tunnels/rcheck", a.api(a.handleRCheck))
	mux.HandleFunc("POST /api/tunnels/csettings", a.api(a.handleCarrierSettings))
	mux.HandleFunc("GET /api/tunnels/rcheck", a.api(a.handleRCheckView))
	mux.HandleFunc("POST /api/tunnels/assign", a.api(a.handleTunnelAssign))
	mux.HandleFunc("POST /api/tunnels/bulk", a.api(a.handleTunnelBulk))
	mux.HandleFunc("POST /api/tunnels/{id}/pool", a.api(a.handleTunnelPool))
	mux.HandleFunc("POST /api/tunnels/{id}/revports", a.api(a.handleRevPorts))
	mux.HandleFunc("POST /api/tunnels/dtsettings", a.api(a.handleDedSettings))
	mux.HandleFunc("POST /api/reality/scan", a.api(a.handleRealityScan))
	mux.HandleFunc("GET /api/reality/keys", a.api(a.handleRealityKeys))
	mux.HandleFunc("GET /api/vless/enc", a.api(a.handleVlessEnc))
	mux.HandleFunc("GET /api/live", a.api(a.handleLive))
	mux.HandleFunc("GET /api/traffic/daily", a.api(a.handleTrafficDaily))
	mux.HandleFunc("POST /api/agent/beat", a.handleBeat)
	mux.HandleFunc("POST /api/tunnels/{id}/speed", a.api(a.handleSpeedTest))
	mux.HandleFunc("GET /api/agent/t/ping", a.handleTestPing)
	mux.HandleFunc("GET /api/agent/t/dl", a.handleTestDown)
	mux.HandleFunc("POST /api/agent/t/ul", a.handleTestUp)
	mux.HandleFunc("POST /api/agent/t/res", a.handleTestResult)
	mux.HandleFunc("POST /api/agent/rc/res", a.handleRCheckResult)
	mux.HandleFunc("GET /api/agent/bin/{name}", a.handleAgentBin)
	mux.HandleFunc("GET /api/agent/probe", a.handleAgentProbe)
	mux.HandleFunc("GET /sub/{token}", a.handleSub)
	mux.HandleFunc("GET /dl/{token}/{file}", a.handleMirror)

	var h http.Handler = mux
	h = securityHeaders(h)
	if a.store.Cfg.BasePath != "/" {
		base := strings.TrimSuffix(a.store.Cfg.BasePath, "/")
		inner := http.StripPrefix(base, h)
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == base {
				http.Redirect(w, r, base+"/", http.StatusFound)
				return
			}
			if !strings.HasPrefix(r.URL.Path, base+"/") {
				http.NotFound(w, r)
				return
			}
			inner.ServeHTTP(w, r)
		})
	}
	return h
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
		h.ServeHTTP(w, r)
	})
}

// ---------- handlers ----------

func (a *App) host(r *http.Request) string {
	if h := a.store.Cfg.PublicHost; h != "" {
		return h
	}
	h, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		h = r.Host
	}
	if h == "127.0.0.1" || h == "localhost" {
		return ""
	}
	return h
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Cfg
	writeJSONResp(w, 200, map[string]any{
		"core": DetectCore(), "version": version, "job": a.job.Snapshot(),
		"settings": map[string]string{"publicHost": cfg.PublicHost, "subBase": cfg.SubBase, "domain": cfg.Domain, "listen": cfg.Listen, "panelURL": a.PanelURL()},
		"allToken": a.store.GetAllToken(),
	})
}

func (a *App) handleInbounds(w http.ResponseWriter, r *http.Request) {
	root, core, err := a.cfg.Load()
	if err != nil {
		fail(w, 409, err)
		return
	}
	host := a.host(r)
	atag := apiTag(root)
	out := []InboundView{}
	seen := map[string]bool{}
	for i, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		if ib == nil {
			continue
		}
		network, security := streamInfo(ib)
		iv := InboundView{ID: inboundID(ib, i), Tag: asStr(ib.Get("tag")), Protocol: asStr(ib.Get("protocol")),
			Port: asStr(ib.Get("port")), Listen: asStr(ib.Get("listen")), Network: network, Security: security,
			Managed: supportsClients(ib), System: (atag != "" && asStr(ib.Get("tag")) == atag) || isTunnelTag(asStr(ib.Get("tag"))), Clients: []ClientView{}}
		relays := a.relaysFor(iv.ID)
		iv.Relays = relays
		iv.Tunnels = a.tunnelStatus(iv.ID, ib)
		iv.Single = singleUserSS(ib, host, Relay{})
		cls := clientsOf(ib)
		if isTunnelTag(iv.Tag) {
			iv.Managed, cls = false, nil
		}
		for _, cv := range cls {
			c := asMap(cv)
			if c == nil {
				continue
			}
			email := asStr(c.Get("email"))
			var meta *ClientMeta
			if email != "" {
				meta = a.store.Meta(email)
				meta.Saved = nil
				seen[email] = true
			}
			link, rl := ClientLinks(ib, c, host, relays)
			iv.Clients = append(iv.Clients, ClientView{Email: email, Secret: clientSecret(iv.Protocol, c),
				Flow: asStr(c.Get("flow")), Link: link, Relays: rl, Meta: meta})
		}
		// clients XRay One paused (expired / over limit) are kept in state
		for _, m := range a.store.All() {
			if raw, ok := m.Saved[iv.ID]; ok && m.Disabled {
				if v, err := ParseOrdered(raw); err == nil {
					c := asMap(v)
					mm := m
					mm.Saved = nil
					iv.Clients = append(iv.Clients, ClientView{Email: m.Email, Secret: clientSecret(iv.Protocol, c),
						Link: ClientLink(ib, c, host), Meta: &mm, Disabled: true})
				}
			}
		}
		out = append(out, iv)
	}
	writeJSONResp(w, 200, map[string]any{"inbounds": out, "core": core, "host": host})
}

func (a *App) handleAddInbound(w http.ResponseWriter, r *http.Request) {
	var n NewInbound
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		fail(w, 400, err)
		return
	}
	if !portFree(n.Port) {
		fail(w, 400, fmt.Errorf("port %d is already in use on this server", n.Port))
		return
	}
	err := a.cfg.Mutate(func(root *OMap) error {
		ib, err := BuildInbound(root, n)
		if err != nil {
			return err
		}
		ensureOutbounds(root)
		root.Set("inbounds", append(asArr(root.Get("inbounds")), ib))
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleDelInbound(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	err := a.cfg.Mutate(func(root *OMap) error {
		ib, idx := findInbound(root, id)
		if ib == nil {
			return errors.New("inbound not found")
		}
		if t := apiTag(root); t != "" && asStr(ib.Get("tag")) == t {
			return errors.New("the API inbound is protected")
		}
		arr := asArr(root.Get("inbounds"))
		root.Set("inbounds", append(append([]any{}, arr[:idx]...), arr[idx+1:]...))
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	_ = a.store.EditRelays(func(m map[string][]Relay) { delete(m, id) })
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

type clientReq struct {
	Inbound    string  `json:"inbound"`
	Email      string  `json:"email"`
	ExpiryDays float64 `json:"expiryDays"`
	LimitGB    float64 `json:"limitGB"`
	Note       string  `json:"note"`
	Reset      bool    `json:"resetTraffic"`
	Enable     bool    `json:"enable"`
	SetExpiry  bool    `json:"setExpiry"`
	SetLimit   bool    `json:"setLimit"`
}

func applyLimits(m *ClientMeta, req clientReq, isNew bool) {
	if isNew || req.SetExpiry {
		m.ExpiryUnix = 0
		if req.ExpiryDays > 0 {
			m.ExpiryUnix = time.Now().Add(time.Duration(req.ExpiryDays * 24 * float64(time.Hour))).Unix()
		}
	}
	if isNew || req.SetLimit {
		m.LimitBytes = int64(req.LimitGB * 1024 * 1024 * 1024)
	}
	if req.Reset {
		m.Up, m.Down = 0, 0
	}
	if req.Note != "" {
		m.Note = req.Note
	}
}

func (a *App) handleAddClient(w http.ResponseWriter, r *http.Request) {
	var req clientReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, 400, err)
		return
	}
	if !reEmail.MatchString(req.Email) {
		fail(w, 400, errors.New("name may use letters, digits and . _ @ + - only"))
		return
	}
	err := a.cfg.Mutate(func(root *OMap) error {
		ib, _ := findInbound(root, req.Inbound)
		if ib == nil {
			return errors.New("inbound not found")
		}
		for _, v := range clientsOf(ib) {
			if asStr(asMap(v).Get("email")) == req.Email {
				return errors.New("this name already exists on the inbound")
			}
		}
		c, err := NewClient(ib, req.Email)
		if err != nil {
			return err
		}
		setClients(ib, append(clientsOf(ib), c))
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.store.Update(req.Email, func(m *ClientMeta) { applyLimits(m, req, true) })
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleDelClient(w http.ResponseWriter, r *http.Request) {
	inb, email := r.URL.Query().Get("inbound"), r.URL.Query().Get("email")
	found := false
	err := a.cfg.Mutate(func(root *OMap) error {
		ib, _ := findInbound(root, inb)
		if ib == nil {
			return errors.New("inbound not found")
		}
		_, found = removeClient(ib, email)
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	a.store.Update(email, func(m *ClientMeta) {
		if m.Saved != nil {
			if _, ok := m.Saved[inb]; ok {
				delete(m.Saved, inb)
				found = true
			}
		}
	})
	// forget panel data once the name is gone from every inbound
	if root, _, err := a.cfg.Load(); err == nil && !emailInUse(root, email) {
		m := a.store.Meta(email)
		if len(m.Saved) == 0 {
			a.store.Forget(email)
		}
	}
	if !found {
		fail(w, 404, errors.New("client not found"))
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func emailInUse(root *OMap, email string) bool {
	for _, v := range asArr(root.Get("inbounds")) {
		for _, c := range clientsOf(asMap(v)) {
			if asStr(asMap(c).Get("email")) == email {
				return true
			}
		}
	}
	return false
}

func (a *App) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	var req clientReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fail(w, 400, err)
		return
	}
	a.store.Update(req.Email, func(m *ClientMeta) { applyLimits(m, req, false) })
	if req.Enable {
		if err := a.enableClient(req.Email); err != nil {
			fail(w, 400, err)
			return
		}
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleQR(w http.ResponseWriter, r *http.Request) {
	png, err := qrcode.Encode(r.URL.Query().Get("text"), qrcode.Medium, 320)
	if err != nil {
		fail(w, 400, err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

func (a *App) handleInstall(w http.ResponseWriter, r *http.Request) {
	var body struct{ Action, Version string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Version != "" && !strings.HasPrefix(body.Version, "v") {
		body.Version = "v" + body.Version
	}
	for _, ch := range body.Version {
		if !strings.ContainsRune("v0123456789.", ch) {
			fail(w, 400, errors.New("invalid version"))
			return
		}
	}
	if !a.job.StartCoreJob(orDefault(body.Action, "install"), body.Version) {
		fail(w, 409, errors.New("a job is already running"))
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleRestart(w http.ResponseWriter, r *http.Request) {
	if err := restartCore(DetectCore()); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleEnableAPI(w http.ResponseWriter, r *http.Request) {
	if err := a.cfg.Mutate(EnableAPI); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleRawConfig(w http.ResponseWriter, r *http.Request) {
	core := DetectCore()
	data, err := os.ReadFile(core.ConfigPath)
	if err != nil {
		fail(w, 404, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

func (a *App) handleRestore(w http.ResponseWriter, r *http.Request) {
	var body struct{ Name string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	name := filepath.Base(body.Name)
	if !strings.HasPrefix(name, "config-") {
		fail(w, 400, errors.New("invalid backup"))
		return
	}
	data, err := os.ReadFile(filepath.Join(a.cfg.backupDir, name))
	if err != nil {
		fail(w, 404, err)
		return
	}
	if err := a.cfg.RestoreRaw(data); err != nil {
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	var body struct{ PublicHost, SubBase string }
	_ = json.NewDecoder(r.Body).Decode(&body)
	a.store.Cfg.PublicHost = strings.TrimSpace(body.PublicHost)
	a.store.Cfg.SubBase = strings.TrimRight(strings.TrimSpace(body.SubBase), "/")
	if err := a.store.SaveCfg(); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// handleSub serves a client's subscription: every inbound the name is on.
func (a *App) handleSub(w http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	if tok != "" && tok == a.store.GetAllToken() {
		a.handleAllSub(w, r)
		return
	}
	m := a.store.ByToken(tok)
	if m == nil {
		http.NotFound(w, r)
		return
	}
	root, _, err := a.cfg.Load()
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	var links []string
	if !m.Disabled {
		links = a.userLinks(root, m.Email, a.host(r))
	}
	if wantsSubPage(r) {
		a.serveSubPage(w, r, m, links)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("XRay One · "+m.Email)))
	w.Header().Set("Profile-Update-Interval", "12")
	w.Header().Set("Subscription-Userinfo", "upload="+itoa(m.Up)+"; download="+itoa(m.Down)+"; total="+itoa(m.LimitBytes)+"; expire="+itoa(m.ExpiryUnix))
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))))
}

// handleAllSub serves every config on the server (all inbounds, all active
// clients, plus relay variants) in one subscription.
func (a *App) handleAllSub(w http.ResponseWriter, r *http.Request) {
	root, _, err := a.cfg.Load()
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	host := a.host(r)
	atag := apiTag(root)
	var links []string
	for i, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		if ib == nil || (atag != "" && asStr(ib.Get("tag")) == atag) || isTunnelTag(asStr(ib.Get("tag"))) {
			continue
		}
		relays := a.relaysFor(inboundID(ib, i))
		if l := singleUserSS(ib, host, Relay{}); l != "" {
			var rls []string
			for _, rl := range relays {
				rls = append(rls, singleUserSS(ib, host, rl))
			}
			links = append(links, subLinks(l, rls, relays)...)
		}
		for _, cv := range clientsOf(ib) {
			c := asMap(cv)
			if c == nil {
				continue
			}
			l, rl := ClientLinks(ib, c, host, relays)
			if l != "" {
				links = append(links, subLinks(l, rl, relays)...)
			}
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("XRay One · all")))
	w.Header().Set("Profile-Update-Interval", "12")
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))))
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---------- enforcement loop (expiry & traffic) ----------

func (a *App) enableClient(email string) error {
	m := a.store.Meta(email)
	if !m.Disabled {
		return nil
	}
	a.store.mu.Lock()
	saved := a.store.Clients[email].Saved
	a.store.mu.Unlock()
	err := a.cfg.Mutate(func(root *OMap) error {
		for id, raw := range saved {
			ib, _ := findInbound(root, id)
			if ib == nil {
				continue
			}
			v, err := ParseOrdered(raw)
			if err != nil {
				continue
			}
			setClients(ib, append(clientsOf(ib), v))
		}
		return nil
	})
	if err != nil {
		return err
	}
	a.store.Update(email, func(m *ClientMeta) { m.Disabled, m.Reason, m.Saved = false, "", nil })
	return nil
}

func (a *App) disableClient(email, reason string) {
	saved := map[string]json.RawMessage{}
	err := a.cfg.Mutate(func(root *OMap) error {
		for i, v := range asArr(root.Get("inbounds")) {
			ib := asMap(v)
			if c, ok := removeClient(ib, email); ok {
				saved[inboundID(ib, i)] = json.RawMessage(EncodeIndent(c))
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("disable %s: %v", email, err)
		return
	}
	a.store.Update(email, func(m *ClientMeta) {
		m.Disabled, m.Reason = true, reason
		if m.Saved == nil {
			m.Saved = map[string]json.RawMessage{}
		}
		for k, v := range saved {
			m.Saved[k] = v
		}
	})
	log.Printf("paused %s (%s)", email, reason)
}

func (a *App) Enforce() {
	var apiTried time.Time
	for {
		func() {
			core := DetectCore()
			if !core.Installed || !core.ConfigOK {
				return
			}
			if core.APIAddr == "" && time.Since(apiTried) > 30*time.Minute {
				// per-user traffic is counted by default; this only adds the
				// missing stats/api parts and never rewrites other sections
				apiTried = time.Now()
				if err := a.cfg.Mutate(EnableAPI); err != nil {
					log.Printf("could not turn on traffic stats: %v", err)
				} else {
					log.Printf("traffic stats turned on")
					core = DetectCore()
				}
			}
			if core.APIAddr != "" {
				if st, err := statsQuery(core, core.APIAddr); err == nil {
					for email, v := range st {
						if v[0] == 0 && v[1] == 0 {
							continue
						}
						a.store.Update(email, func(m *ClientMeta) { m.Up += v[0]; m.Down += v[1] })
					}
				}
			}
			now := time.Now().Unix()
			for _, m := range a.store.All() {
				if m.Disabled {
					continue
				}
				if m.ExpiryUnix > 0 && now > m.ExpiryUnix {
					a.disableClient(m.Email, "expired")
				} else if m.LimitBytes > 0 && m.Up+m.Down >= m.LimitBytes {
					a.disableClient(m.Email, "traffic")
				}
			}
		}()
		time.Sleep(60 * time.Second)
	}
}

// subLinks: a tunneled inbound is served only through its middle servers
// (and alt addresses); the direct link is left out of subscriptions.
func subLinks(direct string, relayLinks []string, relays []Relay) []string {
	for _, r := range relays {
		if r.Tunnel != "" {
			return relayLinks
		}
	}
	return append([]string{direct}, relayLinks...)
}

// userLinks is what a client's subscription holds (tunneled inbounds give
// only their tunnel links).
func (a *App) userLinks(root *OMap, email, host string) []string {
	var links []string
	for i, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		for _, cv := range clientsOf(ib) {
			c := asMap(cv)
			if asStr(c.Get("email")) == email {
				relays := a.relaysFor(inboundID(ib, i))
				l, rl := ClientLinks(ib, c, host, relays)
				links = append(links, subLinks(l, rl, relays)...)
			}
		}
	}
	return links
}

// handleWG lists a client's WireGuard links; the page turns each into a
// .conf file and QR for the official WireGuard app.
func (a *App) handleWG(w http.ResponseWriter, r *http.Request) {
	m := a.store.ByToken(r.URL.Query().Get("token"))
	if m == nil {
		writeJSONResp(w, 404, map[string]string{"error": "not found"})
		return
	}
	root, _, err := a.cfg.Load()
	if err != nil {
		writeJSONResp(w, 503, map[string]string{"error": err.Error()})
		return
	}
	out := []string{}
	for _, l := range a.userLinks(root, m.Email, a.host(r)) {
		if strings.HasPrefix(l, "wireguard://") {
			out = append(out, l)
		}
	}
	writeJSONResp(w, 200, out)
}
