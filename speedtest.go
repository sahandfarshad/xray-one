package main

// Manual tunnel test: latency and throughput through one exact path between
// this server and a middle server, on demand only.
//
// The admin presses Test on a card (WS, XHTTP, REALITY, WireGuard, mKCP). The
// panel queues the test and wakes the middle server's held heartbeat; the
// reply carries the test. The agent runs it on its own goroutine:
//   - a rotating method: a separate, short-lived Xray process (SOCKS on a
//     free 127.0.0.1 port -> that method's outbound, which the panel sends),
//     so the relay, its live path, its search and rotation are never touched;
//     every method's inbound here is pre-armed, so nothing changes here either;
//   - a dedicated tunnel: its own status check inbound (dt-<type>-probe), i.e.
//     the real dedicated path.
// It times small requests to the panel (latency), then a capped download and
// upload, and posts the result over its heartbeat path. One test at a time
// per middle server; traffic is capped on both ends.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	agentTestVer = "0.7.0"
	testPings    = 7
	testDLMax    = 32 << 20 // bytes, per test
	testULMax    = 16 << 20
	testDLSec    = 6
	testULSec    = 5
	testPickup   = 45 * time.Second // agent must pick the test up by then
	testRunMax   = 90 * time.Second // and report by then
)

func isRotatingKind(k string) bool { return validMethod(k) }
func validTestKind(k string) bool  { return validMethod(k) }

// speedSpec: what the agent runs.
type speedSpec struct {
	ID    string          `json:"id"`
	Kind  string          `json:"kind"`
	Out   json.RawMessage `json:"out,omitempty"` // rotating: the method's outbound
	Pings int             `json:"pings"`
	DL    int64           `json:"dl"`
	UL    int64           `json:"ul"`
	DLSec int             `json:"dlSec"`
	ULSec int             `json:"ulSec"`
}

// speedResult: what it found. Times in ms, rates in Mbit/s.
type speedResult struct {
	OK     bool    `json:"ok"`
	Err    string  `json:"err,omitempty"`
	Conn   int     `json:"conn"` // first request, connection set-up included
	Ms     float64 `json:"ms"`   // median round trip
	Min    float64 `json:"min"`
	Max    float64 `json:"max"`
	Jitter float64 `json:"jitter"` // mean change between consecutive round trips
	N      int     `json:"n"`
	Down   float64 `json:"down"`
	DownMB float64 `json:"downMB"`
	Up     float64 `json:"up"`
	UpMB   float64 `json:"upMB"`
	DLErr  string  `json:"dlErr,omitempty"`
	ULErr  string  `json:"ulErr,omitempty"`
}

// speedView: one card's test as the panel shows it.
type speedView struct {
	ID    string       `json:"id"`
	Kind  string       `json:"kind"`
	State string       `json:"state"` // queued, running, done, failed
	At    int64        `json:"at"`
	Done  int64        `json:"done,omitempty"`
	Res   *speedResult `json:"res,omitempty"`
	Err   string       `json:"err,omitempty"`
}

type speedHub struct {
	mu   sync.Mutex
	path string
	m    map[string]map[string]*speedView // server -> kind -> last test
	spec map[string]*speedSpec            // server -> queued test not yet sent
}

var speeds = &speedHub{m: map[string]map[string]*speedView{}, spec: map[string]*speedSpec{}}

// open loads the last results (finished ones only).
func (h *speedHub) open(dir string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.path = filepath.Join(dir, "speedtests.json")
	b, err := os.ReadFile(h.path)
	if err != nil {
		return
	}
	var m map[string]map[string]*speedView
	if json.Unmarshal(b, &m) != nil {
		return
	}
	for id, ks := range m {
		for k, v := range ks {
			if v == nil || (v.State != "done" && v.State != "failed") {
				delete(ks, k)
			}
		}
		h.m[id] = ks
	}
}

func (h *speedHub) saveLocked() {
	if h.path == "" {
		return
	}
	if b, err := json.Marshal(h.m); err == nil {
		_ = writeAtomic(h.path, b)
	}
}

func (h *speedHub) view(id string) map[string]speedView {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]speedView{}
	for k, v := range h.m[id] {
		out[k] = *v
	}
	return out
}

// activeLocked: the test still queued or running on a middle server.
func (h *speedHub) activeLocked(id string) *speedView {
	for _, v := range h.m[id] {
		if v.State == "queued" || v.State == "running" {
			return v
		}
	}
	return nil
}

func (h *speedHub) start(id string, sp *speedSpec) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if v := h.activeLocked(id); v != nil {
		return fmt.Errorf("a test (%s) is already running on this middle server; wait for it to finish", v.Kind)
	}
	if h.m[id] == nil {
		h.m[id] = map[string]*speedView{}
	}
	h.m[id][sp.Kind] = &speedView{ID: sp.ID, Kind: sp.Kind, State: "queued", At: time.Now().Unix()}
	h.spec[id] = sp
	time.AfterFunc(testPickup, func() {
		h.finish(id, sp.ID, nil, "the middle server did not pick up the test (offline, or busy reconnecting)", "queued")
	})
	return nil
}

// take hands a queued test to an agent that can run it, once.
func (h *speedHub) take(s TunnelServer) *speedSpec {
	if s.AgentVer == "" || versionLess(s.AgentVer, agentTestVer) {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	sp := h.spec[s.ID]
	if sp == nil {
		return nil
	}
	delete(h.spec, s.ID)
	v := h.m[s.ID][sp.Kind]
	if v == nil || v.ID != sp.ID || v.State != "queued" {
		return nil
	}
	v.State, v.At = "running", time.Now().Unix()
	time.AfterFunc(testRunMax, func() {
		h.finish(s.ID, sp.ID, nil, "no result from the middle server (the test path or its heartbeat dropped)", "running")
	})
	return sp
}

// finish records a result (or an error). only: finish only while the test is
// in that state ("" any unfinished state).
func (h *speedHub) finish(id, testID string, res *speedResult, errMsg, only string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, v := range h.m[id] {
		if v.ID != testID {
			continue
		}
		if v.State == "done" || v.State == "failed" || (only != "" && v.State != only) {
			return false
		}
		if sp := h.spec[id]; sp != nil && sp.ID == testID {
			delete(h.spec, id)
		}
		v.Done = time.Now().Unix()
		if res != nil && res.OK {
			v.State, v.Res, v.Err = "done", res, ""
		} else {
			v.State, v.Res, v.Err = "failed", res, errMsg
			if res != nil && errMsg == "" {
				v.Err = res.Err
			}
		}
		h.saveLocked()
		return true
	}
	return false
}

// running: the test with this id is running on middle server id.
func (h *speedHub) running(id, testID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, v := range h.m[id] {
		if v.ID == testID && v.State == "running" {
			return true
		}
	}
	return false
}

func (h *speedHub) forget(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.m, id)
	delete(h.spec, id)
	h.saveLocked()
}

// ---------- panel: start a test ----------

// POST /api/tunnels/{id}/speed {kind}: queue a test of one card's path.
func (a *App) handleSpeedTest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	if !validTestKind(b.Kind) {
		fail(w, 400, errors.New("unknown tunnel type"))
		return
	}
	servers, set, _ := a.store.TunnelsCopy()
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
	if s.LastSeen == 0 || time.Since(time.Unix(s.LastSeen, 0)) > onlineWindow {
		fail(w, 400, errors.New("the middle server is offline"))
		return
	}
	if versionLess(s.AgentVer, agentTestVer) {
		fail(w, 400, fmt.Errorf("update the middle server first (agent %s or newer): run the install command again there", agentTestVer))
		return
	}
	sp := &speedSpec{ID: randHex(6), Kind: b.Kind, Pings: testPings, DL: testDLMax, UL: testULMax, DLSec: testDLSec, ULSec: testULSec}
	t := *s
	t.Method = b.Kind
	j := a.joinWith(t, true)
	if (b.Kind == tunnelMethodXHTTP && j.XPort == 0) || (b.Kind == tunnelMethodRT && (j.RPort == 0 || set.RPub == "")) || (b.Kind == tunnelMethodWS && set.Port == 0) ||
		(isUDPMethod(b.Kind) && j.Method != b.Kind) {
		fail(w, 400, errors.New("this method is not ready on this server yet"))
		return
	}
	if !methodCapable(*s, b.Kind) {
		fail(w, 400, fmt.Errorf("the middle server cannot run this method yet: run the install command there again (agent %s or newer, Xray %s or newer for mKCP)", agentKCPVer, minKCPXray))
		return
	}
	outs := methodOutbounds(j, "test")
	if len(outs) == 1 {
		sp.Out = EncodeIndent(outs[0].(*OMap))
	} else {
		if versionLess(s.AgentVer, agentWGTestVer) {
			fail(w, 400, fmt.Errorf("update the middle server first (agent %s or newer): run the install command again there", agentWGTestVer))
			return
		}
		sp.Out = EncodeIndent(outs)
	}
	if err := speeds.start(id, sp); err != nil {
		fail(w, 409, err)
		return
	}
	hub.Poke(id)
	writeJSONResp(w, 200, map[string]any{"ok": true, "id": sp.ID})
}

// ---------- panel: endpoints the agent's test hits (through the tunnel) ----------

// testAgent: the middle server sending a test request, and that its test is
// running (so these endpoints cannot be used for anything else).
func (a *App) testAgent(r *http.Request) (string, bool) {
	id, tok := r.Header.Get("X-Agent-ID"), r.Header.Get("X-Agent-Token")
	if id == "" || tok == "" {
		return "", false
	}
	servers, _, _ := a.store.TunnelsCopy()
	for _, s := range servers {
		if s.ID == id && s.Token != "" && subtle.ConstantTimeCompare([]byte(s.Token), []byte(tok)) == 1 {
			return id, speeds.running(id, r.Header.Get("X-Test-ID"))
		}
	}
	return "", false
}

var testBlob = func() []byte {
	b := make([]byte, 64<<10)
	_, _ = rand.Read(b) // incompressible
	return b
}()

func (a *App) handleTestPing(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.testAgent(r); !ok {
		fail(w, 403, errors.New("no test running"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("ok"))
}

func (a *App) handleTestDown(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.testAgent(r); !ok {
		fail(w, 403, errors.New("no test running"))
		return
	}
	n, _ := strconv.ParseInt(r.URL.Query().Get("n"), 10, 64)
	if n <= 0 || n > testDLMax {
		n = testDLMax
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	end := time.Now().Add((testDLSec + 4) * time.Second)
	for n > 0 && time.Now().Before(end) {
		c := int64(len(testBlob))
		if n < c {
			c = n
		}
		if _, err := w.Write(testBlob[:c]); err != nil {
			return
		}
		n -= c
	}
}

func (a *App) handleTestUp(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.testAgent(r); !ok {
		fail(w, 403, errors.New("no test running"))
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add((testULSec + 6) * time.Second))
	n, _ := io.Copy(io.Discard, io.LimitReader(r.Body, testULMax+(1<<20)))
	writeJSONResp(w, 200, map[string]int64{"n": n})
}

// POST /api/agent/t/res {id, res}: the agent's result (over its heartbeat path).
func (a *App) handleTestResult(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID  string      `json:"id"`
		Res speedResult `json:"res"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	r.Header.Set("X-Test-ID", b.ID)
	id, ok := a.testAgent(r)
	if !ok {
		fail(w, 403, errors.New("no such test running"))
		return
	}
	b.Res.Err = trimTo(b.Res.Err, 300)
	b.Res.DLErr, b.Res.ULErr = trimTo(b.Res.DLErr, 200), trimTo(b.Res.ULErr, 200)
	speeds.finish(id, b.ID, &b.Res, "", "running")
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

// ---------- agent side ----------

var agentTesting atomic.Bool

// agentStartTest runs a test in the background; one at a time.
func agentStartTest(sp *speedSpec, st agentState) {
	if sp == nil || !agentTesting.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer agentTesting.Store(false)
		fmt.Printf("tunnel test %s (%s) started\n", sp.ID, sp.Kind)
		res := runSpeedTest(sp, st, agentXray(), agentDir)
		fmt.Printf("tunnel test %s (%s): ok=%v %.1f ms, down %.1f / up %.1f Mbit/s %s\n", sp.ID, sp.Kind, res.OK, res.Ms, res.Down, res.Up, res.Err)
		reportSpeed(st, sp.ID, res)
	}()
}

// runSpeedTest measures one path. dir holds xray.json (the relay config) and
// the temporary test config.
func runSpeedTest(sp *speedSpec, st agentState, xrayBin, dir string) speedResult {
	var res speedResult
	u, err := url.Parse(st.Join.Panel)
	if err != nil {
		res.Err = "bad panel address"
		return res
	}
	tr := &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 2, DisableCompression: true,
		// the hop ends at the panel on 127.0.0.1, inside the authenticated tunnel
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	if len(sp.Out) > 0 {
		port, stop, err := startTestXray(sp.Out, xrayBin, dir)
		if err != nil {
			res.Err = trimTo(err.Error(), 300)
			return res
		}
		defer stop()
		pu, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
		tr.Proxy = http.ProxyURL(pu)
	} else {
		res.Err = "the panel sent no outbound to test"
		return res
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := strings.TrimSuffix(u.String(), "/") + "/api/agent/t/"
	req := func(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
		hr, err := http.NewRequestWithContext(ctx, method, base+path, body)
		if err != nil {
			return nil, err
		}
		hr.Header.Set("X-Agent-ID", st.Join.ID)
		hr.Header.Set("X-Agent-Token", st.Token)
		hr.Header.Set("X-Test-ID", sp.ID)
		resp, err := c.Do(hr)
		if err == nil && resp.StatusCode != 200 {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
			resp.Body.Close()
			return nil, fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
		}
		return resp, err
	}
	ping := func() (float64, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		t0 := time.Now()
		resp, err := req(ctx, "GET", "ping", nil)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return float64(time.Since(t0).Microseconds()) / 1000, nil
	}
	// connection set-up, then round trips on the same connection
	first, err := ping()
	if err != nil {
		res.Err = "could not reach the main server through this path: " + trimTo(err.Error(), 200)
		return res
	}
	res.Conn = int(math.Round(first))
	var rtts []float64
	for i := 0; i < max(sp.Pings, 1); i++ {
		d, err := ping()
		if err != nil {
			res.Err = trimTo(err.Error(), 200)
			break
		}
		rtts = append(rtts, d)
		time.Sleep(150 * time.Millisecond)
	}
	if len(rtts) == 0 {
		return res
	}
	res.OK, res.N = true, len(rtts)
	res.Ms, res.Min, res.Max, res.Jitter = rttStats(rtts)

	// download: until the cap or the time is up
	if sp.DL > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(sp.DLSec+8)*time.Second)
		resp, err := req(ctx, "GET", "dl?n="+strconv.FormatInt(min(sp.DL, testDLMax), 10), nil)
		if err != nil {
			res.DLErr = trimTo(err.Error(), 200)
		} else {
			buf := make([]byte, 64<<10)
			var n int64
			var t0 time.Time
			end := time.Duration(sp.DLSec) * time.Second
			for {
				k, e := resp.Body.Read(buf)
				if k > 0 && t0.IsZero() {
					t0 = time.Now() // from the first byte: one round trip less
				}
				n += int64(k)
				if e != nil || (!t0.IsZero() && time.Since(t0) > end) {
					if e != nil && e != io.EOF {
						res.DLErr = trimTo(e.Error(), 200)
					}
					break
				}
			}
			resp.Body.Close()
			if el := time.Since(t0).Seconds(); n > 0 && el > 0 {
				res.Down, res.DownMB = round1(float64(n)*8/el/1e6), round1(float64(n)/(1<<20))
			}
		}
		cancel()
	}
	// upload: the panel counts what arrived
	if sp.UL > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(sp.ULSec+10)*time.Second)
		body := &timedReader{left: min(sp.UL, testULMax), until: time.Now().Add(time.Duration(sp.ULSec) * time.Second)}
		t0 := time.Now()
		resp, err := req(ctx, "POST", "ul", body)
		if err != nil {
			res.ULErr = trimTo(err.Error(), 200)
		} else {
			var r struct {
				N int64 `json:"n"`
			}
			_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&r)
			resp.Body.Close()
			if el := time.Since(t0).Seconds(); r.N > 0 && el > 0 {
				res.Up, res.UpMB = round1(float64(r.N)*8/el/1e6), round1(float64(r.N)/(1<<20))
			}
		}
		cancel()
	}
	return res
}

// rttStats: median, min, max and jitter (mean absolute change between
// consecutive samples), rounded to 0.1 ms.
func rttStats(v []float64) (med, lo, hi, jit float64) {
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	if n := len(s); n%2 == 1 {
		med = s[n/2]
	} else {
		med = (s[n/2-1] + s[n/2]) / 2
	}
	lo, hi = s[0], s[len(s)-1]
	for i := 1; i < len(v); i++ {
		jit += math.Abs(v[i] - v[i-1])
	}
	if len(v) > 1 {
		jit /= float64(len(v) - 1)
	}
	return round1(med), round1(lo), round1(hi), round1(jit)
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// timedReader: incompressible bytes until left runs out or the time is up.
type timedReader struct {
	left  int64
	until time.Time
}

func (t *timedReader) Read(p []byte) (int, error) {
	if t.left <= 0 || time.Now().After(t.until) {
		return 0, io.EOF
	}
	n := copy(p, testBlob)
	if int64(n) > t.left {
		n = int(t.left)
	}
	t.left -= int64(n)
	return n, nil
}

// startTestXray runs a separate Xray with only a local SOCKS inbound and the
// method's outbound, apart from the relay (whose config and process it never
// touches). Returns the SOCKS port and a stop function.
func startTestXray(out json.RawMessage, xrayBin, dir string) (int, func(), error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	// one outbound, or a list whose first one is the way out (WireGuard: VLESS,
	// then the WireGuard outbound it dials through)
	var o any
	if err := json.Unmarshal(out, &o); err != nil {
		return 0, nil, errors.New("bad test outbound")
	}
	outs, ok := o.([]any)
	if !ok {
		outs = []any{o}
	}
	cfg, _ := json.MarshalIndent(map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"tag": "test-in", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}},
		"outbounds": outs,
	}, "", " ")
	p := filepath.Join(dir, "xray.test.json")
	if err := os.WriteFile(p, cfg, 0o600); err != nil {
		return 0, nil, err
	}
	var log bytes.Buffer
	cmd := exec.Command(xrayBin, "run", "-config", p)
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		os.Remove(p)
		return 0, nil, err
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	stop := func() {
		_ = cmd.Process.Kill()
		<-exited
		os.Remove(p)
	}
	for i := 0; i < 80; i++ {
		select {
		case <-exited:
			os.Remove(p)
			return 0, nil, fmt.Errorf("test xray did not start: %s", trimTo(strings.TrimSpace(log.String()), 250))
		default:
		}
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond); err == nil {
			c.Close()
			return port, stop, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	stop()
	return 0, nil, errors.New("test xray did not start in time")
}

// reportSpeed posts the result over the heartbeat path (forward SOCKS, then
// the reverse one).
func reportSpeed(st agentState, testID string, res speedResult) {
	body, _ := json.Marshal(map[string]any{"id": testID, "res": res})
	if !agentReport(st, "/api/agent/t/res", body) {
		fmt.Println("tunnel test: could not report the result")
	}
}

// agentXrayVersion: "26.11.9" from `xray version`, "" when unknown.
func agentXrayVersion(bin string) string {
	out, err := run(10*time.Second, bin, "version")
	if err != nil {
		return ""
	}
	f := strings.Fields(out)
	if len(f) >= 2 && f[0] == "Xray" && reClientVer.MatchString(f[1]) {
		return f[1]
	}
	return ""
}
