package main

// Server traffic: a live speed stream (only while the dashboard is open) and a
// cheap per-day total from the main network card's counters.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mainIface: the interface of the default route, else every non-loopback one.
func mainIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) > 2 && p[1] == "00000000" {
			return p[0]
		}
	}
	return ""
}

// netCounters returns received / sent bytes of iface ("" = all but lo).
func netCounters(iface string) (rx, tx uint64, ok bool) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		if (iface != "" && name != iface) || (iface == "" && name == "lo") {
			continue
		}
		p := strings.Fields(line[i+1:])
		if len(p) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(p[0], 10, 64)
		t, _ := strconv.ParseUint(p[8], 10, 64)
		rx += r
		tx += t
		ok = true
	}
	return
}

type DayTraffic struct {
	Rx uint64 `json:"rx"` // received by the server (download)
	Tx uint64 `json:"tx"` // sent by the server (upload)
}

type trafficLog struct {
	mu     sync.Mutex
	path   string
	Iface  string                 `json:"iface"`
	LastRx uint64                 `json:"lastRx"`
	LastTx uint64                 `json:"lastTx"`
	Days   map[string]*DayTraffic `json:"days"`
	dirty  bool
}

func openTrafficLog(dir string) *trafficLog {
	t := &trafficLog{path: filepath.Join(dir, "traffic.json"), Days: map[string]*DayTraffic{}}
	if b, err := os.ReadFile(t.path); err == nil {
		_ = json.Unmarshal(b, t)
		if t.Days == nil {
			t.Days = map[string]*DayTraffic{}
		}
	}
	return t
}

func (t *trafficLog) sample() {
	t.mu.Lock()
	defer t.mu.Unlock()
	iface := mainIface()
	rx, tx, ok := netCounters(iface)
	if !ok {
		return
	}
	if iface != t.Iface || (t.LastRx == 0 && t.LastTx == 0) {
		t.Iface, t.LastRx, t.LastTx, t.dirty = iface, rx, tx, true
		return
	}
	dr, dt := rx-t.LastRx, tx-t.LastTx
	if rx < t.LastRx { // reboot / counter reset
		dr = rx
	}
	if tx < t.LastTx {
		dt = tx
	}
	t.LastRx, t.LastTx = rx, tx
	day := time.Now().Format("2006-01-02")
	d := t.Days[day]
	if d == nil {
		d = &DayTraffic{}
		t.Days[day] = d
		// keep about 13 months
		if len(t.Days) > 400 {
			keys := make([]string, 0, len(t.Days))
			for k := range t.Days {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys[:len(keys)-400] {
				delete(t.Days, k)
			}
		}
	}
	d.Rx += dr
	d.Tx += dt
	t.dirty = true
}

func (t *trafficLog) save() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.dirty {
		return
	}
	b, _ := json.Marshal(t)
	tmp := t.path + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil && os.Rename(tmp, t.path) == nil {
		t.dirty = false
	}
}

// loop: count once an hour (and at start), saving each time. A day's total
// lands in the day the hour ended in, which is close enough.
func (t *trafficLog) loop() {
	t.sample()
	t.save()
	for range time.Tick(time.Hour) {
		t.sample()
		t.save()
	}
}

// GET /api/traffic/daily?month=YYYY-MM | ?days=7
func (a *App) handleTrafficDaily(w http.ResponseWriter, r *http.Request) {
	if n, _ := strconv.Atoi(r.URL.Query().Get("days")); n > 0 && n <= 60 {
		a.trafficLastDays(w, n)
		return
	}
	month := r.URL.Query().Get("month")
	m, err := time.ParseInLocation("2006-01", month, time.Local)
	if err != nil {
		m = time.Now()
		m = time.Date(m.Year(), m.Month(), 1, 0, 0, 0, 0, time.Local)
	}
	t := a.traffic
	t.mu.Lock()
	defer t.mu.Unlock()
	var days []map[string]any
	var sumRx, sumTx uint64
	for d := m; d.Month() == m.Month(); d = d.AddDate(0, 0, 1) {
		k := d.Format("2006-01-02")
		v := t.Days[k]
		if v == nil {
			v = &DayTraffic{}
		}
		sumRx += v.Rx
		sumTx += v.Tx
		days = append(days, map[string]any{"day": d.Day(), "date": k, "rx": v.Rx, "tx": v.Tx})
	}
	first := ""
	for k := range t.Days {
		if first == "" || k < first {
			first = k
		}
	}
	writeJSONResp(w, 200, map[string]any{"month": m.Format("2006-01"), "days": days, "rx": sumRx, "tx": sumTx,
		"since": first, "iface": t.Iface, "today": time.Now().Format("2006-01-02")})
}

// GET /api/live: server-sent events, one small line every 2 s, only while
// the dashboard has it open (the browser closes it when you leave the page).
func (a *App) handleLive(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		fail(w, 500, fmt.Errorf("streaming not supported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	iface := mainIface()
	prx, ptx, _ := netCounters(iface)
	pt := time.Now()
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var prev map[string]int64 // xray counters at the last tick (live detail)
	var core Core
	var skip string // the stats api's own inbound (our reads would show there)
	n := 0
	stop := time.After(30 * time.Minute) // the page reconnects by itself
	for {
		select {
		case <-r.Context().Done():
			return
		case <-stop:
			return
		case now := <-tick.C:
			rx, tx, _ := netCounters(iface)
			sec := now.Sub(pt).Seconds()
			var drx, dtx uint64
			if rx >= prx {
				drx = rx - prx
			}
			if tx >= ptx {
				dtx = tx - ptx
			}
			prx, ptx, pt = rx, tx, now
			msg := map[string]any{"rx": uint64(float64(drx) / sec), "tx": uint64(float64(dtx) / sec)}
			if !a.store.Cfg.LiveOff {
				if n%30 == 0 {
					core = DetectCore()
					if root, _, err := a.cfg.Load(); err == nil {
						skip = apiTag(root)
					}
				}
				n++
				msg["in"], msg["cl"], prev = liveDetail(core, skip, prev, sec)
			} else {
				prev = nil
			}
			b, _ := json.Marshal(msg)
			if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

func (a *App) trafficLastDays(w http.ResponseWriter, n int) {
	t := a.traffic
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	var days []map[string]any
	var sumRx, sumTx uint64
	for i := n - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i)
		k := d.Format("2006-01-02")
		v := t.Days[k]
		if v == nil {
			v = &DayTraffic{}
		}
		sumRx += v.Rx
		sumTx += v.Tx
		days = append(days, map[string]any{"day": d.Day(), "date": k, "rx": v.Rx, "tx": v.Tx})
	}
	first := ""
	for k := range t.Days {
		if first == "" || k < first {
			first = k
		}
	}
	writeJSONResp(w, 200, map[string]any{"days": days, "rx": sumRx, "tx": sumTx, "since": first, "iface": t.Iface, "today": now.Format("2006-01-02")})
}

// liveDetail: speed (bytes/s) per inbound tag and per client since the last
// tick, as [name, down, up] rows, idle ones left out. The per-user counters
// are reset every minute by the stats loop; a counter that went down counts
// from zero.
func liveDetail(core Core, skip string, prev map[string]int64, sec float64) (in, cl [][3]any, cur map[string]int64) {
	in, cl = [][3]any{}, [][3]any{}
	if core.APIAddr == "" {
		return in, cl, nil
	}
	cur, err := statsRaw(core, core.APIAddr)
	if err != nil || prev == nil {
		return in, cl, cur
	}
	type ud struct{ up, down int64 }
	ins, cls := map[string]*ud{}, map[string]*ud{}
	for name, v := range cur {
		p := strings.Split(name, ">>>")
		if len(p) != 4 || p[2] != "traffic" || (p[0] == "inbound" && p[1] == skip) {
			continue
		}
		d := v
		if o, ok := prev[name]; ok && v >= o {
			d = v - o
		}
		var m map[string]*ud
		switch p[0] {
		case "inbound":
			m = ins
		case "user":
			m = cls
		default:
			continue
		}
		e := m[p[1]]
		if e == nil {
			e = &ud{}
			m[p[1]] = e
		}
		if p[3] == "uplink" {
			e.up += d
		} else {
			e.down += d
		}
	}
	rows := func(m map[string]*ud) [][3]any {
		r := [][3]any{}
		for k, e := range m {
			if e.up > 0 || e.down > 0 {
				r = append(r, [3]any{k, int64(float64(e.down) / sec), int64(float64(e.up) / sec)})
			}
		}
		return r
	}
	return rows(ins), rows(cls), cur
}
