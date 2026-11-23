package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Data probe: a heartbeat is a few hundred bytes, so a way the network lets
// through for small packets but chokes for real traffic (ping fine, videos
// stall) looks healthy to it. Now and then the agent pulls a small download
// from the main server over its current way; when that fails twice in a row
// the way counts as broken and the search moves on to the next one.

const (
	probeBytes = 256 << 10        // 256 KB
	probeEvery = 5 * time.Minute  // on a way that works
	probeLimit = 20 * time.Second // ≈13 KB/s at least
	probeMaxN  = 1 << 20
)

// GET /api/agent/probe?n=: n bytes for the agent's data probe
func (a *App) handleAgentProbe(w http.ResponseWriter, r *http.Request) {
	if !a.agentOK(r) {
		fail(w, 403, errors.New("unknown middle server"))
		return
	}
	n := probeBytes
	if v := r.URL.Query().Get("n"); v != "" {
		_, _ = fmt.Sscan(v, &n)
	}
	if n <= 0 || n > probeMaxN {
		n = probeBytes
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprint(n))
	for n > 0 {
		c := min(n, len(testBlob))
		if _, err := w.Write(testBlob[:c]); err != nil {
			return
		}
		n -= c
	}
}

// agentProbe downloads probeBytes over the agent's current way. ok=true also
// when the main server is too old to answer (404): nothing to judge then.
func agentProbe(c *http.Client, st agentState) (ok bool, msg string) {
	hr, _ := http.NewRequest("GET", strings.TrimSuffix(st.Join.Panel, "/")+fmt.Sprintf("/api/agent/probe?n=%d", probeBytes), nil)
	hr.Header.Set("X-Agent-ID", st.Join.ID)
	hr.Header.Set("X-Agent-Token", st.Token)
	t0 := time.Now()
	resp, err := c.Do(hr)
	if err != nil {
		return false, "data test: " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return true, ""
	}
	if resp.StatusCode != 200 {
		return false, fmt.Sprintf("data test: HTTP %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n < probeBytes {
		return false, fmt.Sprintf("data test: got %d of %d KB in %.0f s (ping works, real traffic does not)", n>>10, probeBytes>>10, time.Since(t0).Seconds())
	}
	return true, ""
}
