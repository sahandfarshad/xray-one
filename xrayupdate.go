package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Once a day this server asks GitHub for the newest Xray-core release. The
// panel only shows it; the user decides when to update.
var xrayLatest struct {
	sync.Mutex
	Ver string
	At  int64
	Err string
}

func xrayCheckLoop() {
	for {
		xrayCheckNow()
		time.Sleep(24 * time.Hour)
	}
}

func xrayCheckNow() {
	c := &http.Client{Timeout: 20 * time.Second}
	v, err := func() (string, error) {
		resp, err := c.Get("https://api.github.com/repos/XTLS/Xray-core/releases/latest")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return "", errors.New("GitHub answered " + resp.Status)
		}
		var r struct {
			Tag string `json:"tag_name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			return "", err
		}
		return strings.TrimPrefix(r.Tag, "v"), nil
	}()
	xrayLatest.Lock()
	defer xrayLatest.Unlock()
	xrayLatest.At = time.Now().Unix()
	if err != nil {
		xrayLatest.Err = err.Error()
		return
	}
	xrayLatest.Ver, xrayLatest.Err = v, ""
}

// GET /api/xray/latest
func (a *App) handleXrayLatest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("now") == "1" {
		xrayCheckNow()
	}
	core := DetectCore()
	xrayLatest.Lock()
	out := map[string]any{"current": core.Version, "latest": xrayLatest.Ver, "at": xrayLatest.At, "err": xrayLatest.Err}
	xrayLatest.Unlock()
	writeJSONResp(w, 200, out)
}

// POST /api/xray/update {force}: download the newest Xray, test the current
// config with it, and swap it in. A failed test only warns: with force the
// user chose to update anyway.
func (a *App) handleXrayUpdate(w http.ResponseWriter, r *http.Request) {
	var b struct{ Force bool }
	_ = json.NewDecoder(r.Body).Decode(&b)
	core := DetectCore()
	if core.Bin == "" {
		fail(w, 400, errors.New("xray binary not found"))
		return
	}
	dir, err := os.MkdirTemp("", "xo-xray-")
	if err != nil {
		fail(w, 500, err)
		return
	}
	defer os.RemoveAll(dir)
	if err := downloadXray(dir); err != nil {
		fail(w, 502, err)
		return
	}
	nb := filepath.Join(dir, "xray")
	test := core
	test.Bin = nb
	if terr := testConfig(test); terr != nil && !b.Force {
		writeJSONResp(w, 409, map[string]any{"error": "TEST: " + terr.Error()})
		return
	}
	data, err := os.ReadFile(nb)
	if err != nil {
		fail(w, 500, err)
		return
	}
	old, _ := os.ReadFile(core.Bin)
	if len(old) > 0 {
		_ = os.WriteFile(core.Bin+".old", old, 0o755)
	}
	tmp := core.Bin + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		fail(w, 500, err)
		return
	}
	if err := os.Rename(tmp, core.Bin); err != nil {
		fail(w, 500, err)
		return
	}
	if err := restartCore(core); err != nil {
		fail(w, 500, err)
		return
	}
	writeJSONResp(w, 200, map[string]any{"ok": true, "version": DetectCore().Version})
}
