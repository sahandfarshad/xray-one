package main

// The FRP and Backhaul programs. This server downloads them from GitHub; a
// middle server gets them from this server through its tunnel (GitHub is
// often slow or blocked there), falling back to GitHub itself.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// carrierURL: the release archive holding program name, and its path inside.
func carrierURL(name, arch string) (string, string) {
	if name == "backhaul" {
		return fmt.Sprintf("https://github.com/Musixal/Backhaul/releases/download/%s/backhaul_linux_%s.tar.gz", bhVer, arch), "backhaul"
	}
	d := fmt.Sprintf("frp_%s_linux_%s", frpVer, arch)
	return fmt.Sprintf("https://github.com/fatedier/frp/releases/download/v%s/%s.tar.gz", frpVer, d), d + "/" + name
}

func validCarrierBin(name string) bool { return name == "frpc" || name == "frps" || name == "backhaul" }

// untarOne: file member out of a .tar.gz.
func untarOne(gz []byte, member string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("%s not in the archive", member)
		}
		if strings.TrimPrefix(h.Name, "./") == member {
			return io.ReadAll(io.LimitReader(tr, 200<<20))
		}
	}
}

func httpGet(c *http.Client, u string, h map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20))
}

func writeExec(p string, b []byte) error {
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	tmp := p + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

var binMu sync.Mutex

// carrierBin: path of program name for arch ("" = this machine's) on this
// server, downloaded from GitHub the first time.
func carrierBin(dir, name, arch string) (string, error) {
	if arch == "" {
		arch = runtime.GOARCH
	}
	if !validCarrierBin(name) || (arch != "amd64" && arch != "arm64") {
		return "", errors.New("unknown program")
	}
	ver := frpVer
	if name == "backhaul" {
		ver = bhVer
	}
	p := filepath.Join(dir, "bin", arch, ver, name)
	binMu.Lock()
	defer binMu.Unlock()
	if st, err := os.Stat(p); err == nil && st.Size() > 0 {
		return p, nil
	}
	u, member := carrierURL(name, arch)
	c := &http.Client{Timeout: 5 * time.Minute}
	gz, err := httpGet(c, u, nil)
	if err != nil {
		return "", fmt.Errorf("download %s: %v", name, err)
	}
	b, err := untarOne(gz, member)
	if err != nil {
		return "", err
	}
	if err := writeExec(p, b); err != nil {
		return "", err
	}
	return p, nil
}

// agentOK: the request comes from a known middle server's agent
func (a *App) agentOK(r *http.Request) bool {
	id, tok := r.Header.Get("X-Agent-ID"), r.Header.Get("X-Agent-Token")
	servers, _, _ := a.store.TunnelsCopy()
	for _, s := range servers {
		if id != "" && tok != "" && s.ID == id && s.Token != "" && subtle.ConstantTimeCompare([]byte(s.Token), []byte(tok)) == 1 {
			return true
		}
	}
	return false
}

// GET /api/agent/bin/{name}?arch=: a middle server fetching a program.
func (a *App) handleAgentBin(w http.ResponseWriter, r *http.Request) {
	if !a.agentOK(r) {
		fail(w, 403, errors.New("unknown middle server"))
		return
	}
	p, err := carrierBin(a.store.dir, r.PathValue("name"), r.URL.Query().Get("arch"))
	if err != nil {
		fail(w, 502, err)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		fail(w, 500, err)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, filepath.Base(p), st.ModTime(), f)
}

// agentCarrierBin: the program on the middle server, from the main server
// (through the tunnel) or else GitHub.
func agentCarrierBin(st agentState, name string) (string, error) {
	ver := frpVer
	if name == "backhaul" {
		ver = bhVer
	}
	p := filepath.Join(agentXrayDir, "carriers", ver, name)
	binMu.Lock()
	defer binMu.Unlock()
	if s, err := os.Stat(p); err == nil && s.Size() > 0 {
		return p, nil
	}
	var errs []string
	ctl := st.Ctl
	if ctl == 0 {
		ctl = agentCtlPort
	}
	ports := []int{ctl, ctl + 1}
	if st.Token == "" {
		ports = nil // never reached the main server: GitHub only
	}
	for _, port := range ports {
		pu, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
		c := &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // inside the tunnel, to 127.0.0.1
		b, err := httpGet(c, strings.TrimSuffix(st.Join.Panel, "/")+"/api/agent/bin/"+name+"?arch="+runtime.GOARCH,
			map[string]string{"X-Agent-ID": st.Join.ID, "X-Agent-Token": st.Token})
		if err == nil && len(b) > 0 {
			return p, writeExec(p, b)
		}
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	u, member := carrierURL(name, runtime.GOARCH)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		gz, _ := io.ReadAll(io.LimitReader(resp.Body, 200<<20))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			if b, err := untarOne(gz, member); err == nil {
				return p, writeExec(p, b)
			}
		}
		errs = append(errs, "GitHub: HTTP "+resp.Status)
	} else {
		errs = append(errs, "GitHub: "+err.Error())
	}
	return "", fmt.Errorf("could not get %s: %s", name, strings.Join(errs, "; "))
}
