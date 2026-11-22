package main

// Download mirror for installing a middle server. GitHub stays the first
// choice; when it does not answer from the middle server, the install falls
// back to this server for the same files: tunnel.sh, its own agent binary,
// SHA256SUMS and the Xray core it runs. Served on the panel's own listener
// (no new port), only when that listener is public, and only under a token
// derived from a live (unexpired) join code, so this is not an open file host.

import (
	"crypto/hmac"
	"crypto/sha256"
	"debug/elf"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed tunnel.sh
var tunnelScript []byte

// mirrorToken: a URL-safe secret derived from a server's join secret.
func mirrorToken(join string) string {
	m := hmac.New(sha256.New, []byte(join))
	m.Write([]byte("xray-one download mirror"))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// mirrorBase: the mirror URL a middle server uses, "" when the panel is
// private (listens on loopback only) or has no domain.
func (a *App) mirrorBase(s TunnelServer) string {
	c := a.store.Cfg
	l := strings.TrimSpace(c.Listen)
	if c.Domain == "" || s.Join == "" || strings.HasPrefix(l, "127.") || strings.HasPrefix(l, "localhost") || strings.HasPrefix(l, "[::1]") {
		return ""
	}
	scheme := "http"
	if a.tls {
		scheme = "https"
	}
	return scheme + "://" + c.Domain + portOf(l) + c.BasePath + "dl/" + mirrorToken(s.Join)
}

// installCmd: the one-line install for a middle server. GitHub 3 tries
// (10 s to connect, 45 s max, 3 s apart), then this server, then GitHub once more.
func (a *App) installCmd(s TunnelServer) string {
	m := a.mirrorBase(s)
	g := `g(){ for i in $(seq $3); do echo "tunnel.sh: $1 ($i/$3)..."; curl -fsSL --connect-timeout 10 -m 45 -o /tmp/xo-tunnel.sh "$2" && return; [ $i -lt $3 ] && sleep 3; done; echo "tunnel.sh: $1 failed"; return 1; }; `
	g += "g GitHub " + tunnelInstall + " 3"
	if m != "" {
		g += " || g 'main server' " + m + "/tunnel.sh 1"
	}
	g += " || g 'GitHub again' " + tunnelInstall + " 1"
	g += " && bash /tmp/xo-tunnel.sh " + encodeJoin(a.joinFor(s))
	if m != "" {
		g += " " + m
	}
	return g
}

func (a *App) mirrorOK(tok string) bool {
	if len(tok) != 32 {
		return false
	}
	servers, _, _ := a.store.TunnelsCopy()
	now := time.Now().Unix()
	for _, s := range servers {
		if s.Join != "" && s.JoinExp > now && hmac.Equal([]byte(mirrorToken(s.Join)), []byte(tok)) {
			return true
		}
	}
	return false
}

type sumCache struct {
	mu sync.Mutex
	m  map[string]string // path|size|mtime -> sha256 hex
}

var mirrorSums = sumCache{m: map[string]string{}}

func fileSum(p string) (string, error) {
	st, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	key := p + "|" + strconv.FormatInt(st.Size(), 10) + "|" + strconv.FormatInt(st.ModTime().UnixNano(), 10)
	mirrorSums.mu.Lock()
	defer mirrorSums.mu.Unlock()
	if v, ok := mirrorSums.m[key]; ok {
		return v, nil
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	v := hex.EncodeToString(h.Sum(nil))
	mirrorSums.m[key] = v
	return v, nil
}

// elfArch: amd64 / arm64 of a Linux binary, "" when unknown.
func elfArch(p string) string {
	f, err := elf.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	switch f.Machine {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_AARCH64:
		return "arm64"
	}
	return ""
}

func selfBin() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return p
}

func xrayBinForMirror() string {
	if p := os.Getenv("XRAY_ONE_MIRROR_XRAY"); p != "" { // tests
		return p
	}
	return DetectCore().Bin
}

// mirrorFiles: what this server can hand out, by release file name.
func mirrorFiles() map[string]string {
	out := map[string]string{}
	if p := selfBin(); p != "" {
		if elfArch(p) == runtime.GOARCH {
			out["xray-one-linux-"+runtime.GOARCH] = p
		}
	}
	if p := xrayBinForMirror(); p != "" {
		if ar := elfArch(p); ar != "" {
			out["xray-linux-"+ar] = p
		}
	}
	return out
}

func (a *App) handleMirror(w http.ResponseWriter, r *http.Request) {
	if !a.mirrorOK(r.PathValue("token")) {
		http.NotFound(w, r)
		return
	}
	name := r.PathValue("file")
	w.Header().Set("Cache-Control", "no-store")
	if name == "tunnel.sh" {
		w.Header().Set("Content-Type", "text/x-shellscript")
		_, _ = w.Write(tunnelScript)
		return
	}
	files := mirrorFiles()
	if name == "SHA256SUMS" {
		var b strings.Builder
		for n, p := range files {
			if s, err := fileSum(p); err == nil {
				fmt.Fprintf(&b, "%s  %s\n", s, n)
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, b.String())
		return
	}
	p, ok := files[name]
	if !ok {
		http.Error(w, "not available on the main server (other architecture)", http.StatusNotFound)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, "not available", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, st.ModTime(), f)
}
