package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// xray.service usually runs as a non-root user (nobody). For TLS inbounds we
// let that user read the ORIGINAL certificate files in place (one fixed path
// shared by the panel, xray and Muse99): parent folders get traverse-only
// permission, the certificate folder and key get the service group. Renewal
// rewrites the same files, so the path never changes; xray is restarted when
// the certificate content changes.

func serviceIDs(core Core) (int, int, bool) {
	u := serviceUser(core)
	if u == "" || u == "root" {
		return 0, 0, false
	}
	pu, err := user.Lookup(u)
	if err != nil {
		return 0, 0, false
	}
	uid, _ := strconv.Atoi(pu.Uid)
	gid, _ := strconv.Atoi(pu.Gid)
	if g, _ := run(5*time.Second, "systemctl", "show", "-p", "Group", "--value", core.Service); strings.TrimSpace(g) != "" {
		if pg, err := user.LookupGroup(strings.TrimSpace(g)); err == nil {
			gid, _ = strconv.Atoi(pg.Gid)
		}
	}
	return uid, gid, true
}

// grantRead makes certFile/keyFile readable by the xray service user without
// moving them. Symlinks (certbot live/ → archive/) are followed.
func grantRead(certFile, keyFile string, gid int) {
	for _, f := range []string{certFile, keyFile} {
		real, err := filepath.EvalSymlinks(f)
		if err != nil {
			continue
		}
		for _, p := range []string{f, real} {
			dir := filepath.Dir(p)
			// the folder holding the files: group read+traverse
			_ = os.Chown(dir, 0, gid)
			_ = os.Chmod(dir, 0o750)
			// parents up to /etc: traverse only (no listing)
			for d := filepath.Dir(dir); d != "/" && d != "/etc" && d != "."; d = filepath.Dir(d) {
				if st, err := os.Stat(d); err == nil && st.Mode().Perm()&0o001 == 0 {
					_ = os.Chmod(d, st.Mode().Perm()|0o011)
				}
			}
		}
		_ = os.Chown(real, 0, gid)
		if f == keyFile {
			_ = os.Chmod(real, 0o640)
		} else {
			_ = os.Chmod(real, 0o644)
		}
	}
}

// xrayReadableCert returns the same paths, after giving xray read access.
func xrayReadableCert(certFile, keyFile string) (string, string, error) {
	core := DetectCore()
	if _, gid, ok := serviceIDs(core); ok {
		grantRead(certFile, keyFile, gid)
	}
	return certFile, keyFile, nil
}

type certPair struct{ cert, key string }

// tlsCertsInConfig lists every certificate pair referenced by an inbound.
func tlsCertsInConfig(root *OMap) []certPair {
	var out []certPair
	for _, v := range asArr(root.Get("inbounds")) {
		ib := asMap(v)
		for _, c := range asArr(path(ib, "streamSettings", "tlsSettings", "certificates")) {
			cm := asMap(c)
			if cm == nil {
				continue
			}
			cf, kf := asStr(cm.Get("certificateFile")), asStr(cm.Get("keyFile"))
			if cf != "" && kf != "" {
				out = append(out, certPair{cf, kf})
			}
		}
	}
	return out
}

// migrateCertCopies undoes v0.3.3's private copies: inbounds pointing at
// <configdir>/xray-one-certs/* go back to the original files.
func (a *App) migrateCertCopies() {
	core := DetectCore()
	root := filepath.Join(filepath.Dir(core.ConfigPath), "xray-one-certs")
	if _, err := os.Stat(root); err != nil {
		return
	}
	type src struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	m := map[string]string{}
	sjs, _ := filepath.Glob(filepath.Join(root, "*", "source.json"))
	for _, sj := range sjs {
		var s src
		b, _ := os.ReadFile(sj)
		if json.Unmarshal(b, &s) == nil && s.Cert != "" {
			d := filepath.Dir(sj)
			m[filepath.Join(d, "fullchain.pem")] = s.Cert
			m[filepath.Join(d, "privkey.pem")] = s.Key
		}
	}
	_, gid, ok := serviceIDs(core)
	err := a.cfg.Mutate(func(r *OMap) error {
		for _, v := range asArr(r.Get("inbounds")) {
			for _, c := range asArr(path(asMap(v), "streamSettings", "tlsSettings", "certificates")) {
				cm := asMap(c)
				if cm == nil {
					continue
				}
				cf, kf := m[asStr(cm.Get("certificateFile"))], m[asStr(cm.Get("keyFile"))]
				if cf != "" && kf != "" {
					if ok {
						grantRead(cf, kf, gid)
					}
					cm.Set("certificateFile", cf)
					cm.Set("keyFile", kf)
				}
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("cert migration: %v", err)
		return
	}
	if root2, _, err := a.cfg.Load(); err == nil {
		for _, p := range tlsCertsInConfig(root2) {
			if strings.HasPrefix(p.cert, root) {
				return // still in use, keep it
			}
		}
	}
	_ = os.RemoveAll(root)
}

// certSyncLoop keeps permissions right after every renewal and restarts xray
// once when a certificate it uses has changed.
func (a *App) certSyncLoop() {
	a.migrateCertCopies()
	seen := map[string][]byte{}
	first := true
	for {
		core := DetectCore()
		if root, _, err := a.cfg.Load(); err == nil {
			_, gid, ok := serviceIDs(core)
			changed := false
			for _, p := range tlsCertsInConfig(root) {
				data, err := os.ReadFile(p.cert)
				if err != nil {
					continue
				}
				if ok {
					grantRead(p.cert, p.key, gid)
				}
				if old, had := seen[p.cert]; had && !bytes.Equal(old, data) {
					changed = true
				}
				seen[p.cert] = data
			}
			if changed && !first && serviceActive(core) {
				log.Printf("certificate renewed, restarting %s", core.Service)
				_ = restartCore(core)
			}
		}
		first = false
		time.Sleep(time.Hour)
	}
}
