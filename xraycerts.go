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

// xray.service usually runs as a non-root user (nobody), which cannot read
// /etc/xray-one/certs or /etc/letsencrypt/live. For TLS inbounds we therefore
// give xray its own copy of the certificate, owned by the service user, next
// to its config, and keep that copy in sync when the source is renewed.

type certSource struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func xrayCertRoot(core Core) string {
	return filepath.Join(filepath.Dir(core.ConfigPath), "xray-one-certs")
}

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
	if g := strings.TrimSpace(func() string {
		o, _ := run(5*time.Second, "systemctl", "show", "-p", "Group", "--value", core.Service)
		return o
	}()); g != "" {
		if pg, err := user.LookupGroup(g); err == nil {
			gid, _ = strconv.Atoi(pg.Gid)
		}
	}
	return uid, gid, true
}

// xrayReadableCert returns certificate paths xray's service user can read.
// When xray runs as root the original paths are returned unchanged.
func xrayReadableCert(certFile, keyFile string) (string, string, error) {
	core := DetectCore()
	uid, gid, ok := serviceIDs(core)
	if !ok {
		return certFile, keyFile, nil
	}
	name := filepath.Base(filepath.Dir(certFile))
	if name == "" || name == "." || name == "/" {
		name = "default"
	}
	dir := filepath.Join(xrayCertRoot(core), name)
	if err := copyCert(dir, certSource{certFile, keyFile}, uid, gid); err != nil {
		return "", "", err
	}
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem"), nil
}

func copyCert(dir string, src certSource, uid, gid int) error {
	c, err := os.ReadFile(src.Cert)
	if err != nil {
		return err
	}
	k, err := os.ReadFile(src.Key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(dir), 0o755)
	_ = os.Chmod(dir, 0o750)
	_ = os.Chown(dir, 0, gid)
	for _, f := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{{"fullchain.pem", c, 0o644}, {"privkey.pem", k, 0o600}} {
		p := filepath.Join(dir, f.name)
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, f.data, f.mode); err != nil {
			return err
		}
		_ = os.Chmod(tmp, f.mode)
		_ = os.Chown(tmp, uid, gid)
		if err := os.Rename(tmp, p); err != nil {
			return err
		}
	}
	b, _ := json.Marshal(src)
	return os.WriteFile(filepath.Join(dir, "source.json"), b, 0o600)
}

// syncXrayCerts refreshes every copy whose source changed (renewal) and
// restarts xray once if anything was updated.
func syncXrayCerts() {
	core := DetectCore()
	uid, gid, ok := serviceIDs(core)
	if !ok {
		return
	}
	dirs, _ := filepath.Glob(filepath.Join(xrayCertRoot(core), "*", "source.json"))
	changed := false
	for _, sj := range dirs {
		var src certSource
		b, err := os.ReadFile(sj)
		if err != nil || json.Unmarshal(b, &src) != nil {
			continue
		}
		dir := filepath.Dir(sj)
		newC, err1 := os.ReadFile(src.Cert)
		oldC, _ := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
		if err1 != nil || bytes.Equal(newC, oldC) {
			continue
		}
		if err := copyCert(dir, src, uid, gid); err != nil {
			log.Printf("cert sync %s: %v", dir, err)
			continue
		}
		changed = true
	}
	if changed && serviceActive(core) {
		log.Printf("certificate renewed, restarting %s", core.Service)
		_ = restartCore(core)
	}
}

func certSyncLoop() {
	for {
		syncXrayCerts()
		time.Sleep(time.Hour)
	}
}
