package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

var version = "0.1.0"

func main() {
	dir := os.Getenv("XRAY_ONE_DIR")
	if dir == "" {
		dir = "/etc/xray-one"
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "setup":
			runSetup(dir)
			return
		case "version", "-v", "--version":
			fmt.Println("XRay One", version)
			return
		case "detect":
			c := DetectCore()
			fmt.Printf("installed=%v version=%s service=%s config=%s api=%s\n", c.Installed, c.Version, c.Active, c.ConfigPath, c.APIAddr)
			return
		case "serve":
		default:
			fmt.Println("usage: xray-one [serve|setup|detect|version]")
			return
		}
	}
	app, err := NewApp(dir)
	if err != nil {
		log.Fatal(err)
	}
	if app.store.Cfg.User == "" {
		log.Fatal("no login configured yet: run `xray-one setup` first")
	}
	go app.Enforce()
	cfg := app.store.Cfg
	srv := &http.Server{Addr: cfg.Listen, ReadHeaderTimeout: 10 * time.Second}
	switch {
	case cfg.Domain != "":
		m := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Cache: autocert.DirCache(filepath.Join(dir, "certs"))}
		go func() {
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				log.Printf("ACME http-01 listener on :80 failed (%v); certificate issuance needs port 80", err)
			}
		}()
		srv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS12}
		app.tls = true
		srv.Handler = app.Routes()
		log.Printf("XRay One %s on https://%s%s%s", version, cfg.Domain, portOf(cfg.Listen), cfg.BasePath)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	case cfg.CertFile != "" && cfg.KeyFile != "":
		app.tls = true
		srv.Handler = app.Routes()
		log.Printf("XRay One %s on https://%s%s", version, cfg.Listen, cfg.BasePath)
		log.Fatal(srv.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile))
	default:
		srv.Handler = app.Routes()
		log.Printf("XRay One %s on http://%s%s", version, cfg.Listen, cfg.BasePath)
		log.Fatal(srv.ListenAndServe())
	}
}

func portOf(listen string) string {
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i:]
	}
	return ""
}

func runSetup(dir string) {
	st, err := OpenStore(dir)
	if err != nil {
		log.Fatal(err)
	}
	in := bufio.NewReader(os.Stdin)
	ask := func(q, def string) string {
		if def != "" {
			fmt.Printf("%s [%s]: ", q, def)
		} else {
			fmt.Printf("%s: ", q)
		}
		s, _ := in.ReadString('\n')
		s = strings.TrimSpace(s)
		if s == "" {
			return def
		}
		return s
	}
	fmt.Println("XRay One setup")
	c := &st.Cfg
	c.User = ask("Username", orDefault(c.User, "admin"))
	for {
		readPw := func() []byte {
			if term.IsTerminal(int(os.Stdin.Fd())) {
				b, _ := term.ReadPassword(int(os.Stdin.Fd()))
				return b
			}
			s, _ := in.ReadString('\n')
			return []byte(strings.TrimSpace(s))
		}
		fmt.Print("Password (min 8 chars): ")
		p1 := readPw()
		fmt.Print("\nRepeat password: ")
		p2 := readPw()
		fmt.Println()
		if len(p1) >= 8 && string(p1) == string(p2) {
			h, _ := bcrypt.GenerateFromPassword(p1, bcrypt.DefaultCost)
			c.PassHash = string(h)
			break
		}
		fmt.Println("Passwords do not match or are too short.")
	}
	c.Listen = ask("Listen address (127.0.0.1:PORT keeps it private, 0.0.0.0:PORT opens it)", c.Listen)
	c.BasePath = normBase(ask("Secret base path (e.g. /"+randHex(4)+"/)", c.BasePath))
	c.PublicHost = ask("Server domain or IP used in client links", c.PublicHost)
	c.Domain = ask("Domain for automatic Let's Encrypt SSL (empty = none)", c.Domain)
	if c.Domain == "" {
		c.CertFile = ask("TLS certificate file (empty = plain HTTP)", c.CertFile)
		if c.CertFile != "" {
			c.KeyFile = ask("TLS key file", c.KeyFile)
		}
	}
	if err := st.SaveCfg(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Saved. Restart with: systemctl restart xray-one")
}
