package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

var version = "0.6.9"

func main() {
	dir := os.Getenv("XRAY_ONE_DIR")
	if dir == "" {
		dir = "/etc/xray-one"
	}
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		serve(dir)
	case "init":
		initDefaults(dir, true)
	case "", "menu", "setup":
		if cmd == "" && !term.IsTerminal(int(os.Stdin.Fd())) {
			serve(dir)
			return
		}
		runMenu(dir)
	case "detect":
		c := DetectCore()
		fmt.Printf("installed=%v version=%s service=%s config=%s api=%s\n", c.Installed, c.Version, c.Active, c.ConfigPath, c.APIAddr)
	case "update":
		if err := selfUpdate(); err != nil {
			fmt.Println("Update failed:", err)
			os.Exit(1)
		}
	case "agent":
		agentMain(os.Args[2:])
	case "uninstall":
		uninstall(dir)
	case "version", "-v", "--version":
		fmt.Println("XRay One", version)
	default:
		fmt.Println("usage: xray-one [menu|serve|update|uninstall|detect|version]")
	}
}

func serve(dir string) {
	app, err := NewApp(dir)
	if err != nil {
		log.Fatal(err)
	}
	if app.store.Cfg.User == "" {
		log.Fatal("no login configured yet: run `xray-one` first")
	}
	go app.Enforce()
	go app.certSyncLoop()
	go app.revLoop()
	app.graceLater()
	go app.traffic.loop()
	cfg := app.store.Cfg
	srv := &http.Server{Addr: cfg.Listen, ReadHeaderTimeout: 10 * time.Second}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		if _, err := os.Stat(cfg.CertFile); err == nil {
			r := &certReloader{certFile: cfg.CertFile, keyFile: cfg.KeyFile}
			srv.TLSConfig = &tls.Config{GetCertificate: r.Get, MinVersion: tls.VersionTLS12}
			app.tls = true
			if cfg.Managed && cfg.Domain != "" {
				go app.renewLoop(dir)
			}
			srv.Handler = app.Routes()
			log.Printf("XRay One %s on %s", version, app.PanelURL())
			log.Fatal(srv.ListenAndServeTLS("", ""))
		}
		log.Printf("certificate %s not found, serving plain HTTP", cfg.CertFile)
	}
	srv.Handler = app.Routes()
	log.Printf("XRay One %s on %s", version, app.PanelURL())
	log.Fatal(srv.ListenAndServe())
}

// renewLoop renews a certificate XRay One issued itself, 30 days before expiry.
func (a *App) renewLoop(dir string) {
	for {
		time.Sleep(time.Minute)
		cfg := a.store.Cfg
		if exp, _, err := certExpiry(cfg.CertFile); err == nil && time.Until(exp) < 30*24*time.Hour {
			if _, _, err := ObtainCert(dir, cfg.Domain, cfg.AcmeEmail, log.Printf); err != nil {
				log.Printf("certificate renewal failed: %v", err)
			}
		}
		time.Sleep(12 * time.Hour)
	}
}

func (a *App) PanelURL() string {
	c := a.store.Cfg
	scheme := "http"
	if a.tls || (c.CertFile != "" && c.KeyFile != "") {
		scheme = "https"
	}
	host := c.Domain
	if host == "" {
		host = c.PublicHost
	}
	if host == "" {
		host = "SERVER_IP"
	}
	return scheme + "://" + host + portOf(c.Listen) + c.BasePath
}

func portOf(listen string) string {
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i:]
	}
	return ""
}
