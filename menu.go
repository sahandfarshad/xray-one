package main

// SSH (terminal) menu: everything about the panel itself lives here, so the
// installer asks nothing and the user changes things whenever they like.

import (
	"bufio"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const repo = "sahandfarshad/xray-one"

var stdin = bufio.NewReader(os.Stdin)

func prompt(q, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", q, def)
	} else {
		fmt.Printf("%s: ", q)
	}
	s, _ := stdin.ReadString('\n')
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}

func yes(q string) bool {
	a := strings.ToLower(prompt(q+" (y/N)", ""))
	return a == "y" || a == "yes"
}

func readSecret(q string) string {
	fmt.Print(q + ": ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return string(b)
	}
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}

func randPassword(n int) string {
	const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = crand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

// suggestPort returns a random port that is free on the system and unused
// by any Xray inbound.
func suggestPort() int {
	used := map[string]bool{}
	if root, _, err := (&ConfigStore{}).Load(); err == nil {
		used = usedPorts(root)
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 200; i++ {
		p := 20000 + r.Intn(40000)
		if !used[strconv.Itoa(p)] && portFree(p) {
			return p
		}
	}
	return 0
}

func publicIP() string {
	c := &http.Client{Timeout: 5 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		resp, err := c.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if ip := strings.TrimSpace(string(b)); ip != "" && resp.StatusCode == 200 {
			return ip
		}
	}
	return ""
}

func setPassword(st *Store, pass string) {
	h, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	st.Cfg.PassHash = string(h)
}

// initDefaults gives a fresh install working settings without questions.
func initDefaults(dir string, verbose bool) {
	st, err := OpenStore(dir)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if st.Cfg.User != "" && st.Cfg.PassHash != "" {
		if verbose {
			fmt.Println("Existing settings kept.")
		}
		return
	}
	port := suggestPort()
	pass := randPassword(12)
	st.Cfg.User = "admin"
	setPassword(st, pass)
	st.Cfg.Listen = fmt.Sprintf("0.0.0.0:%d", port)
	st.Cfg.BasePath = "/" + randHex(6) + "/"
	if st.Cfg.PublicHost == "" {
		st.Cfg.PublicHost = publicIP()
	}
	if err := st.SaveCfg(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	app := &App{store: st}
	fmt.Println()
	fmt.Println("  XRay One is ready")
	fmt.Println("  ─────────────────────────────────────────")
	fmt.Println("  URL:      " + app.PanelURL())
	fmt.Println("  Username: admin")
	fmt.Println("  Password: " + pass)
	fmt.Println("  ─────────────────────────────────────────")
	fmt.Println("  Save the password now. Change it any time with: xray-one")
	fmt.Println()
}

func svc(args ...string) string {
	out, _ := run(30*time.Second, "systemctl", args...)
	return out
}

func restartPanel() {
	if _, err := exec.LookPath("systemctl"); err == nil {
		svc("restart", "xray-one")
		fmt.Println("Panel restarted.")
	}
}

func runMenu(dir string) {
	initDefaults(dir, false)
	for {
		st, err := OpenStore(dir)
		if err != nil {
			fmt.Println(err)
			return
		}
		app := &App{store: st}
		c := DetectCore()
		drawMenu(app, c)
		choice := prompt("  "+bold("›")+" Choose", "")
		fmt.Println()
		switch choice {
		case "1":
			st.Cfg.User = prompt("Username", st.Cfg.User)
			p := readSecret("New password (empty = keep, min 8 chars)")
			if p != "" {
				if len(p) < 8 || readSecret("Repeat password") != p {
					fmt.Println("Too short or not matching. Password not changed.")
				} else {
					setPassword(st, p)
				}
			}
			saveAndRestart(st)
		case "2":
			cur := strings.TrimPrefix(portOf(st.Cfg.Listen), ":")
			sug := suggestPort()
			p, err := strconv.Atoi(prompt(fmt.Sprintf("New port (current %s, free suggestion)", cur), strconv.Itoa(sug)))
			if err != nil || p < 1 || p > 65535 {
				fmt.Println("Invalid port.")
				continue
			}
			if strconv.Itoa(p) != cur && !portFree(p) {
				fmt.Printf("Port %d is already in use by another program. Nothing changed.\n", p)
				continue
			}
			host := "0.0.0.0"
			if strings.HasPrefix(st.Cfg.Listen, "127.0.0.1") {
				host = "127.0.0.1"
			}
			st.Cfg.Listen = fmt.Sprintf("%s:%d", host, p)
			saveAndRestart(st)
		case "3":
			st.Cfg.BasePath = normBase(prompt("Secret path", "/"+randHex(6)+"/"))
			saveAndRestart(st)
		case "4":
			sslMenu(dir, st)
		case "5":
			pub := !strings.HasPrefix(st.Cfg.Listen, "127.0.0.1")
			def := "1"
			if !pub {
				def = "2"
			}
			fmt.Println("  1) Public   – open from anywhere (0.0.0.0)")
			fmt.Println("  2) Private  – only through an SSH tunnel (127.0.0.1)")
			mode := prompt("  Access", def)
			port := strings.TrimPrefix(portOf(st.Cfg.Listen), ":")
			if mode == "2" {
				st.Cfg.Listen = "127.0.0.1:" + port
			} else {
				st.Cfg.Listen = "0.0.0.0:" + port
			}
			st.Cfg.PublicHost = prompt("  Domain or IP used in client links", orDefault(st.Cfg.PublicHost, publicIP()))
			saveAndRestart(st)
		case "6":
			v := asciiDigits(prompt("Version (empty = latest)", ""))
			if v != "" && !strings.HasPrefix(v, "v") {
				v = "v" + v
			}
			coreInstallCLI(v)
		case "7":
			restartPanel()
		case "8":
			cmd := exec.Command("journalctl", "-u", "xray-one", "-n", "40", "--no-pager")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			_ = cmd.Run()
		case "9":
			if err := selfUpdate(); err != nil {
				fmt.Println("Update failed:", err)
			} else {
				fmt.Println("Updated. Run `xray-one` again to open the new menu.")
				return
			}
		case "10":
			uninstall(dir)
			return
		case "0", "q", "exit":
			clearScreen()
			return
		default:
			continue
		}
		fmt.Print("\n  " + dim("Press Enter to go back…"))
		stdin.ReadString('\n')
	}
}

const (
	cReset = "\033[0m"
	cBold  = "\033[1m"
	cDim   = "\033[2m"
	cCyan  = "\033[36m"
	cGreen = "\033[32m"
	cRed   = "\033[31m"
	cYel   = "\033[33m"
)

func bold(s string) string { return cBold + s + cReset }
func dim(s string) string  { return cDim + s + cReset }
func clearScreen()         { fmt.Print("\033[H\033[2J") }

func dot(ok bool, label string) string {
	if ok {
		return cGreen + "● " + label + cReset
	}
	return cRed + "● " + label + cReset
}

func drawMenu(app *App, c Core) {
	clearScreen()
	cfg := app.store.Cfg
	panelState := svc("is-active", "xray-one")
	access := cYel + "private (SSH tunnel only)" + cReset
	if !strings.HasPrefix(cfg.Listen, "127.0.0.1") {
		access = "public"
	}
	ssl := cYel + "off" + cReset
	if cfg.CertFile != "" {
		ssl = cfg.Domain
		if exp, _, err := certExpiry(cfg.CertFile); err == nil {
			ssl += dim("  until " + exp.Format("2006-01-02"))
		}
	}
	core := cRed + "not installed" + cReset
	if c.Installed {
		core = c.Version + "  " + dot(c.Active == "active", orDefault(c.Active, "unknown"))
	}
	const w = 49
	title, ver := "✦ XRay One", "v"+version
	pad := w - 2 - len([]rune(title)) - len(ver)
	if pad < 1 {
		pad = 1
	}
	fmt.Println()
	fmt.Println("  " + dim("╭"+strings.Repeat("─", w)+"╮"))
	fmt.Println("  " + dim("│") + " " + cCyan + cBold + title + cReset + strings.Repeat(" ", pad) + dim(ver) + " " + dim("│"))
	fmt.Println("  " + dim("╰"+strings.Repeat("─", w)+"╯"))
	row := func(k, v string) { fmt.Printf("   %s%-7s%s %s\n", cDim, k, cReset, v) }
	row("Panel", app.PanelURL()+"  "+dot(panelState == "active", orDefault(panelState, "?")))
	if panelState != "active" {
		if out, _ := run(5*time.Second, "journalctl", "-u", "xray-one", "-n", "1", "--no-pager", "-o", "cat"); out != "" {
			row("", cRed+out+cReset)
		}
	}
	row("Access", access)
	row("User", cfg.User)
	if cfg.BasePath == "" || cfg.BasePath == "/" {
		row("", cYel+"No secret path set: option 3 is recommended"+cReset)
	}
	row("SSL", ssl)
	row("Xray", core)
	section := func(name string) {
		fmt.Println()
		fmt.Println("   " + cDim + cBold + name + cReset + " " + dim(strings.Repeat("─", w-len(name))))
	}
	item := func(n, label string) { fmt.Printf("   %s%3s%s  %s %s\n", cCyan+cBold, n, cReset, dim("│"), label) }
	section("PANEL")
	item("1", "Username / password")
	item("2", "Panel port")
	item("3", "Secret path")
	item("4", "SSL certificate")
	item("5", "Access & link address")
	section("SYSTEM")
	item("6", "Install / update Xray")
	item("7", "Restart panel")
	item("8", "Logs")
	item("9", "Update XRay One")
	item("10", cRed+"Uninstall XRay One"+cReset)
	fmt.Println()
	item("0", dim("Exit"))
	fmt.Println()
}

func saveAndRestart(st *Store) {
	if err := st.SaveCfg(); err != nil {
		fmt.Println("Save failed:", err)
		return
	}
	fmt.Println("Saved.")
	restartPanel()
}

func sslMenu(dir string, st *Store) {
	found := FindCerts(dir)
	fmt.Println()
	fmt.Println("  SSL for the panel and subscription links")
	fmt.Println("   1) Get a new certificate from Let's Encrypt (needs a domain pointing here and port 80)")
	if len(found) > 0 {
		fmt.Println("   2) Use a certificate already on this server:")
		for i, f := range found {
			fmt.Printf("        %c) %s  [%s, expires %s]\n", 'a'+i, f.Domain, f.Source, f.Expires.Format("2006-01-02"))
		}
	}
	fmt.Println("   3) Turn SSL off")
	fmt.Println("   0) Back")
	switch prompt("Choose", "") {
	case "1":
		dom := strings.ToLower(prompt("Domain", st.Cfg.Domain))
		if dom == "" {
			return
		}
		email := prompt("Email for Let's Encrypt notices (optional)", st.Cfg.AcmeEmail)
		back, ok := free80Menu()
		if !ok {
			return
		}
		cf, kf, err := ObtainCert(dir, dom, email, func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) })
		back()
		if err != nil {
			fmt.Println("Could not get a certificate:", err)
			return
		}
		st.Cfg.Domain, st.Cfg.AcmeEmail, st.Cfg.CertFile, st.Cfg.KeyFile, st.Cfg.Managed = dom, email, cf, kf, true
		if st.Cfg.PublicHost == "" {
			st.Cfg.PublicHost = dom
		}
		fmt.Println("Done. The panel renews it automatically before it expires.")
		saveAndRestart(st)
	case "2":
		if len(found) == 0 {
			return
		}
		ch := prompt("Which one (a, b, …)", "a")
		i := int(ch[0] - 'a')
		if i < 0 || i >= len(found) {
			fmt.Println("Invalid choice.")
			return
		}
		f := found[i]
		st.Cfg.Domain, st.Cfg.CertFile, st.Cfg.KeyFile, st.Cfg.Managed = f.Domain, f.CertFile, f.KeyFile, f.Source == "xray-one"
		fmt.Printf("Using %s. When %s renews it, the panel picks up the new file by itself.\n", f.Domain, f.Source)
		saveAndRestart(st)
	case "3":
		st.Cfg.CertFile, st.Cfg.KeyFile, st.Cfg.Managed = "", "", false
		saveAndRestart(st)
	}
}

// free80Menu: when port 80 is busy, says who holds it and offers to pause
// that service for the minute Let's Encrypt needs; the returned func starts
// it again.
func free80Menu() (func(), bool) {
	nop := func() {}
	if portFree(80) {
		return nop, true
	}
	unit, name := portHolder(80)
	if unit == "" {
		fmt.Printf("Port 80 is used by %s, which is not a service that can be paused.\n", name)
		fmt.Println("Stop it for a minute and choose this option again.")
		return nop, false
	}
	fmt.Printf("Port 80 is used by %s (%s).\n", unit, name)
	low := strings.ToLower(unit)
	switch {
	case unit == "xray-one.service":
		fmt.Println("That is this panel's game unblocker entry; the panel stops for about a minute.")
	case strings.Contains(low, "xray") || strings.Contains(low, "x-ui") || strings.Contains(low, "sing-box") || strings.Contains(low, "marzban"):
		fmt.Println("Warning: this is a proxy core, so its users are cut off for about a minute.")
	}
	if !yes("Pause it, get the certificate, and start it again") {
		return nop, false
	}
	back, err := pauseUnit(unit, func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) })
	if err != nil {
		fmt.Println(err)
		return nop, false
	}
	return back, true
}

// asciiDigits turns Persian and Arabic digits (and the Arabic decimal
// separator) into plain ones, so "۲۶.۱۱.۹" works as a version.
func asciiDigits(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '۰' && r <= '۹':
			return '0' + (r - '۰')
		case r >= '٠' && r <= '٩':
			return '0' + (r - '٠')
		case r == '٫':
			return '.'
		}
		return r
	}, s)
}

func coreInstallCLI(v string) {
	if v == "" {
		if v = latestXrayTag(); v != "" {
			fmt.Println("Latest Xray:", v)
		}
	}
	line := "curl -fsSL " + installScript + " -o /tmp/xray-install.sh && bash /tmp/xray-install.sh install"
	if v != "" {
		line += " --version " + v
	}
	cmd := exec.Command("bash", "-c", line)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("Xray install/update failed:", err)
		return
	}
	svc("enable", "xray")
	svc("restart", "xray")
	fmt.Println("Xray is ready:", DetectCore().Version)
}

// selfUpdate downloads the latest release, checks its SHA256 and swaps the binary.
func selfUpdate() error {
	arch := runtime.GOARCH
	name := "xray-one-linux-" + arch
	base := "https://github.com/" + repo + "/releases/latest/download/"
	get := func(u string) ([]byte, error) {
		c := &http.Client{Timeout: 2 * time.Minute}
		resp, err := c.Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%s: %s", u, resp.Status)
		}
		return io.ReadAll(resp.Body)
	}
	fmt.Println("Downloading", name, "…")
	bin, err := get(base + name)
	if err != nil {
		return err
	}
	sums, err := get(base + "SHA256SUMS")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	if !strings.Contains(string(sums), hex.EncodeToString(sum[:])+"  "+name) {
		return errors.New("checksum mismatch, update cancelled")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		return err
	}
	out, _ := run(5*time.Second, exe, "version")
	fmt.Println("Installed:", out)
	restartPanel()
	return nil
}

func uninstall(dir string) {
	fmt.Println("This removes the XRay One panel only. Xray and its config stay exactly as they are.")
	if !yes("Uninstall XRay One?") {
		return
	}
	svc("disable", "--now", "xray-one")
	os.Remove("/etc/systemd/system/xray-one.service")
	svc("daemon-reload")
	if yes("Also delete panel data (" + dir + ": login, client limits, backups, certificates)?") {
		os.RemoveAll(dir)
	}
	if exe, err := os.Executable(); err == nil {
		os.Remove(exe)
	}
	fmt.Println("XRay One removed.")
}
