package main

// Several main servers on one middle server. Each main server gets its own
// agent instance: instance 1 keeps the original folder and service names,
// instance N uses /etc/xray-one-agent-N, xray-one-relay-N, xray-one-agent-N
// and its own control port, carrier services and GRE link name. Instances
// tell each other which ports they claim (claims.json), so they never take
// the same port, and each one reports every taken port to its main server.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// agentBaseDir: instance 1's folder (a var for tests).
var agentBaseDir = "/etc/xray-one-agent"

func setAgentInst(n int) {
	if n < 2 {
		n = 1
	}
	agentInst = n
	agentDir, agentRelay, agentUnit = agentDirOf(n), "xray-one-relay", "xray-one-agent"
	if n > 1 {
		sfx := "-" + strconv.Itoa(n)
		agentRelay += sfx
		agentUnit += sfx
	}
	agentKeyDir = agentDir
}

func agentDirOf(n int) string {
	if n < 2 {
		return agentBaseDir
	}
	return agentBaseDir + "-" + strconv.Itoa(n)
}

// instName: a service or link name for this instance ("xo-gre", "xo-gre2").
func instName(s string) string {
	if agentInst < 2 {
		return s
	}
	return s + strconv.Itoa(agentInst)
}

func instArg() string {
	if agentInst < 2 {
		return ""
	}
	return " --inst " + strconv.Itoa(agentInst)
}

// agentInsts: the installed instances, in order.
func agentInsts() []int {
	var out []int
	if _, err := os.Stat(filepath.Join(agentBaseDir, "agent.json")); err == nil {
		out = append(out, 1)
	}
	ds, _ := filepath.Glob(agentBaseDir + "-*")
	var more []int
	for _, d := range ds {
		n, err := strconv.Atoi(strings.TrimPrefix(d, agentBaseDir+"-"))
		if err != nil || n < 2 {
			continue
		}
		if _, err := os.Stat(filepath.Join(d, "agent.json")); err == nil {
			more = append(more, n)
		}
	}
	sort.Ints(more)
	return append(out, more...)
}

func loadAgentAt(n int) (agentState, error) {
	var s agentState
	b, err := os.ReadFile(filepath.Join(agentDirOf(n), "agent.json"))
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}

// claimedPorts: every port this instance's relay wants (listening or not)
// plus its control ports.
func claimedPorts(want []byte, ctl int) []int {
	var c struct {
		Inbounds []struct {
			Listen string `json:"listen"`
			Port   any    `json:"port"`
		} `json:"inbounds"`
	}
	seen := map[int]bool{}
	if json.Unmarshal(want, &c) == nil {
		for _, ib := range c.Inbounds {
			if strings.HasPrefix(ib.Listen, "127.") {
				continue
			}
			if f, ok := ib.Port.(float64); ok && f > 0 {
				seen[int(f)] = true
			}
		}
	}
	if ctl > 0 {
		seen[ctl], seen[ctl+1] = true, true
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func writeClaims(want []byte) {
	st, _ := loadAgent()
	ctl := st.Ctl
	if ctl == 0 {
		ctl = agentCtlPort
	}
	b, _ := json.Marshal(claimedPorts(want, ctl))
	p := filepath.Join(agentDir, "claims.json")
	if cur, _ := os.ReadFile(p); string(cur) != string(b) {
		_ = os.WriteFile(p, b, 0o600)
	}
}

// otherClaims: ports the other instances claim (only lower-numbered ones
// when lowerOnly: they win a port both want).
func otherClaims(lowerOnly bool) map[int]bool {
	out := map[int]bool{}
	for _, n := range agentInsts() {
		if n == agentInst || (lowerOnly && n > agentInst) {
			continue
		}
		var l []int
		if b, err := os.ReadFile(filepath.Join(agentDirOf(n), "claims.json")); err == nil {
			_ = json.Unmarshal(b, &l)
		}
		if st, err := loadAgentAt(n); err == nil && st.Ctl > 0 {
			l = append(l, st.Ctl, st.Ctl+1)
		}
		for _, p := range l {
			out[p] = true
		}
	}
	return out
}

// portHint: the range suggested to this instance's main server, only when
// the middle server serves more than one (20000-29999 for the first,
// 30000-39999 for the second …). A suggestion: nothing is forced.
func portHint() [2]int {
	if len(agentInsts()) < 2 {
		return [2]int{}
	}
	from := 10000 * (agentInst + 1)
	if from > 60000 {
		from = 60000
	}
	return [2]int{from, from + 9999}
}

// ---------- install: add or replace ----------

var ttyIn *bufio.Reader

func ask(q string) string {
	if ttyIn == nil {
		if f, err := os.Open("/dev/tty"); err == nil {
			ttyIn = bufio.NewReader(f)
		} else {
			ttyIn = bufio.NewReader(os.Stdin)
		}
	}
	fmt.Print(q)
	s, _ := ttyIn.ReadString('\n')
	return strings.TrimSpace(s)
}

func instLabel(n int) string {
	st, err := loadAgentAt(n)
	if err != nil {
		return fmt.Sprintf("main server %d", n)
	}
	return fmt.Sprintf("main server %d: %s", n, st.Join.Domain)
}

// agentInstallPick decides which instance a join code goes to: the one
// already serving the same main server, the first one on a fresh server,
// or (asked) a new one next to the others / in place of one of them.
func agentInstallPick(code, mode string) error {
	j, err := decodeJoin(code)
	if err != nil {
		return err
	}
	insts := agentInsts()
	for _, n := range insts {
		if st, err := loadAgentAt(n); err == nil && (st.Join.ID == j.ID || strings.EqualFold(st.Join.Domain, j.Domain)) {
			setAgentInst(n)
			return agentInstall(code)
		}
	}
	if len(insts) == 0 {
		setAgentInst(1)
		return agentInstall(code)
	}
	if mode == "" {
		fmt.Println("This middle server already serves:")
		for _, n := range insts {
			fmt.Println("  -", instLabel(n))
		}
		fmt.Println("  1) Add", j.Domain, "as another main server (the current ones keep working)")
		fmt.Println("  2) Replace a current main server with", j.Domain)
		switch ask("Choose [1]: ") {
		case "", "1":
			mode = "add"
		case "2":
			mode = "replace"
		default:
			return errors.New("nothing changed")
		}
	}
	if mode == "replace" {
		n := insts[0]
		if len(insts) > 1 {
			for _, m := range insts {
				fmt.Printf("  %d) %s\n", m, instLabel(m))
			}
			v, _ := strconv.Atoi(ask(fmt.Sprintf("Which one to replace [%d]: ", n)))
			if v > 0 {
				n = v
			}
		}
		if !containsInt(insts, n) {
			return errors.New("no such main server here")
		}
		setAgentInst(n)
		fmt.Printf("Replacing %s\n", instLabel(n))
		agentCarriersRemove()
		return agentInstall(code)
	}
	n := 2
	for containsInt(insts, n) {
		n++
	}
	setAgentInst(n)
	fmt.Printf("Adding %s as main server %d on this middle server\n", j.Domain, n)
	if err := agentInstall(code); err != nil {
		return err
	}
	if h := portHint(); h[0] > 0 {
		fmt.Printf("Ports already taken on this server are reported to both panels. Suggested range for main server %d: %d-%d (not forced).\n", n, h[0], h[1])
	}
	return nil
}

func containsInt(l []int, v int) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// agentRemove removes this instance; the shared Xray goes with the last one.
func agentRemove() {
	agentCarriersRemove()
	_, _ = run(20*time.Second, "systemctl", "disable", "--now", agentUnit, agentRelay)
	_ = os.Remove("/etc/systemd/system/" + agentUnit + ".service")
	_ = os.Remove("/etc/systemd/system/" + agentRelay + ".service")
	_ = os.RemoveAll(agentDir)
	if len(agentInsts()) == 0 {
		_ = os.RemoveAll(agentXrayDir)
	}
	_, _ = run(20*time.Second, "systemctl", "daemon-reload")
	if agentInst > 1 {
		fmt.Printf("Main server %d removed from this middle server.\n", agentInst)
	} else {
		fmt.Println("Tunnel agent removed.")
	}
}

// ---------- the middle server's SSH menu ----------

// agentMenu: `xray-one` on a middle server.
func agentMenu() {
	for {
		insts := agentInsts()
		fmt.Println()
		fmt.Println("  XRay One " + version + " · middle server")
		if len(insts) == 0 {
			fmt.Println("  Not connected to a main server yet.")
		}
		for _, n := range insts {
			setAgentInst(n)
			st, _ := loadAgent()
			relay, _ := run(5*time.Second, "systemctl", "is-active", agentRelay)
			ag, _ := run(5*time.Second, "systemctl", "is-active", agentUnit)
			link := "waiting"
			if st.Token != "" {
				link = "joined"
			}
			hint := ""
			if h := portHint(); h[0] > 0 {
				hint = fmt.Sprintf(" · suggested ports %d-%d", h[0], h[1])
			}
			fmt.Printf("  [%d] %s  relay %s · agent %s · %s · control port %d%s\n", n, st.Join.Domain,
				strings.TrimSpace(relay), strings.TrimSpace(ag), link, st.Ctl, hint)
		}
		fmt.Println()
		fmt.Println("   1) Add a main server (paste the install command or join code from its Tunnel tab)")
		fmt.Println("   2) Remove a main server")
		fmt.Println("   3) Ports in use on this server")
		fmt.Println("   4) Restart services")
		fmt.Println("   5) Recent log")
		fmt.Println("   0) Exit")
		switch ask("  › Choose: ") {
		case "1":
			code := ""
			for _, f := range strings.Fields(ask("Install command or join code: ")) {
				if _, err := decodeJoin(f); err == nil {
					code = f
				}
			}
			if code == "" {
				fmt.Println("No join code found in that text.")
				continue
			}
			if err := agentInstallPick(code, ""); err != nil {
				fmt.Println("Error:", err)
			}
		case "2":
			if len(insts) == 0 {
				continue
			}
			for _, n := range insts {
				fmt.Printf("  %d) %s\n", n, instLabel(n))
			}
			n, _ := strconv.Atoi(ask("Which one: "))
			if !containsInt(insts, n) {
				continue
			}
			if strings.ToLower(ask(fmt.Sprintf("Remove %s from this middle server? (y/N): ", instLabel(n)))) != "y" {
				continue
			}
			setAgentInst(n)
			agentRemove()
		case "3":
			agentShowPorts(insts)
		case "4":
			for _, n := range insts {
				setAgentInst(n)
				_, _ = run(30*time.Second, "systemctl", "restart", agentRelay, agentUnit)
			}
			fmt.Println("Restarted.")
		case "5":
			for _, n := range insts {
				setAgentInst(n)
				out, _ := run(10*time.Second, "journalctl", "-u", agentUnit, "-n", "15", "--no-pager")
				fmt.Printf("--- %s ---\n%s\n", instLabel(n), out)
			}
		case "0", "q", "":
			return
		}
	}
}

// agentShowPorts lists listening ports with who holds or claims them.
func agentShowPorts(insts []int) {
	claim := map[int][]string{}
	for _, n := range insts {
		var l []int
		if b, err := os.ReadFile(filepath.Join(agentDirOf(n), "claims.json")); err == nil {
			_ = json.Unmarshal(b, &l)
		}
		for _, p := range l {
			claim[p] = append(claim[p], "main server "+strconv.Itoa(n))
		}
	}
	ls := scanListeners()
	ports := map[int]bool{}
	for p, l := range ls {
		for _, x := range l {
			if x.tcp {
				ports[p] = true
			}
		}
	}
	for p := range claim {
		ports[p] = true
	}
	var all []int
	for p := range ports {
		all = append(all, p)
	}
	sort.Ints(all)
	fmt.Println("  Port   Held by / claimed by")
	for _, p := range all {
		who := ""
		if len(ls[p]) > 0 {
			u, name := portHolder(p)
			who = orDefault(u, name)
		} else {
			who = "(not listening now)"
		}
		if c := claim[p]; len(c) > 0 {
			who += " · " + strings.Join(c, ", ")
		}
		fmt.Printf("  %-6d %s\n", p, who)
	}
	fmt.Println("  Every port here is reported to each main server, which will not use it for another tunnel.")
}

func orInt(v, d int) int {
	if v == 0 {
		return d
	}
	return v
}
