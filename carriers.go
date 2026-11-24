package main

// GRE, FRP, Backhaul and SSH: four more methods of the rotating tunnel. They
// carry the middle server's VLESS (plain, inside them) like WireGuard does,
// and land on the same local VLESS inbound on this server (xo-tunnel-wgv on
// 127.0.0.1). A middle server uses one method at a time and rotates to the
// others in its pool when it cannot reach us, exactly like WS/XHTTP/REALITY.
//
//   GRE:      a kernel GRE link per middle server. The middle server dials
//             10.78.0.1:V inside it; xo-tunnel-gre listens there.
//   FRP:      frps on the middle server, frpc here dials it (main -> middle,
//             like the reverse path) and opens 127.0.0.1:L there, forwarded
//             to 127.0.0.1:V here. Protocol tcp, kcp, quic or websocket;
//             optionally over the GRE link.
//   Backhaul: the same with Backhaul (server there, client here); tcpmux,
//             tcp, wsmux or ws; optionally over the GRE link.
//   SSH:      a small SSH server built into the agent; this server logs in
//             with its own key and asks for a remote forward of 127.0.0.1:L
//             (traffic looks like plain SSH). No extra program.
//
// Processes are pre-armed for every method in a middle server's pool, on both
// sides, so a switch is instant.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tunnelMethodGRE = "gre"
	tunnelMethodFRP = "frp"
	tunnelMethodBH  = "backhaul"
	tunnelMethodSSH = "ssh"
	tunnelTagGRE    = "xo-tunnel-gre" // VLESS on 10.78.0.1, reached through GRE
	greMain         = "10.78.0.1"     // this server inside every GRE link
	greNet          = "10.78.0."      // middle servers: .N (N = their WireGuard number)
	agentCarrierVer = "0.9.0"
	frpVer          = "0.72.0"
	bhVer           = "v0.7.2"
)

// the local port on the middle server each forwarding method opens
var carrierLocal = map[string]int{tunnelMethodFRP: 10887, tunnelMethodBH: 10888, tunnelMethodSSH: 10889}

var frpProtos = []string{"tcp", "kcp", "quic", "websocket"}
var bhProtos = []string{"tcpmux", "tcp", "wsmux", "ws"}

// allMethods: every method of the rotating tunnel, in card order.
var allMethods = []string{tunnelMethodWS, tunnelMethodXHTTP, tunnelMethodRT, tunnelMethodWG, tunnelMethodKCP,
	tunnelMethodGRE, tunnelMethodFRP, tunnelMethodBH, tunnelMethodSSH}

func isCarrier(m string) bool {
	return m == tunnelMethodGRE || m == tunnelMethodFRP || m == tunnelMethodBH || m == tunnelMethodSSH
}

func inList(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// greNum: a middle server's number in the GRE links (from its WireGuard address).
func greNum(s TunnelServer) int {
	if !strings.HasPrefix(s.WGAddr, wgPeerNet) {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimPrefix(s.WGAddr, wgPeerNet))
	if n < 2 || n > 254 {
		return 0
	}
	return n
}

// ---------- what each side runs ----------

type greSpec struct {
	Remote string `json:"remote"` // the other end's public IP
	Addr   string `json:"addr"`   // our address inside the link
	Peer   string `json:"peer"`   // theirs
}

type frpSpec struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Token string `json:"token"`
	Local int    `json:"local"` // 127.0.0.1:Local on the middle server
}

type bhSpec struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Token  string `json:"token"`
	Local  int    `json:"local"`
	Target int    `json:"target"` // 127.0.0.1:Target on this server
}

type sshSpec struct {
	Port  int    `json:"port"`
	Local int    `json:"local"`
	Auth  string `json:"auth"` // this server's public key (authorized_keys line)
}

type carrierSpec struct {
	GRE *greSpec `json:"gre,omitempty"`
	FRP *frpSpec `json:"frp,omitempty"`
	BH  *bhSpec  `json:"bh,omitempty"`
	SSH *sshSpec `json:"ssh,omitempty"`
}

// carrierWanted: which of the four a middle server should have armed now
// (the active method, and every other in its pool it can run).
func carrierWanted(s TunnelServer, set TunnelSettings) map[string]bool {
	w := map[string]bool{}
	if !set.WGOn || set.WGVPort == 0 {
		return w
	}
	if s.AgentVer == "" && s.Method == tunnelMethodGRE {
		// not connected yet and starting on GRE: only this end of the link
		if s.PublicIP != "" && greNum(s) != 0 && mainGREIP(set) != "" {
			w[tunnelMethodGRE] = true
		}
		return w
	}
	if s.AgentVer == "" || versionLess(s.AgentVer, agentCarrierVer) {
		return w
	}
	for _, m := range []string{tunnelMethodGRE, tunnelMethodFRP, tunnelMethodBH, tunnelMethodSSH} {
		if s.Method == m || s.PrevMethod == m || inPool(s, m) {
			w[m] = true
		}
	}
	if s.PublicIP == "" || greNum(s) == 0 || mainGREIP(set) == "" {
		delete(w, tunnelMethodGRE)
	}
	return w
}

// needsGRE: the GRE link itself is up for this server (its own method, or FRP
// / Backhaul set to run over it).
func needsGRE(s TunnelServer, set TunnelSettings, w map[string]bool) bool {
	if s.PublicIP == "" || greNum(s) == 0 || mainGREIP(set) == "" {
		return false
	}
	return w[tunnelMethodGRE] || (w[tunnelMethodFRP] && set.FRPGre) || (w[tunnelMethodBH] && set.BHGre)
}

// mainGREIP: this server's public IP for GRE (an IP, never a domain).
func mainGREIP(set TunnelSettings) string {
	h := set.WGHost
	if ip := net.ParseIP(h); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	if h != "" {
		if ips, err := net.LookupIP(h); err == nil {
			for _, ip := range ips {
				if ip.To4() != nil {
					return ip.String()
				}
			}
		}
	}
	return ""
}

// carrierSpecFor: what the middle server runs (sent with every heartbeat).
func (a *App) carrierSpecFor(s TunnelServer) *carrierSpec {
	_, set, _ := a.store.TunnelsCopy()
	sp := &carrierSpec{}
	w := carrierWanted(s, set)
	if needsGRE(s, set, w) {
		sp.GRE = &greSpec{Remote: mainGREIP(set), Addr: greNet + strconv.Itoa(greNum(s)), Peer: greMain}
	}
	if w[tunnelMethodFRP] && set.FRPPort > 0 {
		sp.FRP = &frpSpec{Port: set.FRPPort, Proto: set.FRPProto, Token: set.FRPTok, Local: carrierLocal[tunnelMethodFRP]}
	}
	if w[tunnelMethodBH] && set.BHPort > 0 {
		sp.BH = &bhSpec{Port: set.BHPort, Proto: set.BHProto, Token: set.BHTok, Local: carrierLocal[tunnelMethodBH], Target: set.WGVPort}
	}
	if w[tunnelMethodSSH] && set.SSHPort > 0 {
		if _, pub, err := panelSigner(a.store.dir); err == nil {
			sp.SSH = &sshSpec{Port: set.SSHPort, Local: carrierLocal[tunnelMethodSSH], Auth: pub}
		}
	}
	return sp
}

// carrierJoin fills j for a carrier method; false when it is not ready.
func (a *App) carrierJoin(j *joinInfo, s TunnelServer, set TunnelSettings) bool {
	if !set.WGOn || set.WGVPort == 0 {
		return false
	}
	switch s.Method {
	case tunnelMethodGRE:
		ip := mainGREIP(set)
		if greNum(s) == 0 || ip == "" || s.PublicIP == "" {
			return false
		}
		j.CAddr, j.CPort = greMain, set.WGVPort
		j.GRemote, j.GAddr = ip, greNet+strconv.Itoa(greNum(s))
	case tunnelMethodFRP:
		if set.FRPPort == 0 {
			return false
		}
		j.CAddr, j.CPort = "127.0.0.1", carrierLocal[s.Method]
	case tunnelMethodBH:
		if set.BHPort == 0 {
			return false
		}
		j.CAddr, j.CPort = "127.0.0.1", carrierLocal[s.Method]
	case tunnelMethodSSH:
		if set.SSHPort == 0 {
			return false
		}
		j.CAddr, j.CPort = "127.0.0.1", carrierLocal[s.Method]
	default:
		return false
	}
	return true
}

// carrierOutbound: plain VLESS to where the carrier delivers it (never a
// public address, so Xray allows it without TLS).
func carrierOutbound(j joinInfo, tag string) []any {
	return []any{om("tag", tag, "protocol", "vless",
		"settings", om("vnext", []any{om("address", j.CAddr, "port", j.CPort,
			"users", []any{om("id", j.UUID, "encryption", "none")})}),
		"streamSettings", om("network", "raw", "security", "none"))}
}

// ensureCarrierSettings: ports (on the middle servers), protocols and tokens.
func (a *App) ensureCarrierSettings(root *OMap) {
	_ = a.store.EditTunnels(func() error {
		c := &a.store.TunnelCfg
		if !inList(frpProtos, c.FRPProto) {
			c.FRPProto = "tcp"
		}
		if !inList(bhProtos, c.BHProto) {
			c.BHProto = "tcpmux"
		}
		if c.FRPTok == "" {
			c.FRPTok = randHex(16)
		}
		if c.BHTok == "" {
			c.BHTok = randHex(16)
		}
		taken := map[int]bool{c.Port: true, c.XPort: true, c.RPort: true, c.WGPort: true, c.KPort: true}
		pick := func(p *int) {
			for i := 0; *p == 0 && i < 50; i++ {
				if n := suggestPort(); n != 0 && !taken[n] {
					*p = n
				}
			}
			taken[*p] = true
		}
		pick(&c.FRPPort)
		pick(&c.BHPort)
		pick(&c.SSHPort)
		return nil
	})
}

// applyCarriers arms the GRE inbound when some middle server needs it, and
// this server's GRE prerequisites. It returns the inbound tags to allow.
func (a *App) applyCarriers(root *OMap, servers []TunnelServer) []any {
	a.ensureCarrierSettings(root)
	servers, set, _ := a.store.TunnelsCopy()
	need := false
	for _, s := range servers {
		w := carrierWanted(s, set)
		if needsGRE(s, set, w) || (s.Method == tunnelMethodGRE) {
			need = true
		}
	}
	if !need || !set.WGOn || set.WGVPort == 0 {
		removeInboundTag(root, tunnelTagGRE)
		return nil
	}
	greHostPrep()
	var clients []any
	for _, s := range servers {
		clients = append(clients, om("id", s.UUID, "email", "tunnel-"+s.ID, "level", 0))
	}
	ib := armInbound(root, tunnelTagGRE, set.WGVPort)
	ib.Set("listen", greMain)
	ib.Set("settings", om("clients", clients, "decryption", "none"))
	ib.Set("streamSettings", om("network", "raw", "security", "none"))
	return []any{tunnelTagGRE}
}

// greHostPrep: 10.78.0.1 lives on lo, and Xray may bind it even before
// (nonlocal bind), so a reboot never stops Xray.
func greHostPrep() {
	_, _ = run(5*time.Second, "modprobe", "ip_gre")
	_, _ = run(5*time.Second, "sysctl", "-qw", "net.ipv4.ip_nonlocal_bind=1")
	_ = os.WriteFile("/etc/sysctl.d/90-xray-one-gre.conf", []byte("net.ipv4.ip_nonlocal_bind = 1\n"), 0o644)
	if out, _ := run(5*time.Second, "ip", "-4", "addr", "show", "dev", "lo"); !strings.Contains(out, greMain+"/32") {
		_, _ = run(5*time.Second, "ip", "addr", "add", greMain+"/32", "dev", "lo")
	}
}

// ---------- links and programs (both sides) ----------

// greLink makes sure GRE interface dev goes to remote, with addr ours and
// peer theirs ("" addr: this server, whose address lives on lo).
func greLink(dev, remote, addr, peer string) error {
	out, _ := run(5*time.Second, "ip", "-d", "link", "show", "dev", dev)
	if out == "" || !strings.Contains(out, "remote "+remote+" ") {
		if out != "" {
			_, _ = run(5*time.Second, "ip", "link", "del", dev)
		}
		_, _ = run(5*time.Second, "modprobe", "ip_gre")
		if o, err := run(5*time.Second, "ip", "tunnel", "add", dev, "mode", "gre", "remote", remote, "ttl", "255"); err != nil {
			return fmt.Errorf("GRE: %s", orDefault(o, err.Error()))
		}
	}
	if addr != "" {
		if o, _ := run(5*time.Second, "ip", "-4", "addr", "show", "dev", dev); !strings.Contains(o, addr+"/32") {
			_, _ = run(5*time.Second, "ip", "addr", "add", addr+"/32", "dev", dev)
		}
	}
	_, _ = run(5*time.Second, "ip", "link", "set", dev, "mtu", "1476", "up")
	src := addr
	if src == "" {
		src = greMain
	}
	if o, err := run(5*time.Second, "ip", "route", "replace", peer+"/32", "dev", dev, "src", src); err != nil {
		return fmt.Errorf("GRE route: %s", orDefault(o, err.Error()))
	}
	// let GRE in where a firewall drops by default (best effort)
	for _, r := range [][]string{{"-p", "gre", "-s", remote, "-j", "ACCEPT"}, {"-i", dev, "-j", "ACCEPT"}} {
		if _, err := run(5*time.Second, "iptables", append([]string{"-C", "INPUT"}, r...)...); err != nil {
			_, _ = run(5*time.Second, "iptables", append([]string{"-I", "INPUT"}, r...)...)
		}
	}
	return nil
}

func greDrop(dev string) {
	out, _ := run(5*time.Second, "ip", "-d", "link", "show", "dev", dev)
	if out == "" {
		return
	}
	if i := strings.Index(out, "remote "); i >= 0 {
		remote := strings.Fields(out[i+7:])[0]
		_, _ = run(5*time.Second, "iptables", "-D", "INPUT", "-p", "gre", "-s", remote, "-j", "ACCEPT")
	}
	_, _ = run(5*time.Second, "iptables", "-D", "INPUT", "-i", dev, "-j", "ACCEPT")
	_, _ = run(5*time.Second, "ip", "link", "del", dev)
}

// greLinks: our GRE interfaces with prefix.
func greLinks(prefix string) []string {
	out, _ := run(5*time.Second, "ip", "-o", "link", "show")
	var l []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		name, _, _ = strings.Cut(name, "@")
		if strings.HasPrefix(name, prefix) {
			l = append(l, name)
		}
	}
	return l
}

// unitFor: a systemd service running bin with conf.
func unitFor(desc, bin, conf string) string {
	return fmt.Sprintf(`[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s -c %s
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`, desc, bin, conf)
}

// ensureUnit writes the service and its config, restarting it when either
// changed, and keeps it running.
func ensureUnit(name, unit, confPath, conf string) error {
	up := "/etc/systemd/system/" + name + ".service"
	changed := false
	if b, _ := os.ReadFile(up); string(b) != unit {
		if err := os.WriteFile(up, []byte(unit), 0o644); err != nil {
			return err
		}
		_, _ = run(20*time.Second, "systemctl", "daemon-reload")
		changed = true
	}
	_ = os.MkdirAll(filepath.Dir(confPath), 0o700)
	if b, _ := os.ReadFile(confPath); string(b) != conf {
		if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		_, _ = run(20*time.Second, "systemctl", "enable", name)
		if o, err := run(20*time.Second, "systemctl", "restart", name); err != nil {
			return fmt.Errorf("%s: %s", name, orDefault(o, err.Error()))
		}
		return nil
	}
	if o, _ := run(5*time.Second, "systemctl", "is-active", name); o != "active" {
		_, _ = run(20*time.Second, "systemctl", "enable", name)
		if o, err := run(20*time.Second, "systemctl", "restart", name); err != nil {
			return fmt.Errorf("%s: %s", name, orDefault(o, err.Error()))
		}
	}
	return nil
}

func dropUnit(name, confPath string) {
	up := "/etc/systemd/system/" + name + ".service"
	if _, err := os.Stat(up); err != nil {
		return
	}
	_, _ = run(20*time.Second, "systemctl", "disable", "--now", name)
	_ = os.Remove(up)
	if confPath != "" {
		_ = os.Remove(confPath)
	}
	_, _ = run(20*time.Second, "systemctl", "daemon-reload")
}

// units with a prefix that exist now
func unitsWith(prefix string) []string {
	m, _ := filepath.Glob("/etc/systemd/system/" + prefix + "*.service")
	var l []string
	for _, p := range m {
		l = append(l, strings.TrimSuffix(filepath.Base(p), ".service"))
	}
	return l
}

func frpsConf(sp *frpSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "bindAddr = \"0.0.0.0\"\nbindPort = %d\nproxyBindAddr = \"127.0.0.1\"\n", sp.Port)
	switch sp.Proto {
	case "kcp":
		fmt.Fprintf(&b, "kcpBindPort = %d\n", sp.Port)
	case "quic":
		fmt.Fprintf(&b, "quicBindPort = %d\n", sp.Port)
	}
	fmt.Fprintf(&b, "auth.method = \"token\"\nauth.token = %q\nallowPorts = [{ single = %d }]\nlog.level = \"warn\"\n", sp.Token, sp.Local)
	return b.String()
}

func frpcConf(host string, sp *frpSpec, target int, name string) string {
	return fmt.Sprintf(`serverAddr = %q
serverPort = %d
loginFailExit = false
auth.method = "token"
auth.token = %q
transport.protocol = %q
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30
log.level = "warn"

[[proxies]]
name = %q
type = "tcp"
localIP = "127.0.0.1"
localPort = %d
remotePort = %d
`, host, sp.Port, sp.Token, sp.Proto, name, target, sp.Local)
}

func bhServerConf(sp *bhSpec) string {
	return fmt.Sprintf(`[server]
bind_addr = "0.0.0.0:%d"
transport = %q
token = %q
keepalive_period = 75
nodelay = true
heartbeat = 20
channel_size = 2048
mux_con = 8
sniffer = false
web_port = 0
log_level = "warn"
ports = ["127.0.0.1:%d=127.0.0.1:%d"]
`, sp.Port, sp.Proto, sp.Token, sp.Local, sp.Target)
}

func bhClientConf(host string, sp *bhSpec) string {
	return fmt.Sprintf(`[client]
remote_addr = %q
transport = %q
token = %q
connection_pool = 8
aggressive_pool = false
keepalive_period = 75
dial_timeout = 10
nodelay = true
retry_interval = 3
sniffer = false
web_port = 0
log_level = "warn"
`, net.JoinHostPort(host, strconv.Itoa(sp.Port)), sp.Proto, sp.Token)
}

// ---------- this server's side ----------

var carrierPoke = make(chan struct{}, 1)

func pokeCarriers() {
	select {
	case carrierPoke <- struct{}{}:
	default:
	}
}

// carrierLoop keeps this server's ends of every middle server's carriers
// running: GRE links, frpc and Backhaul clients, SSH forwards.
func (a *App) carrierLoop() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		a.carrierSync()
		select {
		case <-t.C:
		case <-carrierPoke:
		}
	}
}

var carrierStatus = struct {
	sync.Mutex
	m map[string]map[string]string // server id -> method -> error ("" ok)
}{m: map[string]map[string]string{}}

func setCarrierStatus(id, m, err string) {
	carrierStatus.Lock()
	if carrierStatus.m[id] == nil {
		carrierStatus.m[id] = map[string]string{}
	}
	carrierStatus.m[id][m] = err
	carrierStatus.Unlock()
}

func carrierStatusOf(id string) map[string]string {
	carrierStatus.Lock()
	defer carrierStatus.Unlock()
	out := map[string]string{}
	for k, v := range carrierStatus.m[id] {
		out[k] = v
	}
	return out
}

func (a *App) carrierSync() {
	servers, set, _ := a.store.TunnelsCopy()
	dir := filepath.Join(a.store.dir, "carriers")
	wantGRE, wantUnits, wantSSH := map[string]bool{}, map[string]bool{}, map[string]sshWant{}
	for _, s := range servers {
		if s.Pending {
			continue
		}
		w := carrierWanted(s, set)
		carrierStatus.Lock()
		for m := range carrierStatus.m[s.ID] {
			if !w[m] || (m == tunnelMethodGRE && !needsGRE(s, set, w)) {
				delete(carrierStatus.m[s.ID], m)
			}
		}
		carrierStatus.Unlock()
		if len(w) == 0 {
			continue
		}
		host := s.PublicIP
		if needsGRE(s, set, w) {
			if len(wantGRE) == 0 {
				greHostPrep()
			}
			dev := "xo-gre" + strconv.Itoa(greNum(s))
			wantGRE[dev] = true
			err := greLink(dev, s.PublicIP, "", greNet+strconv.Itoa(greNum(s)))
			setCarrierStatus(s.ID, tunnelMethodGRE, errText(err))
		}
		if host == "" {
			continue
		}
		hostFor := func(overGRE bool) string {
			if overGRE && needsGRE(s, set, w) {
				return greNet + strconv.Itoa(greNum(s))
			}
			return host
		}
		short := s.ID
		if len(short) > 12 {
			short = short[:12]
		}
		if w[tunnelMethodFRP] && set.FRPPort > 0 {
			name := "xo-frpc-" + short
			wantUnits[name] = true
			bin, err := carrierBin(a.store.dir, "frpc", "")
			if err == nil {
				conf := filepath.Join(dir, name+".toml")
				sp := &frpSpec{Port: set.FRPPort, Proto: set.FRPProto, Token: set.FRPTok, Local: carrierLocal[tunnelMethodFRP]}
				err = ensureUnit(name, unitFor("xray-one FRP to "+s.Name, bin, conf), conf, frpcConf(hostFor(set.FRPGre), sp, set.WGVPort, "xo-"+short))
			}
			setCarrierStatus(s.ID, tunnelMethodFRP, errText(err))
		}
		if w[tunnelMethodBH] && set.BHPort > 0 {
			name := "xo-bhc-" + short
			wantUnits[name] = true
			bin, err := carrierBin(a.store.dir, "backhaul", "")
			if err == nil {
				conf := filepath.Join(dir, name+".toml")
				sp := &bhSpec{Port: set.BHPort, Proto: set.BHProto, Token: set.BHTok}
				err = ensureUnit(name, unitFor("xray-one Backhaul to "+s.Name, bin, conf), conf, bhClientConf(hostFor(set.BHGre), sp))
			}
			setCarrierStatus(s.ID, tunnelMethodBH, errText(err))
		}
		if w[tunnelMethodSSH] && set.SSHPort > 0 && s.SSHHost != "" {
			wantSSH[s.ID] = sshWant{addr: net.JoinHostPort(host, strconv.Itoa(set.SSHPort)), hostKey: s.SSHHost,
				local: carrierLocal[tunnelMethodSSH], target: set.WGVPort}
		}
	}
	for _, dev := range greLinks("xo-gre") {
		if !wantGRE[dev] {
			greDrop(dev)
		}
	}
	for _, p := range []string{"xo-frpc-", "xo-bhc-"} {
		for _, u := range unitsWith(p) {
			if !wantUnits[u] {
				dropUnit(u, filepath.Join(dir, u+".toml"))
			}
		}
	}
	sshClients.sync(a.store.dir, wantSSH)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return trimTo(err.Error(), 300)
}

// ---------- settings ----------

// POST /api/tunnels/csettings {frpport, frpproto, frpgre, bhport, bhproto, bhgre, sshport}
func (a *App) handleCarrierSettings(w http.ResponseWriter, r *http.Request) {
	var b struct {
		FRPPort  int    `json:"frpport"`
		FRPProto string `json:"frpproto"`
		FRPGre   *bool  `json:"frpgre"`
		Frag     *bool  `json:"frag"`
		BHPort   int    `json:"bhport"`
		BHProto  string `json:"bhproto"`
		BHGre    *bool  `json:"bhgre"`
		SSHPort  int    `json:"sshport"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		fail(w, 400, err)
		return
	}
	for _, p := range []int{b.FRPPort, b.BHPort, b.SSHPort} {
		if p != 0 && (p < 1 || p > 65535) {
			fail(w, 400, fmt.Errorf("port %d is not valid", p))
			return
		}
		if p != 0 && p >= 10885 && p <= 10889 {
			fail(w, 400, fmt.Errorf("port %d is used by the tunnel agent on middle servers", p))
			return
		}
	}
	if b.FRPProto != "" && !inList(frpProtos, b.FRPProto) {
		fail(w, 400, errors.New("unknown FRP protocol"))
		return
	}
	if b.BHProto != "" && !inList(bhProtos, b.BHProto) {
		fail(w, 400, errors.New("unknown Backhaul protocol"))
		return
	}
	_, cur, _ := a.store.TunnelsCopy()
	n := cur
	if b.FRPPort != 0 {
		n.FRPPort = b.FRPPort
	}
	if b.BHPort != 0 {
		n.BHPort = b.BHPort
	}
	if b.SSHPort != 0 {
		n.SSHPort = b.SSHPort
	}
	ps := map[int]string{}
	for k, p := range map[string]int{"FRP": n.FRPPort, "Backhaul": n.BHPort, "SSH": n.SSHPort} {
		if o, ok := ps[p]; ok && p != 0 {
			fail(w, 400, fmt.Errorf("%s and %s cannot use the same port (%d)", o, k, p))
			return
		}
		ps[p] = k
	}
	if b.FRPProto != "" {
		n.FRPProto = b.FRPProto
	}
	if b.BHProto != "" {
		n.BHProto = b.BHProto
	}
	if b.FRPGre != nil {
		n.FRPGre = *b.FRPGre
	}
	if b.BHGre != nil {
		n.BHGre = *b.BHGre
	}
	_ = a.store.EditTunnels(func() error {
		c := &a.store.TunnelCfg
		if b.Frag != nil {
			c.Frag = *b.Frag
		}
		c.FRPPort, c.BHPort, c.SSHPort, c.FRPProto, c.BHProto, c.FRPGre, c.BHGre = n.FRPPort, n.BHPort, n.SSHPort, n.FRPProto, n.BHProto, n.FRPGre, n.BHGre
		return nil
	})
	servers, _, _ := a.store.TunnelsCopy()
	if len(servers) > 0 && (n.FRPGre != cur.FRPGre || n.BHGre != cur.BHGre) {
		if err := a.cfg.Mutate(func(root *OMap) error {
			if err := a.ensureTunnelSettings(root); err != nil {
				return err
			}
			return a.applyTunnelConfig(root)
		}); err != nil {
			fail(w, 400, err)
			return
		}
	}
	var ids []string
	for _, s := range servers {
		ids = append(ids, s.ID)
	}
	hub.PokeAll(ids)
	pokeCarriers()
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}
