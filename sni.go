package main

// Anti-sanction entry (تحریم‌شکن). Some sites and games refuse Iranian
// addresses for login, store and matchmaking. A user points their DNS at an
// entry server (the main server, or a middle server when the main one is
// filtered); for listed domains the DNS answers the entry's own address, and
// a small proxy on 443/80 reads the site name (TLS SNI / HTTP Host) and sends
// the connection on to the real site: directly from the main server, through
// the tunnel from a middle server. Nothing is decrypted.
//
// Two locks keep it from becoming an open proxy: only addresses a user
// activated (a link on their subscription page, opened from that network)
// may use it, and only listed domains pass, in the DNS and in the proxy.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// sniSpec is what an entry runs: sent to a middle server in its heartbeat.
type sniSpec struct {
	Domains []string `json:"domains"`
	Keys    []string `json:"keys"`  // activation keys of active users
	IP      string   `json:"ip"`    // address the DNS answers for listed domains
	Hours   int      `json:"hours"` // how long an activation lasts
	// ports this server's tunnels or inbounds use: never taken (set locally)
	Avoid []int `json:"-"`
}

// SniSettings: the panel's settings.
type SniSettings struct {
	Domains []string `json:"domains,omitempty"`
	Main    bool     `json:"main,omitempty"`  // the main server is an entry too
	Hours   int      `json:"hours,omitempty"` // 0 = 24
}

const sniDefaultHours = 24

// the entry's ports (variables only so tests can move them)
var sniPortTLS, sniPortHTTP, sniPortDNS = 443, 80, 53

// sniKey: a user's activation key. It is sent in plain HTTP to the entry,
// so it is derived from the subscription token and never reveals it.
func sniKey(subToken string) string {
	h := sha256.Sum256([]byte("xo-sni:" + subToken))
	return hex.EncodeToString(h[:10])
}

// sniNormDomains cleans a user's list: lower case, no scheme, path, port or
// leading dots, no duplicates.
func sniNormDomains(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		d = strings.TrimPrefix(strings.TrimPrefix(d, "https://"), "http://")
		d = strings.TrimPrefix(d, "domain:")
		if i := strings.IndexAny(d, "/: \t"); i >= 0 {
			d = d[:i]
		}
		d = strings.Trim(strings.TrimPrefix(d, "*"), ".")
		if d == "" || !hostRe.MatchString(d) || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// sniMatch: host is a listed domain or one of its subdomains.
func sniMatch(doms map[string]bool, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for host != "" {
		if doms[host] {
			return true
		}
		i := strings.IndexByte(host, '.')
		if i < 0 {
			return false
		}
		host = host[i+1:]
	}
	return false
}

type sniAllow struct {
	Key   string `json:"key"`
	Until int64  `json:"until"`
}

type sniService struct {
	mu      sync.Mutex
	spec    sniSpec
	doms    map[string]bool
	keys    map[string]bool
	allow   map[string]sniAllow // IP -> activation
	dial    func(host string, port int) (net.Conn, error)
	file    string // where activations are kept across restarts
	running bool
	closers []io.Closer
	ln80    net.Listener
	errs    []string
}

// sniSvc: the entry this process runs, if any (the panel on the main server,
// the agent on a middle server).
var sniSvc *sniService

func newSniService(file string, dial func(string, int) (net.Conn, error)) *sniService {
	s := &sniService{file: file, dial: dial, allow: map[string]sniAllow{}}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, &s.allow)
	}
	return s
}

// Update starts, changes or (nil) stops the entry.
func (s *sniService) Update(sp *sniSpec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sp == nil || len(sp.Domains) == 0 {
		s.stopLocked()
		return
	}
	restart := s.running && fmt.Sprint(s.spec.Avoid) != fmt.Sprint(sp.Avoid)
	s.spec = *sp
	if restart {
		s.stopLocked()
	}
	if s.spec.Hours <= 0 {
		s.spec.Hours = sniDefaultHours
	}
	s.doms, s.keys = map[string]bool{}, map[string]bool{}
	for _, d := range sp.Domains {
		s.doms[d] = true
	}
	for _, k := range sp.Keys {
		s.keys[k] = true
	}
	now := time.Now().Unix()
	changed := false
	for ip, a := range s.allow {
		if !s.keys[a.Key] || a.Until < now { // user disabled, deleted or expired
			delete(s.allow, ip)
			changed = true
		}
	}
	if changed {
		s.saveLocked()
	}
	if !s.running {
		s.startLocked()
	}
}

// Status: errors while starting, and how many addresses are active now.
func (s *sniService) Status() (string, int) {
	if s == nil {
		return "", 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := time.Now().Unix()
	for _, a := range s.allow {
		if a.Until >= now {
			n++
		}
	}
	return strings.Join(s.errs, "; "), n
}

func (s *sniService) saveLocked() {
	if b, err := json.Marshal(s.allow); err == nil {
		_ = writeAtomic(s.file, b)
	}
}

func (s *sniService) stopLocked() {
	for _, c := range s.closers {
		_ = c.Close()
	}
	if s.ln80 != nil {
		_ = s.ln80.Close()
	}
	s.closers, s.ln80, s.running, s.errs = nil, nil, false, nil
}

func (s *sniService) avoidLocked(p int) bool {
	for _, x := range s.spec.Avoid {
		if x == p {
			s.errs = append(s.errs, fmt.Sprintf("port %d is used by an inbound or a tunnel here", p))
			return true
		}
	}
	return false
}

func (s *sniService) startLocked() {
	s.running, s.errs = true, nil
	if !s.avoidLocked(sniPortTLS) {
		if ln, err := net.Listen("tcp", ":"+strconv.Itoa(sniPortTLS)); err != nil {
			s.errs = append(s.errs, fmt.Sprintf("port %d is busy: %s", sniPortTLS, portUser(sniPortTLS)))
		} else {
			s.closers = append(s.closers, ln)
			go s.accept(ln, s.serveTLS)
		}
	}
	s.open80Locked()
	s.startDNSLocked()
}

func (s *sniService) open80Locked() {
	if s.avoidLocked(sniPortHTTP) {
		return
	}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(sniPortHTTP))
	if err != nil {
		s.errs = append(s.errs, fmt.Sprintf("port %d is busy (activation links need it): %s", sniPortHTTP, portUser(sniPortHTTP)))
		return
	}
	s.ln80 = ln
	go s.accept(ln, s.serveHTTP)
}

// release80 frees port 80 for a Let's Encrypt challenge; the returned func
// takes it back. nil when this entry does not hold port 80.
func (s *sniService) release80() func() {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln80 == nil {
		return nil
	}
	_ = s.ln80.Close()
	s.ln80 = nil
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.running && s.ln80 == nil {
			s.errs = dropPortErr(s.errs, fmt.Sprintf("port %d", sniPortHTTP))
			s.open80Locked()
		}
	}
}

func dropPortErr(errs []string, p string) []string {
	var out []string
	for _, e := range errs {
		if !strings.HasPrefix(e, p+" ") {
			out = append(out, e)
		}
	}
	return out
}

// portUser names who holds a port, for the error shown in the panel.
func portUser(p int) string {
	if p == 53 {
		return "another DNS server"
	}
	if u := portUnit(p); u != "" {
		return u
	}
	return "another program"
}

// startDNSLocked listens on port 53. Ubuntu's own resolver holds
// 127.0.0.53:53, so when the wildcard is taken it listens on each address of
// this server instead.
func (s *sniService) startDNSLocked() {
	if s.avoidLocked(sniPortDNS) {
		return
	}
	dp := strconv.Itoa(sniPortDNS)
	addrs := []string{""}
	if !udpFree(sniPortDNS) {
		addrs = nil
		ifs, _ := net.InterfaceAddrs()
		for _, a := range ifs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
				addrs = append(addrs, ipn.IP.String())
			}
		}
	}
	ok := false
	for _, ad := range addrs {
		pc, err := net.ListenPacket("udp4", net.JoinHostPort(ad, dp))
		if err != nil {
			continue
		}
		ok = true
		s.closers = append(s.closers, pc)
		go s.serveDNSUDP(pc)
		if ln, err := net.Listen("tcp4", net.JoinHostPort(ad, dp)); err == nil {
			s.closers = append(s.closers, ln)
			go s.accept(ln, s.serveDNSTCP)
		}
	}
	if !ok {
		s.errs = append(s.errs, fmt.Sprintf("port %d is busy: %s", sniPortDNS, portUser(sniPortDNS)))
	}
}

func udpFree(p int) bool {
	u, err := net.ListenPacket("udp4", ":"+strconv.Itoa(p))
	if err != nil {
		return false
	}
	u.Close()
	return true
}

func (s *sniService) accept(ln net.Listener, h func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go h(c)
	}
}

func hostOf(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
	}
	return h
}

func (s *sniService) allowed(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.allow[ip]
	return ok && a.Until >= time.Now().Unix() && s.keys[a.Key]
}

func (s *sniService) listed(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sniMatch(s.doms, host)
}

// ---------- DNS ----------

var sniUpstreams = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}

func (s *sniService) serveDNSUDP(pc net.PacketConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		q := append([]byte{}, buf[:n]...)
		go func() {
			if out := s.dnsAnswer(q, hostOf(from), false); out != nil {
				_, _ = pc.WriteTo(out, from)
			}
		}()
	}
}

func (s *sniService) serveDNSTCP(c net.Conn) {
	defer c.Close()
	src := hostOf(c.RemoteAddr())
	for {
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		out := s.dnsAnswer(q, src, true)
		if out == nil {
			return
		}
		binary.BigEndian.PutUint16(l[:], uint16(len(out)))
		if _, err := c.Write(append(l[:], out...)); err != nil {
			return
		}
	}
}

// dnsAnswer: listed domains get this entry's address (A) or nothing (AAAA
// and the rest, so phones use IPv4); other names go to a public resolver.
// Addresses that did not activate are refused, so this is no open resolver.
func (s *sniService) dnsAnswer(q []byte, src string, tcp bool) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(q)
	if err != nil || hdr.Response {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return dnsReply(hdr, qs, dnsmessage.RCodeFormatError, nil)
	}
	qq := qs[0]
	if !s.allowed(src) {
		return dnsReply(hdr, qs, dnsmessage.RCodeRefused, nil)
	}
	name := strings.TrimSuffix(qq.Name.String(), ".")
	if s.listed(name) {
		if qq.Type != dnsmessage.TypeA {
			return dnsReply(hdr, qs, dnsmessage.RCodeSuccess, nil)
		}
		s.mu.Lock()
		ip := net.ParseIP(s.spec.IP).To4()
		s.mu.Unlock()
		if ip == nil {
			return dnsReply(hdr, qs, dnsmessage.RCodeServerFailure, nil)
		}
		var a [4]byte
		copy(a[:], ip)
		return dnsReply(hdr, qs, dnsmessage.RCodeSuccess, &dnsmessage.AResource{A: a})
	}
	if out := dnsForward(q, tcp); out != nil {
		return out
	}
	return dnsReply(hdr, qs, dnsmessage.RCodeServerFailure, nil)
}

func dnsReply(h dnsmessage.Header, qs []dnsmessage.Question, rc dnsmessage.RCode, a *dnsmessage.AResource) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, OpCode: h.OpCode,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rc})
	b.EnableCompression()
	_ = b.StartQuestions()
	for _, q := range qs {
		_ = b.Question(q)
	}
	if a != nil && len(qs) == 1 {
		_ = b.StartAnswers()
		_ = b.AResource(dnsmessage.ResourceHeader{Name: qs[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, *a)
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

func dnsForward(q []byte, tcp bool) []byte {
	for _, up := range sniUpstreams {
		if tcp {
			c, err := net.DialTimeout("tcp", up, 3*time.Second)
			if err != nil {
				continue
			}
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var l [2]byte
			binary.BigEndian.PutUint16(l[:], uint16(len(q)))
			_, err = c.Write(append(l[:], q...))
			if err == nil {
				_, err = io.ReadFull(c, l[:])
			}
			if err == nil {
				out := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err = io.ReadFull(c, out); err == nil {
					c.Close()
					return out
				}
			}
			c.Close()
			continue
		}
		c, err := net.DialTimeout("udp", up, 3*time.Second)
		if err != nil {
			continue
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(q); err == nil {
			buf := make([]byte, 4096)
			if n, err := c.Read(buf); err == nil {
				c.Close()
				return buf[:n]
			}
		}
		c.Close()
	}
	return nil
}

// ---------- proxy ----------

func (s *sniService) serveTLS(c net.Conn) {
	defer c.Close()
	if !s.allowed(hostOf(c.RemoteAddr())) {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	hello, host, err := readClientHello(c)
	if err != nil || host == "" || !s.listed(host) {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	s.relay(c, hello, host, 443)
}

func (s *sniService) relay(c net.Conn, first []byte, host string, port int) {
	up, err := s.dial(host, port)
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(first); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(up, c)
	go cp(c, up)
	<-done
	<-done
}

// readClientHello reads the first TLS record and returns it with the site
// name it asks for.
func readClientHello(c net.Conn) ([]byte, string, error) {
	h := make([]byte, 5)
	if _, err := io.ReadFull(c, h); err != nil {
		return nil, "", err
	}
	if h[0] != 0x16 {
		return nil, "", errors.New("not TLS")
	}
	n := int(binary.BigEndian.Uint16(h[3:5]))
	if n == 0 || n > 16384 {
		return nil, "", errors.New("bad record")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		return nil, "", err
	}
	return append(h, body...), helloSNI(body), nil
}

func helloSNI(b []byte) string {
	if len(b) < 4 || b[0] != 1 {
		return ""
	}
	b = b[4:]
	if len(b) < 34 {
		return ""
	}
	b = b[34:] // version, random
	skip := func(lenBytes int) bool {
		if len(b) < lenBytes {
			return false
		}
		l := 0
		for i := 0; i < lenBytes; i++ {
			l = l<<8 | int(b[i])
		}
		if len(b) < lenBytes+l {
			return false
		}
		b = b[lenBytes+l:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, ciphers, compression
		return ""
	}
	if len(b) < 2 {
		return ""
	}
	ext := b[2:]
	if l := int(binary.BigEndian.Uint16(b)); l < len(ext) {
		ext = ext[:l]
	}
	for len(ext) >= 4 {
		typ, l := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+l {
			return ""
		}
		data := ext[4 : 4+l]
		ext = ext[4+l:]
		if typ != 0 || len(data) < 5 {
			continue
		}
		data = data[2:]
		for len(data) >= 3 {
			nt, nl := data[0], int(binary.BigEndian.Uint16(data[1:]))
			if len(data) < 3+nl {
				return ""
			}
			if nt == 0 {
				return string(data[3 : 3+nl])
			}
			data = data[3+nl:]
		}
	}
	return ""
}

// serveHTTP: activation links (/xo-act/<key>) and plain HTTP for listed
// domains.
func (s *sniService) serveHTTP(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	var buf []byte
	tmp := make([]byte, 2048)
	for !strings.Contains(string(buf), "\r\n\r\n") {
		if len(buf) > 16384 {
			return
		}
		n, err := c.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			return
		}
	}
	head := string(buf[:strings.Index(string(buf), "\r\n\r\n")])
	lines := strings.Split(head, "\r\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return
	}
	src := hostOf(c.RemoteAddr())
	if strings.HasPrefix(parts[1], "/xo-act/") {
		_ = c.SetReadDeadline(time.Time{})
		s.activate(c, src, strings.Trim(strings.TrimPrefix(parts[1], "/xo-act/"), "/"))
		return
	}
	host := ""
	for _, l := range lines[1:] {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "host") {
			host = strings.TrimSpace(v)
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" || !s.allowed(src) || !s.listed(host) {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	s.relay(c, buf, host, 80)
}

func (s *sniService) activate(c net.Conn, src, key string) {
	if i := strings.IndexAny(key, "?#"); i >= 0 {
		key = key[:i]
	}
	s.mu.Lock()
	ok := s.keys[key]
	hours, ip := s.spec.Hours, s.spec.IP
	if ok {
		s.allow[src] = sniAllow{Key: key, Until: time.Now().Add(time.Duration(hours) * time.Hour).Unix()}
		s.saveLocked()
	}
	s.mu.Unlock()
	code, title, msg := "200 OK", "فعال شد", fmt.Sprintf("این اینترنت برای %d ساعت فعال شد. دی‌ان‌اس گوشی یا کنسول را روی این آدرس بگذارید:", hours)
	if !ok {
		code, title, msg = "404 Not Found", "لینک معتبر نیست", "این لینک فعال‌سازی معتبر نیست یا اشتراک شما فعال نیست."
	}
	body := `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + title + `</title>` +
		`<style>body{font-family:system-ui,Tahoma,sans-serif;background:#111;color:#eee;display:grid;place-items:center;min-height:90vh;margin:0}` +
		`.c{max-width:420px;padding:24px;border:1px solid #333;border-radius:16px;text-align:center;line-height:1.9}b{font-size:1.4em;direction:ltr;display:block;margin:10px 0}` +
		`small{color:#999}</style></head><body><div class="c"><h2>` + title + `</h2><p>` + html.EscapeString(msg) + `</p>`
	if ok {
		body += `<b>` + html.EscapeString(ip) + `</b><small>هر وقت اینترنت یا سیم‌کارت عوض شد، یا زمانش تمام شد، دوباره همین لینک را باز کنید.</small>`
	}
	body += `</div></body></html>`
	_, _ = fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", code, len(body), body)
}

// socksDial: connect to host:port through a local SOCKS5 port (a middle
// server reaches sites through its tunnel this way).
func socksDial(socks int, host string, port int) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(socks), 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 0 {
		return fail(errors.New("socks: no auth refused"))
	}
	if len(host) > 255 {
		return fail(errors.New("host too long"))
	}
	req := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil || h[1] != 0 {
		return fail(errors.New("socks: connect refused"))
	}
	skip := 0
	switch h[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return fail(err)
		}
		skip = int(l[0])
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// agentSni runs (or stops) the entry on a middle server; sites are reached
// through the tunnel, by the relay's local SOCKS port.
func agentSni(sp *sniSpec, st agentState) {
	if sniSvc == nil {
		if sp == nil {
			return
		}
		ctl := st.Ctl
		sniSvc = newSniService(filepath.Join(agentDir, "sni-allow.json"), func(h string, p int) (net.Conn, error) {
			return socksDial(ctl, h, p)
		})
	}
	if sp != nil {
		cfg, _ := os.ReadFile(filepath.Join(agentDir, "xray.json"))
		for _, p := range fwdPorts(cfg) {
			if p == 53 || p == 80 || p == 443 {
				sp.Avoid = append(sp.Avoid, p)
			}
		}
	}
	sniSvc.Update(sp)
}
