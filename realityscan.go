package main

// REALITY target scanner: checks, from this server, which sites can be used
// as a REALITY target (TLS 1.3 + h2 + X25519, valid certificate), and how
// fast they answer from here.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var realityCandidates = []string{
	"www.cloudflare.com", "dl.google.com", "www.google.com", "www.amd.com", "www.microsoft.com", "www.intel.com",
	"www.sony.com", "www.nvidia.com", "www.samsung.com", "aws.amazon.com", "www.apple.com", "swdist.apple.com",
	"www.icloud.com", "www.mozilla.org", "addons.mozilla.org", "www.tesla.com", "www.oracle.com", "www.dell.com",
	"www.hp.com", "www.lenovo.com", "www.asus.com", "www.cisco.com", "www.ibm.com", "www.logitech.com",
	"www.bing.com", "www.yahoo.com", "www.speedtest.net", "www.github.com", "www.python.org", "www.wikipedia.org",
	"www.lovelive-anime.jp", "www.nintendo.com", "www.xbox.com", "www.visa.com", "www.mastercard.com", "www.paypal.com",
	"www.adobe.com", "www.spotify.com", "www.booking.com", "www.ebay.com", "www.bbc.com", "www.cnn.com",
}

type realityResult struct {
	Target   string `json:"target"` // what goes into dest
	SNI      string `json:"sni"`    // what goes into serverNames
	Feasible bool   `json:"feasible"`
	Reason   string `json:"reason,omitempty"`
	TLS      string `json:"tls"`
	ALPN     string `json:"alpn"`
	KeyEx    string `json:"keyEx"`
	Cert     string `json:"cert"`
	Latency  int64  `json:"latency"` // ms, TCP + TLS handshake from this server
}

// probeReality tests one site. addr is host:port to dial; sni is the name
// sent and checked against the certificate.
func probeReality(ctx context.Context, addr, sni string) realityResult {
	res := realityResult{Target: addr, SNI: sni}
	start := time.Now()
	d := net.Dialer{Timeout: 4 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.Reason = "no connection"
		return res
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	c := tls.Client(raw, &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
	if err := c.HandshakeContext(ctx); err != nil {
		res.Reason = "no TLS 1.3 / X25519"
		if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
			res.Reason = "timeout"
		}
		return res
	}
	res.Latency = time.Since(start).Milliseconds()
	st := c.ConnectionState()
	res.TLS, res.KeyEx, res.ALPN = "1.3", "X25519", st.NegotiatedProtocol
	if res.ALPN == "" {
		res.ALPN = "http/1.1"
	}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		res.Cert = leaf.Subject.CommonName
		if res.Cert == "" && len(leaf.DNSNames) > 0 {
			res.Cert = leaf.DNSNames[0]
		}
		inter := x509.NewCertPool()
		for _, ic := range st.PeerCertificates[1:] {
			inter.AddCert(ic)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: sni, Intermediates: inter}); err != nil {
			res.Reason = "certificate not valid for " + sni
			return res
		}
	}
	if st.NegotiatedProtocol != "h2" {
		res.Reason = "no h2"
		return res
	}
	res.Feasible = true
	return res
}

// certName reads a usable site name from the certificate an IP serves.
func certName(ctx context.Context, addr string) string {
	d := net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if c.HandshakeContext(ctx) != nil {
		return ""
	}
	pc := c.ConnectionState().PeerCertificates
	if len(pc) == 0 {
		return ""
	}
	names := append([]string{pc[0].Subject.CommonName}, pc[0].DNSNames...)
	for _, n := range names {
		if n != "" && !strings.HasPrefix(n, "*") && strings.Contains(n, ".") && net.ParseIP(n) == nil {
			return n
		}
	}
	for _, n := range names { // only wildcards: try www.<domain>
		if strings.HasPrefix(n, "*.") {
			return "www." + n[2:]
		}
	}
	return ""
}

func splitTarget(s string) (host string, port int) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://"))
	s = strings.TrimSuffix(strings.SplitN(s, "/", 2)[0], ".")
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, _ := strconv.Atoi(p)
		return h, n
	}
	return s, 443
}

func (a *App) handleRealityScan(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Q string `json:"q"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	q := strings.TrimSpace(b.Q)
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	type job struct{ addr, sni, ip string }
	var jobs []job
	switch {
	case q == "":
		for _, h := range realityCandidates {
			jobs = append(jobs, job{addr: net.JoinHostPort(h, "443"), sni: h})
		}
	case strings.Contains(q, "/"): // CIDR
		_, n, err := net.ParseCIDR(q)
		if err != nil || n.IP.To4() == nil {
			fail(w, 400, errors.New("use an IPv4 range like 1.2.3.0/24"))
			return
		}
		if ones, _ := n.Mask.Size(); ones < 22 {
			fail(w, 400, errors.New("range too big: at most /22 (1024 addresses)"))
			return
		}
		for ip := n.IP.Mask(n.Mask).To4(); n.Contains(ip); ip = nextIP(ip) {
			if ip[3] != 0 && ip[3] != 255 {
				jobs = append(jobs, job{ip: ip.String()})
			}
		}
	default:
		h, p := splitTarget(q)
		if h == "" || p <= 0 || p > 65535 {
			fail(w, 400, errors.New("enter a domain, an IP or a range"))
			return
		}
		if net.ParseIP(h) != nil {
			jobs = append(jobs, job{ip: h, addr: net.JoinHostPort(h, strconv.Itoa(p))})
		} else {
			jobs = append(jobs, job{addr: net.JoinHostPort(h, strconv.Itoa(p)), sni: h})
		}
	}

	var mu sync.Mutex
	out := []realityResult{}
	seen := map[string]bool{}
	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer func() { <-sem; wg.Done() }()
			if j.ip != "" {
				if j.addr == "" {
					j.addr = net.JoinHostPort(j.ip, "443")
				}
				j.sni = certName(ctx, j.addr)
				if j.sni == "" {
					if q != "" && !strings.Contains(q, "/") {
						mu.Lock()
						out = append(out, realityResult{Target: j.addr, Reason: "no TLS certificate"})
						mu.Unlock()
					}
					return
				}
			}
			res := probeReality(ctx, j.addr, j.sni)
			if j.ip != "" && strings.Contains(q, "/") && !res.Feasible {
				return // ranges list only usable hits
			}
			mu.Lock()
			if !seen[res.Target+"|"+res.SNI] {
				seen[res.Target+"|"+res.SNI] = true
				out = append(out, res)
			}
			mu.Unlock()
		}(j)
	}
	wg.Wait()
	sort.SliceStable(out, func(i, k int) bool {
		if out[i].Feasible != out[k].Feasible {
			return out[i].Feasible
		}
		if out[i].Feasible {
			return out[i].Latency < out[k].Latency
		}
		return out[i].Target < out[k].Target
	})
	writeJSONResp(w, 200, map[string]any{"results": out, "scanned": len(jobs)})
}

func nextIP(ip net.IP) net.IP {
	n := make(net.IP, len(ip))
	copy(n, ip)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

// handleRealityKeys makes a new x25519 pair, or gives the public key of ?priv=.
func (a *App) handleRealityKeys(w http.ResponseWriter, r *http.Request) {
	if p := strings.TrimSpace(r.URL.Query().Get("priv")); p != "" {
		pub := pubFromPriv(p)
		if pub == "" {
			fail(w, 400, errors.New("not a valid x25519 private key"))
			return
		}
		writeJSONResp(w, 200, map[string]string{"privateKey": p, "publicKey": pub})
		return
	}
	priv, pub, err := genX25519()
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSONResp(w, 200, map[string]string{"privateKey": priv, "publicKey": pub})
}
