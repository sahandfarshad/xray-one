package main

// SSL for the panel and subscription: reuse a certificate that already
// exists on the server (certbot / Muse99 / acme.sh) or get a new one from
// Let's Encrypt with the built-in ACME client. Certificates are reloaded
// automatically when their files change (e.g. after certbot renews).

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

type FoundCert struct {
	Domain   string    `json:"domain"`
	CertFile string    `json:"certFile"`
	KeyFile  string    `json:"keyFile"`
	Source   string    `json:"source"`
	Expires  time.Time `json:"expires"`
}

func certExpiry(certFile string) (time.Time, []string, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return time.Time{}, nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return time.Time{}, nil, errors.New("not a PEM certificate")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return time.Time{}, nil, err
	}
	return c.NotAfter, c.DNSNames, nil
}

// FindCerts lists certificates already on this server.
func FindCerts(dataDir string) []FoundCert {
	var out []FoundCert
	add := func(domain, cf, kf, src string) {
		if _, err := os.Stat(kf); err != nil {
			return
		}
		exp, names, err := certExpiry(cf)
		if err != nil {
			return
		}
		if domain == "" && len(names) > 0 {
			domain = names[0]
		}
		for _, f := range out {
			if f.CertFile == cf {
				return
			}
		}
		out = append(out, FoundCert{domain, cf, kf, src, exp})
	}
	dirs, _ := filepath.Glob("/etc/letsencrypt/live/*")
	for _, d := range dirs {
		add(filepath.Base(d), filepath.Join(d, "fullchain.pem"), filepath.Join(d, "privkey.pem"), "certbot")
	}
	homes, _ := filepath.Glob("/home/*")
	homes = append(homes, "/root")
	for _, h := range homes {
		mc, _ := filepath.Glob(filepath.Join(h, ".muse99/certs/*"))
		for _, d := range mc {
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				add(filepath.Base(d), filepath.Join(d, "fullchain.pem"), filepath.Join(d, "privkey.pem"), "muse99")
			}
		}
		if _, err := os.Stat(filepath.Join(h, ".muse99/certs/fullchain.pem")); err == nil {
			add("", filepath.Join(h, ".muse99/certs/fullchain.pem"), filepath.Join(h, ".muse99/certs/privkey.pem"), "muse99")
		}
		ac, _ := filepath.Glob(filepath.Join(h, ".acme.sh/*"))
		for _, d := range ac {
			dom := strings.TrimSuffix(filepath.Base(d), "_ecc")
			add(dom, filepath.Join(d, "fullchain.cer"), filepath.Join(d, dom+".key"), "acme.sh")
		}
	}
	own, _ := filepath.Glob(filepath.Join(dataDir, "certs/*"))
	for _, d := range own {
		add(filepath.Base(d), filepath.Join(d, "fullchain.pem"), filepath.Join(d, "privkey.pem"), "xray-one")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// certReloader serves the cert and reloads it when the files change.
type certReloader struct {
	mu       sync.Mutex
	certFile string
	keyFile  string
	mtime    time.Time
	cert     *tls.Certificate
}

func (r *certReloader) Get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := os.Stat(r.certFile)
	if err == nil && (r.cert == nil || st.ModTime().After(r.mtime)) {
		c, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
		if err == nil {
			r.cert, r.mtime = &c, st.ModTime()
		} else if r.cert == nil {
			return nil, err
		}
	}
	if r.cert == nil {
		return nil, errors.New("no certificate")
	}
	return r.cert, nil
}

func portFree(port int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// ObtainCert gets a Let's Encrypt certificate with an HTTP-01 challenge on
// port 80 and stores it in <dataDir>/certs/<domain>/.
func ObtainCert(dataDir, domain, email string, logf func(string, ...any)) (string, string, error) {
	if !portFree(80) {
		return "", "", errors.New("port 80 is busy (nginx, apache or another program); Let's Encrypt needs it free for a minute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	accKey, err := loadOrCreateKey(filepath.Join(dataDir, "acme-account.key"))
	if err != nil {
		return "", "", err
	}
	client := &acme.Client{Key: accKey, DirectoryURL: acme.LetsEncryptURL}
	acct := &acme.Account{}
	if email != "" {
		acct.Contact = []string{"mailto:" + email}
	}
	if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return "", "", fmt.Errorf("register: %w", err)
	}
	tokens := map[string]string{}
	var tmu sync.Mutex
	srv := &http.Server{Addr: ":80", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tmu.Lock()
		body, ok := tokens[r.URL.Path]
		tmu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	})}
	go srv.ListenAndServe()
	defer srv.Close()

	logf("Requesting certificate for %s ...", domain)
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return "", "", fmt.Errorf("order: %w", err)
	}
	for _, zurl := range order.AuthzURLs {
		z, err := client.GetAuthorization(ctx, zurl)
		if err != nil {
			return "", "", err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "http-01" {
				chal = c
			}
		}
		if chal == nil {
			return "", "", errors.New("no http-01 challenge offered")
		}
		resp, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return "", "", err
		}
		tmu.Lock()
		tokens[client.HTTP01ChallengePath(chal.Token)] = resp
		tmu.Unlock()
		if _, err := client.Accept(ctx, chal); err != nil {
			return "", "", err
		}
		logf("Waiting for Let's Encrypt to check http://%s/ ...", domain)
		if _, err := client.WaitAuthorization(ctx, z.URI); err != nil {
			return "", "", fmt.Errorf("validation failed (does %s point to this server, and is port 80 open in the firewall?): %w", domain, err)
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return "", "", err
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{domain}}, key)
	if err != nil {
		return "", "", err
	}
	ders, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return "", "", err
	}
	dir := filepath.Join(dataDir, "certs", domain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	var chain []byte
	for _, d := range ders {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	cf, kf := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(cf, chain, 0o644); err != nil {
		return "", "", err
	}
	logf("Certificate saved: %s", cf)
	return cf, kf, nil
}

func loadOrCreateKey(p string) (crypto.Signer, error) {
	if data, err := os.ReadFile(p); err == nil {
		if b, _ := pem.Decode(data); b != nil {
			return x509.ParseECPrivateKey(b.Bytes)
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	b, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}
