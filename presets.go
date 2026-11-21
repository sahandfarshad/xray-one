package main

// Quick setup: a catalogue of ready-made inbound types the user ticks and
// creates in one go, each on its own free port, with one shared client.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

type Preset struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Group      string `json:"group"` // reality | tls | plain | ss | proxy
	Protocol   string `json:"protocol"`
	Network    string `json:"network"`
	Security   string `json:"security"`
	Method     string `json:"method,omitempty"`
	HeaderType string `json:"headerType,omitempty"`
	Note       string `json:"note,omitempty"`
}

func pr(id, label, group, proto, network, security, note string) Preset {
	return Preset{ID: id, Label: label, Group: group, Protocol: proto, Network: network, Security: security, Note: note}
}

func ssPreset(id, label, method, note string) Preset {
	return Preset{ID: id, Label: label, Group: "ss", Protocol: "shadowsocks", Network: "tcp", Security: "none", Method: method, Note: note}
}

func hdr(p Preset, h string) Preset { p.HeaderType = h; return p }

var presets = []Preset{
	// REALITY: no domain or certificate needed
	pr("vless-tcp-reality", "VLESS · TCP · REALITY (Vision)", "reality", "vless", "tcp", "reality", "recommended"),
	pr("vless-xhttp-reality", "VLESS · XHTTP · REALITY", "reality", "vless", "xhttp", "reality", ""),
	pr("vless-grpc-reality", "VLESS · gRPC · REALITY", "reality", "vless", "grpc", "reality", ""),
	pr("trojan-tcp-reality", "Trojan · TCP · REALITY", "reality", "trojan", "tcp", "reality", ""),
	pr("trojan-xhttp-reality", "Trojan · XHTTP · REALITY", "reality", "trojan", "xhttp", "reality", ""),
	pr("trojan-grpc-reality", "Trojan · gRPC · REALITY", "reality", "trojan", "grpc", "reality", ""),

	// TLS with the domain certificate
	pr("vless-tcp-tls", "VLESS · TCP · TLS (Vision)", "tls", "vless", "tcp", "tls", ""),
	pr("vless-ws-tls", "VLESS · WebSocket · TLS", "tls", "vless", "ws", "tls", "CDN"),
	pr("vless-grpc-tls", "VLESS · gRPC · TLS", "tls", "vless", "grpc", "tls", "CDN"),
	pr("vless-xhttp-tls", "VLESS · XHTTP · TLS", "tls", "vless", "xhttp", "tls", "CDN"),
	pr("vless-httpupgrade-tls", "VLESS · HTTPUpgrade · TLS", "tls", "vless", "httpupgrade", "tls", "CDN"),
	pr("vmess-tcp-tls", "VMess · TCP · TLS", "tls", "vmess", "tcp", "tls", ""),
	pr("vmess-ws-tls", "VMess · WebSocket · TLS", "tls", "vmess", "ws", "tls", "CDN"),
	pr("vmess-grpc-tls", "VMess · gRPC · TLS", "tls", "vmess", "grpc", "tls", "CDN"),
	pr("vmess-xhttp-tls", "VMess · XHTTP · TLS", "tls", "vmess", "xhttp", "tls", "CDN"),
	pr("vmess-httpupgrade-tls", "VMess · HTTPUpgrade · TLS", "tls", "vmess", "httpupgrade", "tls", "CDN"),
	pr("trojan-tcp-tls", "Trojan · TCP · TLS", "tls", "trojan", "tcp", "tls", ""),
	pr("trojan-ws-tls", "Trojan · WebSocket · TLS", "tls", "trojan", "ws", "tls", "CDN"),
	pr("trojan-grpc-tls", "Trojan · gRPC · TLS", "tls", "trojan", "grpc", "tls", "CDN"),
	pr("trojan-xhttp-tls", "Trojan · XHTTP · TLS", "tls", "trojan", "xhttp", "tls", "CDN"),
	pr("trojan-httpupgrade-tls", "Trojan · HTTPUpgrade · TLS", "tls", "trojan", "httpupgrade", "tls", "CDN"),
	pr("hysteria2", "Hysteria2 (QUIC · UDP)", "tls", "hysteria", "hysteria", "tls", "UDP"),

	// no TLS
	pr("vless-tcp", "VLESS · TCP", "plain", "vless", "tcp", "none", ""),
	hdr(pr("vless-tcp-http", "VLESS · TCP · HTTP header", "plain", "vless", "tcp", "none", "obfs"), "http"),
	pr("vless-ws", "VLESS · WebSocket", "plain", "vless", "ws", "none", "relay / CDN over HTTP"),
	pr("vless-grpc", "VLESS · gRPC", "plain", "vless", "grpc", "none", ""),
	pr("vless-xhttp", "VLESS · XHTTP", "plain", "vless", "xhttp", "none", "relay / CDN over HTTP"),
	pr("vless-httpupgrade", "VLESS · HTTPUpgrade", "plain", "vless", "httpupgrade", "none", "relay / CDN over HTTP"),
	pr("vless-kcp", "VLESS · mKCP", "plain", "vless", "kcp", "none", "UDP"),
	pr("vmess-tcp", "VMess · TCP", "plain", "vmess", "tcp", "none", ""),
	hdr(pr("vmess-tcp-http", "VMess · TCP · HTTP header", "plain", "vmess", "tcp", "none", "obfs"), "http"),
	pr("vmess-ws", "VMess · WebSocket", "plain", "vmess", "ws", "none", "relay / CDN over HTTP"),
	pr("vmess-grpc", "VMess · gRPC", "plain", "vmess", "grpc", "none", ""),
	pr("vmess-xhttp", "VMess · XHTTP", "plain", "vmess", "xhttp", "none", "relay / CDN over HTTP"),
	pr("vmess-httpupgrade", "VMess · HTTPUpgrade", "plain", "vmess", "httpupgrade", "none", "relay / CDN over HTTP"),
	pr("vmess-kcp", "VMess · mKCP", "plain", "vmess", "kcp", "none", "UDP"),
	pr("trojan-tcp", "Trojan · TCP (no TLS)", "plain", "trojan", "tcp", "none", ""),
	pr("trojan-ws", "Trojan · WebSocket (no TLS)", "plain", "trojan", "ws", "none", "relay / CDN over HTTP"),

	// Shadowsocks
	ssPreset("ss-2022", "Shadowsocks 2022 · AES-128", "2022-blake3-aes-128-gcm", "recommended"),
	ssPreset("ss-2022-aes256", "Shadowsocks 2022 · AES-256", "2022-blake3-aes-256-gcm", ""),
	ssPreset("ss-aes128", "Shadowsocks · AES-128-GCM", "aes-128-gcm", "legacy"),
	ssPreset("ss-aes256", "Shadowsocks · AES-256-GCM", "aes-256-gcm", "legacy"),
	ssPreset("ss-chacha", "Shadowsocks · ChaCha20-Poly1305", "chacha20-ietf-poly1305", "legacy"),

	// plain proxies (own random user/password, not the shared client)
	pr("socks", "SOCKS5 (user/password)", "proxy", "socks", "tcp", "none", "TCP+UDP"),
	pr("http", "HTTP proxy (user/password)", "proxy", "http", "tcp", "none", ""),
}

// presetCert picks the certificate TLS presets use: the panel's own, else
// the first one found on the server.
func (a *App) presetCert() *FoundCert {
	c := a.store.Cfg
	if c.CertFile != "" && c.KeyFile != "" {
		return &FoundCert{Domain: c.Domain, CertFile: c.CertFile, KeyFile: c.KeyFile}
	}
	if f := FindCerts(a.store.dir); len(f) > 0 {
		return &f[0]
	}
	return nil
}

func (a *App) handlePresets(w http.ResponseWriter, r *http.Request) {
	cert := a.presetCert()
	type row struct {
		Preset
		Available bool   `json:"available"`
		Exists    string `json:"exists,omitempty"`
	}
	have := map[string]string{}
	if root, _, err := a.cfg.Load(); err == nil {
		for i, v := range asArr(root.Get("inbounds")) {
			ib := asMap(v)
			if ib == nil {
				continue
			}
			n, s := streamInfo(ib)
			if n == "raw" {
				n = "tcp"
			}
			have[presetKey(asStr(ib.Get("protocol")), n, s, pathStr(ib, "settings", "method"), tcpHeader(ib))] = inboundID(ib, i)
		}
	}
	out := []row{}
	for _, p := range presets {
		out = append(out, row{p, p.Security != "tls" || cert != nil, have[presetKey(p.Protocol, p.Network, p.Security, p.Method, p.HeaderType)]})
	}
	domain := ""
	if cert != nil {
		domain = cert.Domain
	}
	writeJSONResp(w, 200, map[string]any{"presets": out, "certDomain": domain})
}

func (a *App) handleCreatePresets(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs        []string `json:"ids"`
		Client     string   `json:"client"`
		ExpiryDays float64  `json:"expiryDays"`
		LimitGB    float64  `json:"limitGB"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	if len(body.IDs) == 0 {
		fail(w, 400, errors.New("pick at least one type"))
		return
	}
	if body.Client != "" && !reEmail.MatchString(body.Client) {
		fail(w, 400, errors.New("name may use letters, digits and . _ @ + - only"))
		return
	}
	byID := map[string]Preset{}
	for _, p := range presets {
		byID[p.ID] = p
	}
	cert := a.presetCert()
	var created []string
	err := a.cfg.Mutate(func(root *OMap) error {
		taken := map[int]bool{}
		for _, id := range body.IDs {
			p, ok := byID[id]
			if !ok {
				return fmt.Errorf("unknown type %q", id)
			}
			n := NewInbound{Protocol: p.Protocol, Network: p.Network, Security: p.Security, Method: p.Method, HeaderType: p.HeaderType}
			if p.Security == "tls" {
				if cert == nil {
					return errors.New("TLS types need a certificate: set SSL in the SSH menu first")
				}
				n.CertFile, n.KeyFile, n.ServerName = cert.CertFile, cert.KeyFile, cert.Domain
			}
			used := usedPorts(root)
			for i := 0; i < 50; i++ {
				port := suggestPort()
				if port != 0 && !taken[port] && !used[strconv.Itoa(port)] {
					n.Port = port
					break
				}
			}
			if n.Port == 0 {
				return errors.New("no free port found")
			}
			taken[n.Port] = true
			n.Tag = fmt.Sprintf("%s-%d", p.ID, n.Port)
			ib, err := BuildInbound(root, n)
			if err != nil {
				return fmt.Errorf("%s: %w", p.Label, err)
			}
			if body.Client != "" && supportsClients(ib) {
				c, err := NewClient(ib, body.Client)
				if err != nil {
					return err
				}
				setClients(ib, append(clientsOf(ib), c))
			}
			ensureOutbounds(root)
			root.Set("inbounds", append(asArr(root.Get("inbounds")), ib))
			created = append(created, n.Tag)
		}
		return nil
	})
	if err != nil {
		fail(w, 400, err)
		return
	}
	if body.Client != "" {
		a.store.Update(body.Client, func(m *ClientMeta) {
			applyLimits(m, clientReq{ExpiryDays: body.ExpiryDays, LimitGB: body.LimitGB}, true)
		})
	}
	writeJSONResp(w, 200, map[string]any{"ok": true, "created": created})
}

func (a *App) handleAddRelay(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tags []string `json:"tags"`
		Relay
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		fail(w, 400, err)
		return
	}
	if body.Address == "" || len(body.Tags) == 0 {
		fail(w, 400, errors.New("address and at least one inbound are needed"))
		return
	}
	if body.Port < 0 || body.Port > 65535 {
		fail(w, 400, errors.New("invalid port"))
		return
	}
	err := a.store.EditRelays(func(m map[string][]Relay) {
		for _, t := range body.Tags {
			dup := false
			for _, x := range m[t] {
				if x.Address == body.Address && x.Port == body.Port {
					dup = true
				}
			}
			if !dup {
				m[t] = append(m[t], body.Relay)
			}
		}
	})
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func (a *App) handleDelRelay(w http.ResponseWriter, r *http.Request) {
	tag, addr := r.URL.Query().Get("tag"), r.URL.Query().Get("address")
	port, _ := strconv.Atoi(r.URL.Query().Get("port"))
	err := a.store.EditRelays(func(m map[string][]Relay) {
		var keep []Relay
		for _, x := range m[tag] {
			if !(x.Address == addr && x.Port == port) {
				keep = append(keep, x)
			}
		}
		if len(keep) == 0 {
			delete(m, tag)
		} else {
			m[tag] = keep
		}
	})
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}

func presetKey(proto, network, security, method, header string) string {
	return proto + "|" + network + "|" + security + "|" + method + "|" + header
}

func tcpHeader(ib *OMap) string {
	ss := asMap(ib.Get("streamSettings"))
	t := asMap(ss.Get("tcpSettings"))
	if t == nil {
		t = asMap(ss.Get("rawSettings"))
	}
	if pathStr(t, "header", "type") == "http" {
		return "http"
	}
	return ""
}
