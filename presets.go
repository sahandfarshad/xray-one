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
	ID       string `json:"id"`
	Label    string `json:"label"`
	Group    string `json:"group"` // reality | tls | plain
	Protocol string `json:"protocol"`
	Network  string `json:"network"`
	Security string `json:"security"`
	Method   string `json:"method,omitempty"`
	Note     string `json:"note,omitempty"`
}

var presets = []Preset{
	{ID: "vless-tcp-reality", Label: "VLESS · TCP · REALITY (Vision)", Group: "reality", Protocol: "vless", Network: "tcp", Security: "reality", Note: "recommended"},
	{ID: "vless-xhttp-reality", Label: "VLESS · XHTTP · REALITY", Group: "reality", Protocol: "vless", Network: "xhttp", Security: "reality"},
	{ID: "vless-grpc-reality", Label: "VLESS · gRPC · REALITY", Group: "reality", Protocol: "vless", Network: "grpc", Security: "reality"},
	{ID: "trojan-tcp-reality", Label: "Trojan · TCP · REALITY", Group: "reality", Protocol: "trojan", Network: "tcp", Security: "reality"},
	{ID: "trojan-grpc-reality", Label: "Trojan · gRPC · REALITY", Group: "reality", Protocol: "trojan", Network: "grpc", Security: "reality"},

	{ID: "vless-tcp-tls", Label: "VLESS · TCP · TLS (Vision)", Group: "tls", Protocol: "vless", Network: "tcp", Security: "tls"},
	{ID: "vless-ws-tls", Label: "VLESS · WebSocket · TLS", Group: "tls", Protocol: "vless", Network: "ws", Security: "tls", Note: "CDN"},
	{ID: "vless-grpc-tls", Label: "VLESS · gRPC · TLS", Group: "tls", Protocol: "vless", Network: "grpc", Security: "tls", Note: "CDN"},
	{ID: "vless-xhttp-tls", Label: "VLESS · XHTTP · TLS", Group: "tls", Protocol: "vless", Network: "xhttp", Security: "tls", Note: "CDN"},
	{ID: "vless-httpupgrade-tls", Label: "VLESS · HTTPUpgrade · TLS", Group: "tls", Protocol: "vless", Network: "httpupgrade", Security: "tls", Note: "CDN"},
	{ID: "vmess-ws-tls", Label: "VMess · WebSocket · TLS", Group: "tls", Protocol: "vmess", Network: "ws", Security: "tls", Note: "CDN"},
	{ID: "vmess-grpc-tls", Label: "VMess · gRPC · TLS", Group: "tls", Protocol: "vmess", Network: "grpc", Security: "tls"},
	{ID: "vmess-httpupgrade-tls", Label: "VMess · HTTPUpgrade · TLS", Group: "tls", Protocol: "vmess", Network: "httpupgrade", Security: "tls", Note: "CDN"},
	{ID: "trojan-tcp-tls", Label: "Trojan · TCP · TLS", Group: "tls", Protocol: "trojan", Network: "tcp", Security: "tls"},
	{ID: "trojan-ws-tls", Label: "Trojan · WebSocket · TLS", Group: "tls", Protocol: "trojan", Network: "ws", Security: "tls", Note: "CDN"},
	{ID: "trojan-grpc-tls", Label: "Trojan · gRPC · TLS", Group: "tls", Protocol: "trojan", Network: "grpc", Security: "tls"},

	{ID: "vless-ws", Label: "VLESS · WebSocket (no TLS)", Group: "plain", Protocol: "vless", Network: "ws", Security: "none", Note: "relay / CDN over HTTP"},
	{ID: "vmess-tcp", Label: "VMess · TCP", Group: "plain", Protocol: "vmess", Network: "tcp", Security: "none"},
	{ID: "vmess-ws", Label: "VMess · WebSocket (no TLS)", Group: "plain", Protocol: "vmess", Network: "ws", Security: "none", Note: "relay / CDN over HTTP"},
	{ID: "ss-2022", Label: "Shadowsocks 2022 (AES-128)", Group: "plain", Protocol: "shadowsocks", Network: "tcp", Security: "none", Method: "2022-blake3-aes-128-gcm"},
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
			have[asStr(ib.Get("protocol"))+"|"+n+"|"+s] = inboundID(ib, i)
		}
	}
	out := []row{}
	for _, p := range presets {
		out = append(out, row{p, p.Security != "tls" || cert != nil, have[p.Protocol+"|"+p.Network+"|"+p.Security]})
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
			n := NewInbound{Protocol: p.Protocol, Network: p.Network, Security: p.Security, Method: p.Method}
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
			if body.Client != "" {
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
