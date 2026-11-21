package main

// Share links and subscription output (vless, vmess, trojan, shadowsocks).

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/curve25519"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func genX25519() (priv, pub string, err error) {
	k := make([]byte, 32)
	if _, err = rand.Read(k); err != nil {
		return
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return
	}
	return base64.RawURLEncoding.EncodeToString(k), base64.RawURLEncoding.EncodeToString(p), nil
}

func pubFromPriv(priv string) string {
	k, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(priv, "="))
	if err != nil || len(k) != 32 {
		return ""
	}
	p, err := curve25519.X25519(k, curve25519.Basepoint)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(p)
}

type streamParams struct {
	network, security       string
	sni, fp, alpn           string
	pbk, sid, spx           string
	path, host, serviceName string
	headerType, mode        string
	seed                    string
}

func readStream(ib *OMap, host string) streamParams {
	p := streamParams{}
	p.network, p.security = streamInfo(ib)
	ss := asMap(ib.Get("streamSettings"))
	switch p.security {
	case "tls":
		t := asMap(ss.Get("tlsSettings"))
		p.sni = orDefault(asStr(t.Get("serverName")), host)
		p.fp = orDefault(asStr(t.Get("fingerprint")), "chrome")
		var al []string
		for _, a := range asArr(t.Get("alpn")) {
			al = append(al, asStr(a))
		}
		p.alpn = strings.Join(al, ",")
	case "reality":
		r := asMap(ss.Get("realitySettings"))
		if sn := asArr(r.Get("serverNames")); len(sn) > 0 {
			p.sni = asStr(sn[0])
		}
		if sid := asArr(r.Get("shortIds")); len(sid) > 0 {
			p.sid = asStr(sid[0])
		}
		p.pbk = pubFromPriv(asStr(r.Get("privateKey")))
		p.fp = "chrome"
		if st := asMap(r.Get("settings")); st != nil {
			p.fp = orDefault(asStr(st.Get("fingerprint")), "chrome")
			if v := asStr(st.Get("spiderX")); v != "" && v != "/" {
				p.spx = v
			}
		}
	}
	switch p.network {
	case "ws":
		w := asMap(ss.Get("wsSettings"))
		p.path = asStr(w.Get("path"))
		p.host = orDefault(asStr(w.Get("host")), pathStr(w, "headers", "Host"))
	case "grpc":
		p.serviceName = pathStr(ss, "grpcSettings", "serviceName")
	case "xhttp", "splithttp":
		x := asMap(ss.Get("xhttpSettings"))
		if x == nil {
			x = asMap(ss.Get("splithttpSettings"))
		}
		p.path = asStr(x.Get("path"))
		p.host = asStr(x.Get("host"))
		p.mode = asStr(x.Get("mode"))
	case "httpupgrade":
		h := asMap(ss.Get("httpupgradeSettings"))
		p.path = asStr(h.Get("path"))
		p.host = asStr(h.Get("host"))
	case "tcp", "raw":
		t := asMap(ss.Get("tcpSettings"))
		if t == nil {
			t = asMap(ss.Get("rawSettings"))
		}
		if pathStr(t, "header", "type") == "http" {
			p.headerType = "http"
			if ps := asArr(path(t, "header", "request", "path")); len(ps) > 0 {
				p.path = asStr(ps[0])
			}
			if hs := asArr(path(t, "header", "request", "headers", "Host")); len(hs) > 0 {
				p.host = asStr(hs[0])
			}
		}
	case "kcp", "mkcp":
		k := asMap(ss.Get("kcpSettings"))
		p.headerType = orDefault(pathStr(k, "header", "type"), "none")
		p.seed = asStr(k.Get("seed"))
	}
	return p
}

func (p streamParams) query(q url.Values) {
	q.Set("type", p.network)
	q.Set("security", p.security)
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("sni", p.sni)
	set("fp", p.fp)
	set("alpn", p.alpn)
	set("pbk", p.pbk)
	set("sid", p.sid)
	set("spx", p.spx)
	set("path", p.path)
	set("host", p.host)
	set("serviceName", p.serviceName)
	set("headerType", p.headerType)
	set("mode", p.mode)
	set("seed", p.seed)
}

func linkPort(ib *OMap) string {
	p := asStr(ib.Get("port"))
	return strings.SplitN(strings.SplitN(p, ",", 2)[0], "-", 2)[0]
}

// ClientLink builds the share link of one client on one inbound.
func ClientLink(ib *OMap, c *OMap, host string) string {
	return clientLinkAt(ib, c, host, Relay{})
}

// ClientLinks returns the direct link followed by one link per relay.
func ClientLinks(ib *OMap, c *OMap, host string, relays []Relay) (string, []string) {
	var rl []string
	for _, r := range relays {
		rl = append(rl, clientLinkAt(ib, c, host, r))
	}
	return clientLinkAt(ib, c, host, Relay{}), rl
}

// singleUserSS gives the link of a shadowsocks inbound without a clients list.
func singleUserSS(ib *OMap, host string, r Relay) string {
	if pr := asStr(ib.Get("protocol")); pr == "socks" || pr == "http" {
		acc := asArr(path(ib, "settings", "accounts"))
		if len(acc) == 0 {
			return ""
		}
		a := asMap(acc[0])
		if a == nil {
			return ""
		}
		return clientLinkAt(ib, om("user", asStr(a.Get("user")), "pass", asStr(a.Get("pass")), "email", ""), host, r)
	}
	if asStr(ib.Get("protocol")) != "shadowsocks" || len(clientsOf(ib)) > 0 || path(ib, "settings", "clients") != nil {
		return ""
	}
	pass := pathStr(ib, "settings", "password")
	if pass == "" {
		return ""
	}
	return clientLinkAt(ib, om("password", pass, "email", "", "_single", true), host, r)
}

// clientLinkAt builds a link that connects to relay r (when set) while TLS
// SNI / REALITY / host headers stay those of the real server.
func clientLinkAt(ib *OMap, c *OMap, host string, r Relay) string {
	if host == "" {
		host = "SERVER_IP"
	}
	proto := asStr(ib.Get("protocol"))
	email := asStr(c.Get("email"))
	label := strings.Trim(email+"-"+asStr(ib.Get("tag")), "-")
	port := linkPort(ib)
	addr := host
	if r.Address != "" {
		addr = r.Address
		if r.Port > 0 {
			port = strconv.Itoa(r.Port)
		}
		label += "-" + orDefault(r.Name, "relay")
	}
	name := url.PathEscape(label)
	hp := addr + ":" + port
	if strings.Contains(addr, ":") && !strings.HasPrefix(addr, "[") {
		hp = "[" + addr + "]:" + port
	}
	sp := readStream(ib, host)
	if r.Address != "" && sp.host == "" && (sp.network == "ws" || sp.network == "httpupgrade" || sp.network == "xhttp") {
		if sp.security == "tls" && sp.sni != "" {
			sp.host = sp.sni
		} else if isDomain(host) {
			sp.host = host
		}
	}
	switch proto {
	case "vless":
		q := url.Values{}
		q.Set("encryption", vlessClientEncryption(pathStr(ib, "settings", "decryption")))
		if f := asStr(c.Get("flow")); f != "" {
			q.Set("flow", f)
		}
		sp.query(q)
		return "vless://" + asStr(c.Get("id")) + "@" + hp + "?" + q.Encode() + "#" + name
	case "trojan":
		q := url.Values{}
		sp.query(q)
		return "trojan://" + url.PathEscape(asStr(c.Get("password"))) + "@" + hp + "?" + q.Encode() + "#" + name
	case "vmess":
		tls := ""
		if sp.security == "tls" {
			tls = "tls"
		}
		pth := sp.path
		if sp.network == "grpc" {
			pth = sp.serviceName
		}
		if sp.network == "kcp" {
			pth = sp.seed
		}
		obj := map[string]string{"v": "2", "ps": label, "add": addr, "port": port,
			"id": asStr(c.Get("id")), "aid": "0", "scy": "auto", "net": sp.network, "type": orDefault(sp.headerType, "none"),
			"host": sp.host, "path": pth, "tls": tls, "sni": sp.sni, "fp": sp.fp}
		b, _ := json.Marshal(obj)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "hysteria":
		q := url.Values{}
		q.Set("sni", sp.sni)
		q.Set("alpn", "h3")
		q.Set("insecure", "0")
		return "hysteria2://" + url.PathEscape(asStr(c.Get("auth"))) + "@" + hp + "/?" + q.Encode() + "#" + name
	case "wireguard":
		q := url.Values{}
		q.Set("publickey", wgPub(pathStr(ib, "settings", "secretKey")))
		if a := asArr(c.Get("allowedIPs")); len(a) > 0 {
			q.Set("address", asStr(a[0]))
		}
		q.Set("mtu", orDefault(pathStr(ib, "settings", "mtu"), "1420"))
		return "wireguard://" + url.QueryEscape(asStr(c.Get("privateKey"))) + "@" + hp + "?" + q.Encode() + "#" + name
	case "socks":
		return "socks://" + base64.StdEncoding.EncodeToString([]byte(asStr(c.Get("user"))+":"+asStr(c.Get("pass")))) + "@" + hp + "#" + name
	case "http":
		return "http://" + url.PathEscape(asStr(c.Get("user"))) + ":" + url.PathEscape(asStr(c.Get("pass"))) + "@" + hp + "#" + name
	case "shadowsocks":
		method := orDefault(asStr(c.Get("method")), pathStr(ib, "settings", "method"))
		pass := asStr(c.Get("password"))
		if strings.HasPrefix(method, "2022-") {
			if sp := pathStr(ib, "settings", "password"); sp != "" && c.Get("_single") == nil {
				pass = sp + ":" + pass
			}
			return "ss://" + url.PathEscape(method) + ":" + url.PathEscape(pass) + "@" + hp + "#" + name
		}
		ui := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + pass))
		return "ss://" + ui + "@" + hp + "#" + name
	}
	return ""
}

func isDomain(h string) bool {
	return h != "" && h != "SERVER_IP" && net.ParseIP(strings.Trim(h, "[]")) == nil
}
