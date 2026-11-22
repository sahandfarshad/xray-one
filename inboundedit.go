package main

// Edit an existing inbound: port, transport, security (TLS / REALITY).
// Protocol, tag, clients and unknown keys stay as they are.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func strList(v any) []string {
	var out []string
	for _, x := range asArr(v) {
		if s := asStr(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func numOf(v any) int64 {
	n, _ := strconv.ParseInt(asStr(v), 10, 64)
	return n
}

// inboundForm reads an inbound back into the Add-inbound form shape.
func inboundForm(ib *OMap) NewInbound {
	n := NewInbound{Protocol: asStr(ib.Get("protocol")), Tag: asStr(ib.Get("tag")), HeaderType: "none"}
	if n.Protocol == "vless" {
		n.VlessEnc = "none"
		if strings.HasPrefix(pathStr(ib, "settings", "decryption"), vlessEncName) {
			n.VlessEnc = vlessEncName
		}
	}
	n.Proto = protoForm(ib)
	n.Port = int(numOf(ib.Get("port")))
	n.Network, n.Security = streamInfo(ib)
	if n.Network == "raw" {
		n.Network = "tcp"
	}
	ss := asMap(ib.Get("streamSettings"))
	switch n.Network {
	case "ws":
		n.Path = asStr(asMap(ss.Get("wsSettings")).Get("path"))
	case "xhttp":
		n.Path = asStr(asMap(ss.Get("xhttpSettings")).Get("path"))
	case "httpupgrade":
		n.Path = asStr(asMap(ss.Get("httpupgradeSettings")).Get("path"))
	case "grpc":
		n.ServiceName = asStr(asMap(ss.Get("grpcSettings")).Get("serviceName"))
	case "tcp":
		t := asMap(ss.Get("tcpSettings"))
		if t == nil {
			t = asMap(ss.Get("rawSettings"))
		}
		if h := asMap(t.Get("header")); h != nil {
			n.HeaderType = orDefault(asStr(h.Get("type")), "none")
		}
	}
	switch n.Security {
	case "tls":
		t := asMap(ss.Get("tlsSettings"))
		n.ServerName = asStr(t.Get("serverName"))
		if c := asArr(t.Get("certificates")); len(c) > 0 {
			n.CertFile = asStr(asMap(c[0]).Get("certificateFile"))
			n.KeyFile = asStr(asMap(c[0]).Get("keyFile"))
		}
	case "reality":
		r := asMap(ss.Get("realitySettings"))
		st := asMap(r.Get("settings"))
		o := &RealityOpts{
			Show:         asStr(r.Get("show")) == "true",
			Xver:         int(numOf(r.Get("xver"))),
			Fingerprint:  orDefault(asStr(st.Get("fingerprint")), "chrome"),
			Target:       orDefault(asStr(r.Get("target")), asStr(r.Get("dest"))),
			ServerNames:  strList(r.Get("serverNames")),
			MaxTimeDiff:  numOf(r.Get("maxTimeDiff")),
			MinClientVer: asStr(r.Get("minClientVer")),
			MaxClientVer: asStr(r.Get("maxClientVer")),
			ShortIDs:     strList(r.Get("shortIds")),
			SpiderX:      orDefault(asStr(st.Get("spiderX")), "/"),
			PrivateKey:   asStr(r.Get("privateKey")),
		}
		for _, v := range asArr(r.Get("shortIds")) { // keep an empty short ID
			if asStr(v) == "" {
				o.ShortIDs = append(o.ShortIDs, "")
				break
			}
		}
		n.Reality = o
	}
	return n
}

func editableInbound(root *OMap, ib *OMap) error {
	tag := asStr(ib.Get("tag"))
	if tag == tunnelTag || (apiTag(root) != "" && tag == apiTag(root)) {
		return errors.New("system inbound cannot be edited")
	}
	switch asStr(ib.Get("protocol")) {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria", "socks", "http", "wireguard":
	default:
		return fmt.Errorf("protocol %q cannot be edited here", asStr(ib.Get("protocol")))
	}
	if _, p := targetOf(ib); p == 0 {
		return errors.New("inbounds with a port range cannot be edited here")
	}
	return nil
}

func (a *App) handleInboundDetail(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	root, _, err := a.cfg.Load()
	if err != nil {
		fail(w, 500, err)
		return
	}
	ib, _ := findInbound(root, id)
	if ib == nil {
		fail(w, 404, errors.New("inbound not found"))
		return
	}
	if err := editableInbound(root, ib); err != nil {
		fail(w, 400, err)
		return
	}
	n := inboundForm(ib)
	pub := ""
	if n.Reality != nil {
		pub = pubFromPriv(n.Reality.PrivateKey)
	}
	writeJSONResp(w, 200, map[string]any{"id": id, "form": n, "publicKey": pub})
}

func (a *App) handleEditInbound(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
		NewInbound
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.ID == "" {
		fail(w, 400, errors.New("bad request"))
		return
	}
	n := b.NewInbound
	n.Reality = b.Reality
	var servers []string
	var backup map[string][]TunnelUse
	err := a.cfg.Mutate(func(root *OMap) error {
		ib, idx := findInbound(root, b.ID)
		if ib == nil {
			return errors.New("inbound not found")
		}
		if err := editableInbound(root, ib); err != nil {
			return err
		}
		old := inboundForm(ib)
		n.Protocol, n.Tag = old.Protocol, old.Tag
		if n.Protocol == "shadowsocks" {
			n.Method = asStr(asMap(ib.Get("settings")).Get("method"))
		}
		if n.Port != old.Port && !portFree(n.Port) {
			return fmt.Errorf("port %d is already in use on this server", n.Port)
		}
		// build the new inbound against the config without this one
		all := asArr(root.Get("inbounds"))
		others := make([]any, 0, len(all))
		for i, v := range all {
			if i != idx {
				others = append(others, v)
			}
		}
		root.Set("inbounds", others)
		nb, err := BuildInbound(root, n)
		root.Set("inbounds", all)
		if err != nil {
			return err
		}
		ib.Set("port", n.Port)
		if ns := asMap(nb.Get("streamSettings")); ns != nil {
			if os := asMap(ib.Get("streamSettings")); os != nil {
				for _, k := range []string{"sockopt", "finalmask"} {
					if v := os.Get(k); v != nil {
						ns.Set(k, v)
					}
				}
			}
			ib.Set("streamSettings", ns)
		}
		if n.Proto != nil {
			if err := applyProto(ib, n.Proto); err != nil {
				return err
			}
		} else if n.Protocol == "vless" && n.VlessEnc != "" && n.VlessEnc != old.VlessEnc {
			if s := asMap(ib.Get("settings")); s != nil {
				s.Set("decryption", pathStr(nb, "settings", "decryption"))
			}
		}
		// VLESS Vision flow only fits TCP + TLS/REALITY/Encryption
		if n.Protocol == "vless" {
			vision := visionOK(ib)
			for _, c := range asArr(asMap(ib.Get("settings")).Get("clients")) {
				cm := asMap(c)
				if cm == nil || isTunnelEmail(asStr(cm.Get("email"))) {
					continue
				}
				if vision && asStr(cm.Get("flow")) == "" {
					cm.Set("flow", "xtls-rprx-vision")
				} else if !vision && cm.Get("flow") != nil {
					cm.Delete("flow")
				}
			}
		}
		// tunnels follow the new port
		if n.Port != old.Port {
			ibPorts := map[string]int{}
			for i, v := range asArr(root.Get("inbounds")) {
				if x := asMap(v); x != nil {
					_, ibPorts[inboundID(x, i)] = targetOf(x)
				}
			}
			if err := a.store.EditTunnels(func() error {
				uses := a.store.TunnelUse[b.ID]
				if len(uses) == 0 {
					return nil
				}
				backup = map[string][]TunnelUse{b.ID: append([]TunnelUse{}, uses...)}
				ok, err := a.store.checkUsesLocked(b.ID, uses, n.Port, ibPorts)
				if err != nil {
					return fmt.Errorf("tunnel: %v", err)
				}
				if len(ok) != len(uses) {
					return errors.New("tunnel: the new port is busy on a middle server")
				}
				a.store.TunnelUse[b.ID] = ok
				for _, u := range ok {
					servers = append(servers, u.Server)
				}
				return nil
			}); err != nil {
				return err
			}
			return a.applyTunnelConfig(root)
		}
		return nil
	})
	if err != nil {
		if backup != nil {
			_ = a.store.EditTunnels(func() error {
				for k, v := range backup {
					a.store.TunnelUse[k] = v
				}
				return nil
			})
		}
		fail(w, 400, err)
		return
	}
	for _, s := range servers {
		hub.Poke(s)
	}
	writeJSONResp(w, 200, map[string]bool{"ok": true})
}
