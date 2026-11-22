package main

// VLESS Encryption keys, Vision testseed and fallbacks (the "Protocol" part of
// a VLESS / Trojan inbound).

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

const vlessEncName = "mlkem768x25519plus"

var defaultTestseed = []int{900, 500, 900, 256}

type Fallback struct {
	Name string `json:"name,omitempty"`
	Alpn string `json:"alpn,omitempty"`
	Path string `json:"path,omitempty"`
	Dest string `json:"dest"`
	Xver int    `json:"xver,omitempty"`
}

type ProtoOpts struct {
	Decryption string     `json:"decryption"`           // VLESS only; "none" = off
	Encryption string     `json:"encryption,omitempty"` // output only: what clients use
	Testseed   []int      `json:"testseed,omitempty"`
	Fallbacks  []Fallback `json:"fallbacks"`
}

// newVlessEnc makes a server decryption + client encryption pair.
// auth: x25519 (short links) or mlkem768 (post-quantum auth key, long links).
// mode: native, xorpub or random (how the handshake looks on the wire).
func newVlessEnc(auth, mode string) (dec, enc string, err error) {
	switch mode {
	case "", "native":
		mode = "native"
	case "xorpub", "random":
	default:
		return "", "", errors.New("mode must be native, xorpub or random")
	}
	var key string
	switch auth {
	case "", "x25519":
		key, _, err = genX25519()
		if err != nil {
			return
		}
	case "mlkem768":
		seed := make([]byte, mlkem.SeedSize)
		if _, err = rand.Read(seed); err != nil {
			return
		}
		key = base64.RawURLEncoding.EncodeToString(seed)
	default:
		return "", "", errors.New("auth must be x25519 or mlkem768")
	}
	dec = vlessEncName + "." + mode + ".600s." + key
	return dec, vlessClientEncryption(dec), nil
}

// vlessClientEncryption turns the server's decryption string into the client's
// (same mode and padding, 0-RTT, public half of the auth key).
func vlessClientEncryption(dec string) string {
	if dec == "" || dec == "none" {
		return "none"
	}
	p := strings.Split(dec, ".")
	if len(p) < 4 || p[0] != vlessEncName {
		return "none"
	}
	key := p[len(p)-1]
	b, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return "none"
	}
	var pub string
	switch len(b) {
	case 32:
		pub = pubFromPriv(key)
	case 64:
		dk, err := mlkem.NewDecapsulationKey768(b)
		if err != nil {
			return "none"
		}
		pub = base64.RawURLEncoding.EncodeToString(dk.EncapsulationKey().Bytes())
	}
	if pub == "" {
		return "none"
	}
	out := []string{p[0], p[1], "0rtt"}
	out = append(out, p[3:len(p)-1]...) // padding settings, if any
	return strings.Join(append(out, pub), ".")
}

// checkDecryption does the same shape checks xray does.
func checkDecryption(dec string) error {
	if dec == "none" {
		return nil
	}
	p := strings.Split(dec, ".")
	if len(p) < 4 || p[0] != vlessEncName {
		return errors.New(`decryption must be "none" or start with ` + vlessEncName)
	}
	switch p[1] {
	case "native", "xorpub", "random":
	default:
		return errors.New("decryption mode must be native, xorpub or random")
	}
	b, err := base64.RawURLEncoding.DecodeString(p[len(p)-1])
	if err != nil || (len(b) != 32 && len(b) != 64) {
		return errors.New("decryption key is not valid")
	}
	return nil
}

func sameInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// protoForm reads the Protocol part of an inbound.
func protoForm(ib *OMap) *ProtoOpts {
	proto := asStr(ib.Get("protocol"))
	if proto != "vless" && proto != "trojan" {
		return nil
	}
	s := asMap(ib.Get("settings"))
	o := &ProtoOpts{Fallbacks: []Fallback{}}
	if proto == "vless" {
		o.Decryption = orDefault(asStr(s.Get("decryption")), "none")
		o.Encryption = vlessClientEncryption(o.Decryption)
		o.Testseed = append([]int{}, defaultTestseed...)
		if ts := asArr(s.Get("testseed")); len(ts) >= 4 {
			for i := 0; i < 4; i++ {
				o.Testseed[i] = int(numOf(ts[i]))
			}
		}
	}
	for _, v := range asArr(s.Get("fallbacks")) {
		f := asMap(v)
		if f == nil {
			continue
		}
		o.Fallbacks = append(o.Fallbacks, Fallback{Name: asStr(f.Get("name")), Alpn: asStr(f.Get("alpn")),
			Path: asStr(f.Get("path")), Dest: asStr(f.Get("dest")), Xver: int(numOf(f.Get("xver")))})
	}
	return o
}

// applyProto writes decryption / testseed / fallbacks onto a built inbound.
func applyProto(ib *OMap, o *ProtoOpts) error {
	proto := asStr(ib.Get("protocol"))
	if o == nil || (proto != "vless" && proto != "trojan") {
		return nil
	}
	s := asMap(ib.Get("settings"))
	if s == nil {
		s = NewOMap()
		ib.Set("settings", s)
	}
	dec := "none"
	if proto == "vless" {
		dec = strings.TrimSpace(o.Decryption)
		if dec == "" {
			dec = "none"
		}
		if err := checkDecryption(dec); err != nil {
			return err
		}
		s.Set("decryption", dec)
		switch {
		case len(o.Testseed) == 0 || sameInts(o.Testseed, defaultTestseed):
			s.Delete("testseed")
		case len(o.Testseed) == 4:
			ts := make([]any, 4)
			for i, v := range o.Testseed {
				if v < 0 || v > 65535 {
					return errors.New("testseed numbers must be 0-65535")
				}
				ts[i] = v
			}
			s.Set("testseed", ts)
		default:
			return errors.New("testseed needs 4 numbers")
		}
	}
	if len(o.Fallbacks) == 0 {
		s.Delete("fallbacks")
		return nil
	}
	if dec != "none" {
		return errors.New("fallbacks can't be used together with VLESS Encryption")
	}
	if network, _ := streamInfo(ib); network != "tcp" && network != "raw" {
		return errors.New("fallbacks work only on TCP (raw) transport")
	}
	var fbs []any
	for i, f := range o.Fallbacks {
		f.Dest = strings.TrimSpace(f.Dest)
		if f.Dest == "" {
			return fmt.Errorf("fallback %d: dest is empty", i+1)
		}
		if f.Path != "" && !strings.HasPrefix(f.Path, "/") {
			return fmt.Errorf("fallback %d: path must start with /", i+1)
		}
		if f.Xver < 0 || f.Xver > 2 {
			return fmt.Errorf("fallback %d: xver must be 0, 1 or 2", i+1)
		}
		m := NewOMap()
		if f.Name != "" {
			m.Set("name", f.Name)
		}
		if f.Alpn != "" {
			m.Set("alpn", f.Alpn)
		}
		if f.Path != "" {
			m.Set("path", f.Path)
		}
		if p, err := strconv.Atoi(f.Dest); err == nil {
			m.Set("dest", p)
		} else {
			m.Set("dest", f.Dest)
		}
		if f.Xver > 0 {
			m.Set("xver", f.Xver)
		}
		fbs = append(fbs, m)
	}
	s.Set("fallbacks", fbs)
	return nil
}

// BuildInbound builds a new inbound, then applies the Protocol options.
func BuildInbound(root *OMap, n NewInbound) (*OMap, error) {
	ib, err := buildInboundBase(root, n)
	if err != nil {
		return nil, err
	}
	if n.Proto != nil {
		if err := applyProto(ib, n.Proto); err != nil {
			return nil, err
		}
	}
	return ib, nil
}

// GET /api/vless/enc?auth=x25519|mlkem768&mode=native|xorpub|random -> new pair
// GET /api/vless/enc?dec=... -> encryption for a given decryption
func (a *App) handleVlessEnc(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if d := strings.TrimSpace(q.Get("dec")); d != "" {
		if err := checkDecryption(d); err != nil {
			fail(w, 400, err)
			return
		}
		writeJSONResp(w, 200, map[string]string{"decryption": d, "encryption": vlessClientEncryption(d)})
		return
	}
	dec, enc, err := newVlessEnc(q.Get("auth"), q.Get("mode"))
	if err != nil {
		fail(w, 400, err)
		return
	}
	writeJSONResp(w, 200, map[string]string{"decryption": dec, "encryption": enc})
}
