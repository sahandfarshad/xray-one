package main

// Subscription page: the same /sub/{token} link shows a small page when it
// is opened in a browser (usage, expiry, configs with QR, app downloads,
// WireGuard files). VPN apps keep getting the plain base64 list.

import (
	"bytes"
	crand "crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

//go:embed subpage.html
var subPageHTML string

var subTmpl = template.Must(template.New("sub").Funcs(template.FuncMap{
	"safeURL": func(s string) template.URL { return template.URL(s) },
}).Parse(subPageHTML))

// wantsSubPage is true for a browser asking for a page, never for VPN apps,
// which do not send text/html in Accept.
func wantsSubPage(r *http.Request) bool {
	q := r.URL.Query()
	if q.Has("raw") {
		return false
	}
	if q.Has("page") {
		return true
	}
	ua := strings.ToLower(r.UserAgent())
	for _, app := range []string{"v2ray", "hiddify", "streisand", "v2box", "clash", "sing-box", "singbox", "shadowrocket", "nekobox", "nekoray", "happ", "foxray", "karing", "mihomo", "stash", "quantumult", "surge", "loon"} {
		if strings.Contains(ua, app) {
			return false
		}
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html") && strings.Contains(ua, "mozilla")
}

type subCfg struct {
	Name, Link, QR string
}

type subWG struct {
	Name, File, Conf, QR string
}

type subApp struct {
	Name, Platforms, Download, Import string
	Store                             []subStore
}

type subStore struct{ Label, URL string }

type subView struct {
	Lang, Dir, Nonce          string
	T                         map[string]string
	Name                      string
	State, StateText          string
	Used, Total, Left, Up, Dn string
	Pct                       int
	Unlimited                 bool
	Expiry, DaysLeft          string
	Never                     bool
	SubURL, SubQR             string
	Configs                   []subCfg
	WG                        []subWG
	Apps                      []subApp
	OtherLang                 string
}

var subText = map[string]map[string]string{
	"fa": {
		"title": "اشتراک", "used": "مصرف شده", "of": "از", "left": "باقی‌مانده", "unlimited": "نامحدود", "up": "آپلود", "down": "دانلود",
		"expiry": "انقضا", "never": "بدون تاریخ انقضا", "days": "روز", "today": "امروز",
		"active": "فعال", "expired": "منقضی شده", "traffic": "حجم تمام شده", "paused": "متوقف",
		"sub": "لینک اشتراک", "subHint": "این لینک را در برنامه اضافه کنید تا همه‌ی کانفیگ‌ها خودکار به‌روز شوند.",
		"copy": "کپی", "copied": "کپی شد", "qr": "QR", "add": "افزودن به برنامه",
		"configs": "کانفیگ‌ها", "wg": "وایرگارد", "wgHint": "فایل را در برنامه‌ی رسمی WireGuard وارد کنید یا QR را اسکن کنید.", "wgFile": "دانلود فایل",
		"apps": "برنامه‌ها", "download": "دانلود", "none": "کانفیگ فعالی وجود ندارد.", "theme": "تاریک / روشن", "lang": "English",
	},
	"en": {
		"title": "Subscription", "used": "Used", "of": "of", "left": "left", "unlimited": "Unlimited", "up": "Upload", "down": "Download",
		"expiry": "Expires", "never": "No expiry date", "days": "days", "today": "today",
		"active": "Active", "expired": "Expired", "traffic": "Data used up", "paused": "Paused",
		"sub": "Subscription link", "subHint": "Add this link to your app so every config updates by itself.",
		"copy": "Copy", "copied": "Copied", "qr": "QR", "add": "Add to app",
		"configs": "Configs", "wg": "WireGuard", "wgHint": "Import the file into the official WireGuard app, or scan the QR.", "wgFile": "Download file",
		"apps": "Apps", "download": "Download", "none": "No active configs.", "theme": "Dark / Light", "lang": "فارسی",
	},
}

func qrData(s string) string {
	png, err := qrcode.Encode(s, qrcode.Medium, 300)
	if err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	v := float64(n) / 1024
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if v >= 100 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return fmt.Sprintf("%.2f %s", v, units[i])
}

func linkName(l string) string {
	if i := strings.LastIndex(l, "#"); i >= 0 {
		if s, err := url.QueryUnescape(l[i+1:]); err == nil && s != "" {
			return s
		}
		return l[i+1:]
	}
	if i := strings.Index(l, "://"); i > 0 {
		return strings.ToUpper(l[:i])
	}
	return "config"
}

// wgConfFromLink turns a wireguard:// link into a .conf for the official app.
func wgConfFromLink(l string) (name, file, conf string) {
	u, err := url.Parse("http" + strings.TrimPrefix(l, "wireguard"))
	if err != nil {
		return "", "", ""
	}
	q := u.Query()
	name = linkName(l)
	priv := u.User.Username()
	if p, err := url.QueryUnescape(priv); err == nil {
		priv = p
	}
	port := u.Port()
	if port == "" {
		port = "51820"
	}
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	addr := q.Get("address")
	if addr == "" {
		addr = "10.0.0.2/32"
	}
	mtu := q.Get("mtu")
	if mtu == "" {
		mtu = "1420"
	}
	conf = strings.Join([]string{"[Interface]", "PrivateKey = " + priv, "Address = " + addr, "DNS = 1.1.1.1, 8.8.8.8", "MTU = " + mtu, "",
		"[Peer]", "PublicKey = " + q.Get("publickey"), "AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = " + host + ":" + port, "PersistentKeepalive = 25", ""}, "\n")
	f := strings.Map(func(r rune) rune {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_=+.-", r)) {
			return r
		}
		return -1
	}, name)
	if len(f) > 15 {
		f = f[:15]
	}
	if f == "" {
		f = "wg"
	}
	return name, f + ".conf", conf
}

func (a *App) subPublicURL(tok string) string {
	base := a.store.Cfg.SubBase
	if base == "" {
		base = a.PanelURL()
	}
	return strings.TrimRight(base, "/") + "/sub/" + tok
}

func (a *App) serveSubPage(w http.ResponseWriter, r *http.Request, m *ClientMeta, links []string) {
	lang := "fa"
	if l := r.URL.Query().Get("lang"); l == "en" || l == "fa" {
		lang = l
	} else if al := strings.ToLower(r.Header.Get("Accept-Language")); al != "" && !strings.HasPrefix(al, "fa") {
		lang = "en"
	}
	T := subText[lang]
	nb := make([]byte, 12)
	_, _ = crand.Read(nb)
	v := subView{Lang: lang, Dir: "rtl", Nonce: base64.StdEncoding.EncodeToString(nb), T: T, Name: m.Email, OtherLang: "en"}
	if lang == "en" {
		v.Dir, v.OtherLang = "ltr", "fa"
	}
	used := m.Up + m.Down
	v.Used, v.Up, v.Dn = humanBytes(used), humanBytes(m.Up), humanBytes(m.Down)
	if m.LimitBytes > 0 {
		v.Total = humanBytes(m.LimitBytes)
		left := m.LimitBytes - used
		if left < 0 {
			left = 0
		}
		v.Left = humanBytes(left)
		v.Pct = int(math.Min(100, math.Round(float64(used)*100/float64(m.LimitBytes))))
	} else {
		v.Unlimited = true
	}
	if m.ExpiryUnix > 0 {
		t := time.Unix(m.ExpiryUnix, 0)
		v.Expiry = t.Format("2006-01-02")
		d := int(math.Ceil(time.Until(t).Hours() / 24))
		switch {
		case d > 0:
			v.DaysLeft = fmt.Sprintf("%d %s", d, T["days"])
		case time.Until(t) > 0:
			v.DaysLeft = T["today"]
		}
	} else {
		v.Never = true
	}
	switch {
	case !m.Disabled:
		v.State, v.StateText = "ok", T["active"]
	case m.Reason == "expired":
		v.State, v.StateText = "bad", T["expired"]
	case m.Reason == "traffic":
		v.State, v.StateText = "bad", T["traffic"]
	default:
		v.State, v.StateText = "bad", T["paused"]
	}
	v.SubURL = a.subPublicURL(m.SubToken)
	v.SubQR = qrData(v.SubURL)
	for _, l := range links {
		if strings.HasPrefix(l, "wireguard://") {
			n, f, c := wgConfFromLink(l)
			if c != "" {
				v.WG = append(v.WG, subWG{Name: n, File: f, Conf: c, QR: qrData(c)})
			}
			continue
		}
		v.Configs = append(v.Configs, subCfg{Name: linkName(l), Link: l, QR: qrData(l)})
	}
	su, title := url.QueryEscape(v.SubURL), url.PathEscape(m.Email)
	if len(v.Configs) > 0 {
		v.Apps = []subApp{
			{Name: "v2rayNG", Platforms: "Android", Download: "https://github.com/2dust/v2rayNG/releases/latest", Import: "v2rayng://install-sub?url=" + su + "&name=" + title},
			{Name: "Hiddify", Platforms: "Android · iOS · Windows · macOS · Linux", Download: "https://github.com/hiddify/hiddify-app/releases/latest", Import: "hiddify://import/" + v.SubURL + "#" + title,
				Store: []subStore{{"Google Play", "https://play.google.com/store/apps/details?id=app.hiddify.com"}, {"App Store", "https://apps.apple.com/app/id6596777532"}}},
			{Name: "Streisand", Platforms: "iOS · macOS", Download: "https://apps.apple.com/app/id6450534064", Import: "streisand://import/" + v.SubURL + "#" + title},
			{Name: "V2Box", Platforms: "iOS · macOS", Download: "https://apps.apple.com/app/id6446814690", Import: "v2box://install-sub?url=" + su + "&name=" + title},
		}
	}
	if len(v.WG) > 0 {
		v.Apps = append(v.Apps, subApp{Name: "WireGuard", Platforms: "Android · iOS · Windows · macOS · Linux", Download: "https://www.wireguard.com/install/"})
	}
	var buf bytes.Buffer
	if err := subTmpl.Execute(&buf, v); err != nil {
		http.Error(w, "page error", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'nonce-"+v.Nonce+"'; base-uri 'none'; form-action 'none'")
	_, _ = w.Write(buf.Bytes())
}
