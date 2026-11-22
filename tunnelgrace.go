package main

// Port change grace: when a rotating tunnel port moves, the old port keeps
// listening (same inbound, cloned) for a while, so middle servers still
// connected through it get their new relay config over the old port and
// then move to the new one without the tunnel ever going down.

import (
	"log"
	"strconv"
	"strings"
	"time"
)

const (
	gracePrefix = "xo-tunnel-g-"
	graceFor    = 30 * time.Minute
)

type tunnelGrace struct {
	Tag   string `json:"tag"` // the method inbound it copies
	Port  int    `json:"port"`
	Until int64  `json:"until"`
}

func isGraceTag(t string) bool { return strings.HasPrefix(t, gracePrefix) }

// graceHas: a grace inbound in root listens on p.
func graceHas(root *OMap, p int) bool {
	for _, v := range asArr(root.Get("inbounds")) {
		if x := asMap(v); x != nil && isGraceTag(asStr(x.Get("tag"))) && asStr(x.Get("port")) == strconv.Itoa(p) {
			return true
		}
	}
	return false
}

// applyGrace rebuilds the grace inbounds from the live ones and returns their
// tags (for the tunnel routing rules).
func applyGrace(root *OMap, set TunnelSettings) []any {
	var keep []any
	for _, v := range asArr(root.Get("inbounds")) {
		if !isGraceTag(asStr(asMap(v).Get("tag"))) {
			keep = append(keep, v)
		}
	}
	if keep == nil {
		keep = []any{}
	}
	root.Set("inbounds", keep)
	now := time.Now().Unix()
	cur := map[int]bool{set.Port: true, set.XPort: true, set.RPort: true, set.WGPort: true}
	var tags []any
	for _, g := range set.Grace {
		if g.Until <= now || cur[g.Port] || usedPorts(root)[strconv.Itoa(g.Port)] {
			continue
		}
		src, _ := findInbound(root, g.Tag)
		if src == nil {
			continue
		}
		c, err := ParseOrdered(EncodeIndent(src))
		if err != nil || asMap(c) == nil {
			continue
		}
		ib := asMap(c)
		kind := strings.TrimPrefix(strings.TrimPrefix(g.Tag, "xo-tunnel"), "-")
		if kind == "" {
			kind = "ws"
		}
		tag := gracePrefix + kind + "-" + strconv.Itoa(g.Port)
		ib.Set("tag", tag)
		ib.Set("port", g.Port)
		root.Set("inbounds", append(asArr(root.Get("inbounds")), ib))
		tags = append(tags, tag)
	}
	return tags
}

// graceLater drops the old ports once their time is up.
func (a *App) graceLater() {
	_, set, _ := a.store.TunnelsCopy()
	var next int64
	for _, g := range set.Grace {
		if next == 0 || g.Until < next {
			next = g.Until
		}
	}
	if next == 0 {
		return
	}
	d := time.Until(time.Unix(next, 0)) + 5*time.Second
	if d < 5*time.Second {
		d = 5 * time.Second
	}
	time.AfterFunc(d, func() {
		now := time.Now().Unix()
		_ = a.store.EditTunnels(func() error {
			var keep []tunnelGrace
			for _, g := range a.store.TunnelCfg.Grace {
				if g.Until > now {
					keep = append(keep, g)
				}
			}
			a.store.TunnelCfg.Grace = keep
			return nil
		})
		revMu.Lock()
		err := a.cfg.Mutate(func(root *OMap) error { return a.applyTunnelConfig(root) })
		revMu.Unlock()
		if err != nil {
			log.Printf("tunnel: closing old ports: %v", err)
		}
		a.graceLater()
	})
}
