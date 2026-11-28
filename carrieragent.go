package main

// The middle server's ends of the carrier methods (carriers.go): the GRE
// link, frps, the Backhaul server and the SSH server, as the main server
// asks in every heartbeat.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

var agentCarrierBusy atomic.Bool

var agentCState = struct {
	sync.Mutex
	m map[string]string // method -> error ("" ok)
}{m: map[string]string{}}

func agentCarrierState() map[string]string {
	agentCState.Lock()
	defer agentCState.Unlock()
	out := map[string]string{}
	for k, v := range agentCState.m {
		out[k] = v
	}
	return out
}

// agentCarriers applies sp in the background (one run at a time); nil (an
// older main server) leaves everything as it is.
func agentCarriers(sp *carrierSpec, st agentState) {
	if sp == nil || !agentCarrierBusy.CompareAndSwap(false, true) {
		return
	}
	// kept for the next start: a carrier may be the only way to the main
	// server, so it must come up before the first heartbeat
	if b, err := json.Marshal(sp); err == nil {
		p := filepath.Join(agentDir, "carriers.json")
		if cur, _ := os.ReadFile(p); string(cur) != string(b) {
			_ = os.WriteFile(p, b, 0o600)
		}
	}
	go func() {
		defer agentCarrierBusy.Store(false)
		res := map[string]string{}
		dir := filepath.Join(agentDir, "carriers")
		if sp.GRE != nil {
			if n := greOther(); n != 0 {
				greDrop(instName("xo-gre"))
				res[tunnelMethodGRE] = fmt.Sprintf("GRE is used here by main server %d", n)
			} else {
				res[tunnelMethodGRE] = errText(greLink(instName("xo-gre"), sp.GRE.Remote, sp.GRE.Addr, sp.GRE.Peer))
			}
		} else {
			greDrop(instName("xo-gre"))
		}
		if sp.FRP != nil {
			bin, err := agentCarrierBin(st, "frps")
			if err == nil {
				conf := filepath.Join(dir, "frps.toml")
				err = ensureUnit(instName("xo-frps"), unitFor("xray-one FRP server", bin, conf), conf, frpsConf(sp.FRP))
			}
			res[tunnelMethodFRP] = errText(err)
		} else {
			dropUnit(instName("xo-frps"), filepath.Join(dir, "frps.toml"))
		}
		if sp.BH != nil {
			bin, err := agentCarrierBin(st, "backhaul")
			if err == nil {
				conf := filepath.Join(dir, "backhaul.toml")
				err = ensureUnit(instName("xo-bhs"), unitFor("xray-one Backhaul server", bin, conf), conf, bhServerConf(sp.BH))
			}
			res[tunnelMethodBH] = errText(err)
		} else {
			dropUnit(instName("xo-bhs"), filepath.Join(dir, "backhaul.toml"))
		}
		if e := agentSSHSync(sp.SSH); sp.SSH != nil {
			res[tunnelMethodSSH] = e
		}
		agentCState.Lock()
		agentCState.m = res
		agentCState.Unlock()
	}()
}

// agentCarriersRemove: everything the carriers left on this server.
func agentCarriersRemove() {
	greDrop(instName("xo-gre"))
	dropUnit(instName("xo-frps"), "")
	dropUnit(instName("xo-bhs"), "")
}

// agentCarriersBoot brings up what the carriers ran before (or what the join
// code asks for when this server never reached the main server yet).
func agentCarriersBoot(st agentState) {
	var sp *carrierSpec
	if b, err := os.ReadFile(filepath.Join(agentDir, "carriers.json")); err == nil {
		var x carrierSpec
		if json.Unmarshal(b, &x) == nil {
			sp = &x
		}
	}
	if sp == nil {
		sp = st.Join.CS
	}
	agentCarriers(sp, st)
}
