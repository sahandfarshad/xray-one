package main

// The middle server's ends of the carrier methods (carriers.go): the GRE
// link, frps, the Backhaul server and the SSH server, as the main server
// asks in every heartbeat.

import (
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
	go func() {
		defer agentCarrierBusy.Store(false)
		res := map[string]string{}
		dir := filepath.Join(agentDir, "carriers")
		if sp.GRE != nil {
			res[tunnelMethodGRE] = errText(greLink("xo-gre", sp.GRE.Remote, sp.GRE.Addr, sp.GRE.Peer))
		} else {
			greDrop("xo-gre")
		}
		if sp.FRP != nil {
			bin, err := agentCarrierBin(st, "frps")
			if err == nil {
				conf := filepath.Join(dir, "frps.toml")
				err = ensureUnit("xo-frps", unitFor("xray-one FRP server", bin, conf), conf, frpsConf(sp.FRP))
			}
			res[tunnelMethodFRP] = errText(err)
		} else {
			dropUnit("xo-frps", filepath.Join(dir, "frps.toml"))
		}
		if sp.BH != nil {
			bin, err := agentCarrierBin(st, "backhaul")
			if err == nil {
				conf := filepath.Join(dir, "backhaul.toml")
				err = ensureUnit("xo-bhs", unitFor("xray-one Backhaul server", bin, conf), conf, bhServerConf(sp.BH))
			}
			res[tunnelMethodBH] = errText(err)
		} else {
			dropUnit("xo-bhs", filepath.Join(dir, "backhaul.toml"))
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
	greDrop("xo-gre")
	dropUnit("xo-frps", "")
	dropUnit("xo-bhs", "")
}
