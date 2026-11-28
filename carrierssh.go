package main

// The SSH method: an SSH server built into the agent on the middle server,
// and an SSH client here that logs in with this server's key and asks for a
// remote forward of 127.0.0.1:L there. Each connection to it comes back over
// SSH and goes to the local VLESS inbound here. On the wire it is plain SSH.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(x, y net.Conn) {
		_, _ = io.Copy(x, y)
		if c, ok := x.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// ---------- this server: one SSH client per middle server ----------

type sshWant struct {
	addr, hostKey string
	local, target int
}

type sshRun struct {
	want   sshWant
	cancel context.CancelFunc
}

type sshMgr struct {
	mu  sync.Mutex
	run map[string]*sshRun
}

var sshClients = &sshMgr{run: map[string]*sshRun{}}

func (m *sshMgr) sync(dir string, want map[string]sshWant) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.run {
		if w, ok := want[id]; !ok || w != r.want {
			r.cancel()
			delete(m.run, id)
		}
	}
	for id, w := range want {
		if m.run[id] != nil {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		m.run[id] = &sshRun{want: w, cancel: cancel}
		go sshForward(ctx, dir, id, w)
	}
}

func sshForward(ctx context.Context, dir, id string, w sshWant) {
	for ctx.Err() == nil {
		err := sshOnce(ctx, dir, id, w)
		setCarrierStatus(id, tunnelMethodSSH, errText(err))
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func sshOnce(ctx context.Context, dir, id string, w sshWant) error {
	signer, _, err := panelSigner(dir)
	if err != nil {
		return err
	}
	hk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(w.hostKey))
	if err != nil {
		return fmt.Errorf("middle server's SSH key: %v", err)
	}
	cfg := &ssh.ClientConfig{User: "xray-one", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hk), Timeout: 15 * time.Second}
	d := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", w.addr)
	if err != nil {
		return err
	}
	cc, chans, reqs, err := ssh.NewClientConn(raw, w.addr, cfg)
	if err != nil {
		raw.Close()
		return err
	}
	c := ssh.NewClient(cc, chans, reqs)
	defer c.Close()
	ln, err := c.Listen("tcp", "127.0.0.1:"+strconv.Itoa(w.local))
	if err != nil {
		return fmt.Errorf("remote forward: %v", err)
	}
	setCarrierStatus(id, tunnelMethodSSH, "")
	go func() { // keepalive, and stop on cancel
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				c.Close()
				return
			case <-t.C:
				if _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); err != nil {
					c.Close()
					return
				}
			}
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(conn net.Conn) {
			t, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(w.target), 5*time.Second)
			if err != nil {
				conn.Close()
				return
			}
			pipe(conn, t)
		}(conn)
	}
}

// ---------- middle server: the SSH server ----------

// newSSHHostKey: a middle server's host key made on this server (starting on
// SSH), as the agent stores it, and its public line.
func newSSHHostKey() (string, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "xray-one-agent")
	if err != nil {
		return "", "", err
	}
	sg, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(blk)), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sg.PublicKey()))), nil
}

// agentKeyDir: where the agent keeps its SSH host key (a var for tests).
var agentKeyDir = agentDir

// agentHostKey: the agent's own SSH host key (made once).
func agentHostKey() (ssh.Signer, error) {
	p := filepath.Join(agentKeyDir, "ssh_host_ed25519")
	if b, err := os.ReadFile(p); err == nil {
		return ssh.ParsePrivateKey(b)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "xray-one-agent")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

func agentHostPub() string {
	s, err := agentHostKey()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

type sshServer struct {
	spec   sshSpec
	ln     net.Listener
	err    string
	mu     sync.Mutex
	closed bool
	owner  *ssh.ServerConn // the main server's connection holding the forward
}

var agentSSH struct {
	sync.Mutex
	s *sshServer
}

// agentSSHSync runs (or stops) the SSH server; "" = fine.
func agentSSHSync(sp *sshSpec) string {
	agentSSH.Lock()
	defer agentSSH.Unlock()
	cur := agentSSH.s
	if cur != nil && (sp == nil || *sp != cur.spec) {
		cur.mu.Lock()
		cur.closed = true
		if cur.owner != nil {
			cur.owner.Close()
		}
		cur.mu.Unlock()
		cur.ln.Close()
		agentSSH.s = nil
		cur = nil
	}
	if sp == nil {
		return ""
	}
	if cur != nil {
		return cur.err
	}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(sp.Port))
	if err != nil {
		return fmt.Sprintf("SSH port %d: %v", sp.Port, err)
	}
	s := &sshServer{spec: *sp, ln: ln}
	agentSSH.s = s
	go s.serve()
	return ""
}

func (s *sshServer) serve() {
	host, err := agentHostKey()
	if err != nil {
		s.err = err.Error()
		return
	}
	auth, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.spec.Auth))
	if err != nil {
		s.err = "bad key from the main server"
		return
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(auth.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("no")
		},
		ServerVersion: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
	}
	cfg.AddHostKey(host)
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c, cfg)
	}
}

func (s *sshServer) handle(c net.Conn, cfg *ssh.ServerConfig) {
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetDeadline(time.Time{})
	defer sc.Close()
	go func() {
		for ch := range chans {
			_ = ch.Reject(ssh.Prohibited, "no")
		}
	}()
	var lns []net.Listener
	defer func() {
		for _, l := range lns {
			l.Close()
		}
	}()
	for r := range reqs {
		switch r.Type {
		case "tcpip-forward":
			var m struct {
				Addr string
				Port uint32
			}
			if ssh.Unmarshal(r.Payload, &m) != nil || int(m.Port) != s.spec.Local || (m.Addr != "127.0.0.1" && m.Addr != "localhost") {
				_ = r.Reply(false, nil)
				continue
			}
			// one main server: a new login takes the forward over from an old,
			// half-dead one
			s.mu.Lock()
			if s.owner != nil && s.owner != sc {
				s.owner.Close()
			}
			s.owner = sc
			s.mu.Unlock()
			var l net.Listener
			for i := 0; i < 10; i++ {
				if l, err = net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(s.spec.Local)); err == nil {
					break
				}
				time.Sleep(300 * time.Millisecond)
			}
			if err != nil {
				_ = r.Reply(false, nil)
				continue
			}
			lns = append(lns, l)
			p := make([]byte, 4)
			binary.BigEndian.PutUint32(p, m.Port)
			_ = r.Reply(true, p)
			go func(l net.Listener, addr string, port uint32) {
				for {
					conn, err := l.Accept()
					if err != nil {
						return
					}
					go func(conn net.Conn) {
						ra := conn.RemoteAddr().(*net.TCPAddr)
						pl := ssh.Marshal(struct {
							Addr       string
							Port       uint32
							OriginAddr string
							OriginPort uint32
						}{addr, port, ra.IP.String(), uint32(ra.Port)})
						ch, rq, err := sc.OpenChannel("forwarded-tcpip", pl)
						if err != nil {
							conn.Close()
							return
						}
						go ssh.DiscardRequests(rq)
						pipe(conn, chanConn{ch, conn})
					}(conn)
				}
			}(l, m.Addr, m.Port)
		case "cancel-tcpip-forward":
			for _, l := range lns {
				l.Close()
			}
			lns = nil
			_ = r.Reply(true, nil)
		default:
			if r.WantReply {
				_ = r.Reply(r.Type == "keepalive@openssh.com", nil)
			}
		}
	}
}

// chanConn: an SSH channel as a net.Conn (addresses borrowed from the TCP side).
type chanConn struct {
	ssh.Channel
	peer net.Conn
}

func (c chanConn) LocalAddr() net.Addr                { return c.peer.LocalAddr() }
func (c chanConn) RemoteAddr() net.Addr               { return c.peer.RemoteAddr() }
func (c chanConn) SetDeadline(t time.Time) error      { return nil }
func (c chanConn) SetReadDeadline(t time.Time) error  { return nil }
func (c chanConn) SetWriteDeadline(t time.Time) error { return nil }
func (c chanConn) CloseWrite() error                  { return c.Channel.CloseWrite() }
