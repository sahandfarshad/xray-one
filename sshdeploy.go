package main

// Native SSH for deploying the tunnel agent on a middle server. The host key
// is trusted on first use and pinned; when a password is given, the panel's
// own key is installed so the password is never needed (or kept) again.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func panelSigner(dir string) (ssh.Signer, string, error) {
	p := panelSSHKeyPath(dir)
	if b, err := os.ReadFile(p); err == nil {
		s, err := ssh.ParsePrivateKey(b)
		if err != nil {
			return nil, "", err
		}
		return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " xray-one", nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "xray-one")
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, "", err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", err
	}
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) + " xray-one", nil
}

func sshDeploy(dir string, s TunnelServer, password, cmd string) (out, hostKey string, keyOK bool, err error) {
	signer, pub, err := panelSigner(dir)
	if err != nil {
		return "", "", false, err
	}
	var auth []ssh.AuthMethod
	auth = append(auth, ssh.PublicKeys(signer))
	if password != "" {
		auth = append(auth, ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				ans := make([]string, len(qs))
				for i := range qs {
					ans[i] = password
				}
				return ans, nil
			}))
	}
	cfg := &ssh.ClientConfig{
		User: s.SSHUser, Auth: auth, Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			got := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
			if s.HostKey != "" && s.HostKey != got {
				return errors.New("the server's SSH host key changed since last time; if you reinstalled it, delete and re-add the tunnel server")
			}
			hostKey = got
			return nil
		},
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.SSHPort))
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		if password == "" && !s.KeyOK {
			return "", hostKey, false, errors.New("SSH login failed: enter the server's password")
		}
		return "", hostKey, false, fmt.Errorf("SSH login failed: %v", err)
	}
	defer c.Close()
	runCmd := func(line string, timeout time.Duration) (string, error) {
		ss, err := c.NewSession()
		if err != nil {
			return "", err
		}
		defer ss.Close()
		var buf bytes.Buffer
		ss.Stdout, ss.Stderr = &buf, &buf
		done := make(chan error, 1)
		go func() { done <- ss.Run(line) }()
		select {
		case err := <-done:
			return buf.String(), err
		case <-time.After(timeout):
			_ = ss.Signal(ssh.SIGKILL)
			return buf.String(), errors.New("timed out")
		}
	}
	// install the panel key so the password is not needed again
	q := shellQuote(pub)
	if _, err := runCmd("umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qxF "+q+" ~/.ssh/authorized_keys || echo "+q+" >> ~/.ssh/authorized_keys)", 20*time.Second); err == nil {
		keyOK = true
	}
	line := "bash -c " + shellQuote(cmd)
	if s.SSHUser != "root" {
		line = "sudo -n bash -c " + shellQuote(cmd)
	}
	out, err = runCmd(line, 5*time.Minute)
	if err != nil {
		if strings.Contains(out, "sudo:") {
			return out, hostKey, keyOK, errors.New("the user needs passwordless sudo, or use root")
		}
		return out, hostKey, keyOK, fmt.Errorf("deploy failed: %v", err)
	}
	return out, hostKey, keyOK, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
