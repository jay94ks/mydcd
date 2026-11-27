// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
)

// Installing over SSH (devel/design/vps-nodes.md §4) for servers created
// without a user script: the leader logs in as root with the account SSH
// key the vendor put on the server and does what the enrollment script
// would. The host key of a brand-new server cannot be known in advance, so
// the first connection trusts whatever key answers (see the design's
// remaining risks); what it could gain is a non-voter join, never a key.

const (
	vpsSSHUser    = "root"
	vpsSSHRetry   = 2 * time.Minute
	vpsSSHTimeout = 3 * time.Minute
)

// vpsShell runs one command on the server, feeding stdin.
type vpsShell interface {
	Run(ctx context.Context, command string, stdin io.Reader) ([]byte, error)
	Close() error
}

type sshShell struct{ c *ssh.Client }

// dialVPSShell connects as root. With pinned set (the host key this leader
// saw on its first contact) any other host key is refused; otherwise the
// key that answers is trusted and returned for later connections.
func dialVPSShell(ctx context.Context, address string, key ed25519.PrivateKey, pinned []byte) (vpsShell, []byte, error) {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, nil, err
	}
	var seen []byte
	config := &ssh.ClientConfig{User: vpsSSHUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, Timeout: 20 * time.Second,
		HostKeyCallback: vpsHostKeyCheck(pinned, &seen)}
	d := net.Dialer{Timeout: 20 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return sshShell{ssh.NewClient(c, chans, reqs)}, seen, nil
}

var errVPSHostKey = errors.New("vps: ssh host key changed since first contact")

func vpsHostKeyCheck(pinned []byte, seen *[]byte) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		raw := key.Marshal()
		if pinned != nil && !bytes.Equal(pinned, raw) {
			return errVPSHostKey
		}
		*seen = raw
		return nil
	}
}

func (s sshShell) Run(ctx context.Context, command string, stdin io.Reader) ([]byte, error) {
	session, err := s.c.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	var out bytes.Buffer
	session.Stdin, session.Stdout = stdin, &limitedBuffer{b: &out, n: 4 << 10}
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case err = <-done:
		return out.Bytes(), err
	case <-ctx.Done():
		_ = session.Close()
		return nil, ctx.Err()
	}
}

func (s sshShell) Close() error { return s.c.Close() }

type limitedBuffer struct {
	b *bytes.Buffer
	n int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// vpsSSHInstall puts the leader's sfcd on the server and returns the
// public key of the identity there (made once, read again on a retry).
func vpsSSHInstall(ctx context.Context, sh vpsShell, binary io.Reader, build control.VPSBuild) (string, error) {
	sum := hex.EncodeToString(build.SHA256[:])
	install := "set -e; umask 022; mkdir -p /usr/local/bin /etc/sfc /var/lib/sfc; cat > /usr/local/bin/sfcd.new; " +
		"echo '" + sum + "  /usr/local/bin/sfcd.new' | sha256sum -c - >/dev/null; chmod 755 /usr/local/bin/sfcd.new; mv /usr/local/bin/sfcd.new /usr/local/bin/sfcd"
	if _, err := sh.Run(ctx, install, binary); err != nil {
		return "", fmt.Errorf("install sfcd: %w", err)
	}
	out, err := sh.Run(ctx, "set -e; umask 077; if [ -d /etc/sfc/identity ]; then sfcd identity show /etc/sfc/identity; else sfcd identity create /etc/sfc/identity; fi", nil)
	if err != nil {
		return "", fmt.Errorf("identity: %w", err)
	}
	key := strings.TrimSpace(string(out))
	if k, err := identity.ParseKey(key); err != nil || hex.EncodeToString(k[:]) != key {
		return "", fmt.Errorf("identity: unexpected output")
	}
	return key, nil
}

// vpsNodeYAML is the node.yaml of a VPS server: inbound only, listening on
// its public endpoint. The enrollment script in docs/reference/vps-enroll.md
// writes the same file.
func vpsNodeYAML(name, endpoint string) string {
	return "version: 1\nnode:\n  id: " + name + "\n  state_dir: /var/lib/sfc\n  identity_dir: /etc/sfc/identity\n  listen: \"" + endpoint + "\"\n  inbound_only: true\n"
}

const vpsServiceUnit = `[Unit]
Description=Seafield Cluster node daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sfcd --config /etc/sfc/node.yaml run
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

// vpsSSHJoin writes the invitation and node.yaml, joins and starts sfcd.
func vpsSSHJoin(ctx context.Context, sh vpsShell, server control.VPSServer, inv *membership.Invitation) error {
	raw, err := inv.Encode()
	if err != nil {
		return err
	}
	source, err := identity.ParseKey(inv.Source.Key)
	if err != nil {
		return err
	}
	for path, body := range map[string]string{"/etc/sfc/invitation.json": string(raw), "/etc/sfc/node.yaml": vpsNodeYAML(server.Name, inv.Target.Endpoint), "/etc/systemd/system/sfcd.service": vpsServiceUnit} {
		if _, err := sh.Run(ctx, "set -e; umask 022; cat > "+path, strings.NewReader(body)); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	join := "set -e; sfcd --config /etc/sfc/node.yaml join --cluster " + hex.EncodeToString(inv.Cluster[:]) + " --source-public-key " + hex.EncodeToString(source[:]) +
		" --invitation /etc/sfc/invitation.json --timeout 2m; systemctl daemon-reload; systemctl enable --now sfcd"
	if _, err := sh.Run(ctx, join, nil); err != nil {
		return fmt.Errorf("join: %w", err)
	}
	return nil
}

// vpsSSHPending reports SSH work the leader still owes a server.
func vpsSSHPending(server control.VPSServer, entry membership.Entry, entered bool) bool {
	if server.Phase != control.VPSInstalling || server.Script != "" {
		return false
	}
	return !entered || server.Invitation != nil && entry.Phase == membership.Invited
}

func openOwnBinary() (*os.File, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

// vpsSSHStep does the next SSH step for server: install and enroll, or,
// once the invitation is signed, join and start.
func (r *Runtime) vpsSSHStep(ctx context.Context, v cluster.View, catalog control.VPSCatalog, server control.VPSServer, entered bool, hostKeys map[string][]byte) error {
	account, ok := catalog.Account(server.Account)
	if !ok || server.Build == nil {
		return fmt.Errorf("no account or build")
	}
	cred, err := r.vpsCredential(account)
	if err != nil {
		return fmt.Errorf("open account key")
	}
	key, ok := cred.SSHSigner()
	if !ok {
		return fmt.Errorf("account has no ssh key")
	}
	ctx, cancel := context.WithTimeout(ctx, vpsSSHTimeout)
	defer cancel()
	// Pinned by name and address: a new instance at another address starts over.
	pin := server.Name + "/" + server.PublicIP
	sh, seen, err := dialVPSShell(ctx, net.JoinHostPort(server.PublicIP, "22"), key, hostKeys[pin])
	if err != nil {
		return err
	}
	defer sh.Close()
	hostKeys[pin] = seen
	if entered {
		return vpsSSHJoin(ctx, sh, server, server.Invitation)
	}
	own, err := selfBuild()
	if err != nil || own != *server.Build {
		return fmt.Errorf("this leader does not run the recorded build")
	}
	f, err := openOwnBinary()
	if err != nil {
		return err
	}
	defer f.Close()
	public, err := vpsSSHInstall(ctx, sh, f, *server.Build)
	if err != nil {
		return err
	}
	members, err := r.memberPolicy().Members(v.State)
	if err != nil {
		return err
	}
	// The leader itself reached the key over SSH at the server's address.
	return r.memberReport(ctx, v, control.MemberReport{Action: "vps-enroll", Node: server.Name, Expected: members.Revision, Source: server.PublicIP,
		Peer: config.Peer{ID: server.Name, Key: public, Endpoint: server.Endpoint()}})
}
