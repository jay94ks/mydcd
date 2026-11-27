// SPDX-License-Identifier: Apache-2.0

package nodeshell

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

// This selector reuses the OS root's namespaces, PID1, read-only system binds,
// real sshd and host baseline/rollback. Explicit prebuilt binaries are bound
// read-only before chroot; no Docker, downloads, host accounts or fake Ready.
// Its extra owned state is one managed Raft node, Unix socket, three CLI homes
// and original user journals under /tmp/runtime. Daemon/CLI children are Waited
// before PID1 returns; interrupted PID1 uses the existing namespace rollback.
// This is a single installed node and tests Unix entry plus real TLS entry,
// not cross-node relay or an arbitrary detached shell-descendant guarantee.
func TestRQ14NodeShellManagedRuntimeOwnedRootFS(t *testing.T) {
	if os.Getenv("SFC_NODE_SHELL_NATIVE_CHILD") == "1" && os.Getenv("SFC_NODE_SHELL_RUNTIME_CHILD") != "1" {
		t.Fatal("runtime child selector missing")
	}
	if os.Getenv("SFC_NODE_SHELL_NATIVE_CHILD") != "1" && os.Getenv("SFC_TEST_NODE_SHELL_RUNTIME") != "1" {
		t.Skip("set SFC_TEST_NODE_SHELL_RUNTIME=1 and explicit prebuilt daemon/CLI paths")
	}
	nodeShellOwnedRootFS(t, true)
}

func nodeShellRuntimeInputs(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for env, name := range map[string]string{"SFC_TEST_NODE_SHELL_DAEMON": "sfcd", "SFC_TEST_NODE_SHELL_CLI": "sfc"} {
		path := os.Getenv(env)
		info, err := os.Lstat(path)
		if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			t.Fatal("explicit regular executable prerequisite", env, err)
		}
		out[name] = path
	}
	return out
}
func nodeShellRuntimeBindInputs(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, "opt/sfc")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, source := range nodeShellRuntimeInputs(t) {
		target := filepath.Join(dir, name)
		if err := os.WriteFile(target, nil, 0700); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
			t.Fatal("owned executable bind", name, err)
		}
		if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			t.Fatal("read-only executable bind", name, err)
		}
	}
}

const nodeShellRuntimeWalletPassword = "private-fixture-wallet-passphrase\n"

func nodeShellRuntimePassword(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(w, nodeShellRuntimeWalletPassword); err != nil {
		r.Close()
		w.Close()
		t.Fatal(err)
	}
	_ = w.Close()
	return r
}
func nodeShellRuntimeCLI(t *testing.T, ctx context.Context, home, profile string, args ...string) ([]byte, int) {
	t.Helper()
	password := nodeShellRuntimePassword(t)
	defer password.Close()
	flags := []string{"--config", profile}
	extras := []*os.File{password}
	if len(args) > 0 && args[0] == "wallet" {
		confirm := nodeShellRuntimePassword(t)
		defer confirm.Close()
		extras = append(extras, confirm)
		args = append(append([]string(nil), args...), "--wallet-password-fd", "3", "--wallet-confirm-fd", "4", "--no-input")
	} else {
		flags = append(flags, "--wallet-password-fd", "3", "--no-input")
	}
	command := exec.CommandContext(ctx, "/opt/sfc/sfcli", append(flags, args...)...)
	command.Env = append(os.Environ(), "HOME="+home)
	command.ExtraFiles = extras
	var out, diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &out, &diagnostic
	err := command.Run()
	if err == nil {
		return out.Bytes(), 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatal("CLI failed before an exit result", args, err)
	}
	// No terminal transcript, credential, wallet material or private key is
	// printed on failure. Public operation/state checks below identify the edge.
	return out.Bytes(), exit.ExitCode()
}

func nodeShellRuntimeNativeAssertions(t *testing.T, ctx context.Context) {
	t.Helper()
	root := "/tmp/runtime"
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	keys := map[string]*identity.Identity{}
	for _, name := range []string{"admin", "alice", "bob"} {
		key, err := identity.Create(filepath.Join(root, name+"-key"))
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key
		defer clear(key.Private)
	}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := packet.LocalAddr().String()
	_ = packet.Close()
	nodeConfig := filepath.Join(root, "node.yaml")
	configText := fmt.Sprintf("version: 1\nnode:\n id: node-a\n listen: '%s'\n state_dir: %s/state\n identity_dir: %s/node-key\n management_socket: %s/sfcdp.sock\nmodules:\n network: {enabled: false}\n workload: {enabled: false}\n ingress: {enabled: false}\n", endpoint, root, root, root)
	if err = os.WriteFile(nodeConfig, []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}
	tlsProfile := filepath.Join(root, "tls.yaml")
	init := exec.CommandContext(ctx, "/opt/sfc/sfcd", "--config", nodeConfig, "init", "--admin-public-key", keys["admin"].Actor(), "--request-id", "shell-original-init", "--client-config-out", tlsProfile)
	init.Stdout, init.Stderr = io.Discard, io.Discard
	if err = init.Run(); err != nil {
		t.Fatal("actual managed CLI init", err)
	}
	raw, err := os.ReadFile(tlsProfile)
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Version int           `yaml:"version"`
		Auth    string        `yaml:"auth"`
		Cluster string        `yaml:"cluster"`
		Peers   []config.Peer `yaml:"peers"`
	}
	if err = yaml.Unmarshal(raw, &profile); err != nil || profile.Auth != "user" || len(profile.Peers) != 1 {
		t.Fatal("user init profile", err)
	}
	clusterID, err := identity.ParseKey(profile.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := identity.ParseKey(profile.Peers[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	profile.Peers[0].Endpoint = "unix://" + filepath.Join(root, "sfcdp.sock")
	raw, err = yaml.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	unixProfile := filepath.Join(root, "unix.yaml")
	if err = os.WriteFile(unixProfile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var daemon *exec.Cmd
	var daemonDone chan error
	stopDaemon := func() {
		if daemon == nil {
			return
		}
		_ = daemon.Process.Signal(syscall.SIGTERM)
		select {
		case err := <-daemonDone:
			if err != nil {
				t.Error("managed daemon normal Close/Wait", err)
			}
		case <-ctx.Done():
			_ = daemon.Process.Kill()
			<-daemonDone
			t.Error("managed daemon shutdown did not Wait before fixture deadline")
		}
		daemon = nil
	}
	defer stopDaemon()
	startDaemon := func() {
		daemon = exec.CommandContext(ctx, "/opt/sfc/sfcd", "--config", nodeConfig, "run")
		daemon.Stdout, daemon.Stderr = io.Discard, io.Discard
		if err := daemon.Start(); err != nil {
			t.Fatal(err)
		}
		daemonDone = make(chan error, 1)
		go func(cmd *exec.Cmd, ch chan error) { ch <- cmd.Wait() }(daemon, daemonDone)
	}
	wait := func(label string, ready func() bool) {
		t.Helper()
		for !ready() {
			select {
			case err := <-daemonDone:
				daemonDone <- err
				t.Fatal("daemon ended before", label, err)
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	startDaemon()
	wait("managed Unix listener", func() bool {
		info, err := os.Lstat(filepath.Join(root, "sfcdp.sock"))
		return err == nil && info.Mode()&os.ModeSocket != 0
	})
	home := func(name string) string {
		path := filepath.Join(root, name+"-home")
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	adminHome, bobHome, aliceHome, aliceTLSHome := home("admin"), home("bob"), home("alice"), home("alice-tls")
	ok := func(h, p string, args ...string) []byte {
		t.Helper()
		out, code := nodeShellRuntimeCLI(t, ctx, h, p, args...)
		if code != 0 {
			t.Fatal("actual user CLI rejected", args, code)
		}
		return out
	}
	ok(adminHome, unixProfile, "wallet", "init")
	ok(adminHome, unixProfile, "enroll-admin", "--user-id", "admin", "--username", "admin", "--key-file", filepath.Join(root, "admin-key/key.pem"), "--request-id", "shell-enroll-admin")
	ok(adminHome, unixProfile, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin-key/key.pem"))
	for _, name := range []string{"alice", "bob"} {
		user := access.User{ID: name, Username: name, Enabled: true, SystemAdmin: name == "bob", Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: keys[name].Public, Enabled: true}}}
		payload, err := json.Marshal(user)
		if err != nil {
			t.Fatal(err)
		}
		// The CLI accepts a public change document; its authenticated user
		// supplies Principal rather than taking it from an internal Change.
		change, err := json.Marshal(control.ChangeDocument{Schema: 1, Action: "put-user", Expected: 0, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "put-"+name+".json")
		if err = os.WriteFile(path, change, 0600); err != nil {
			t.Fatal(err)
		}
		ok(adminHome, unixProfile, "manage", "apply", "--request-id", "put-"+name, "--change", path)
	}
	for _, login := range []struct{ name, home, profile string }{{"bob", bobHome, unixProfile}, {"alice", aliceHome, unixProfile}, {"alice", aliceTLSHome, tlsProfile}} {
		ok(login.home, login.profile, "wallet", "init")
		ok(login.home, login.profile, "login", "--username", login.name, "--method", "private-key", "--key-file", filepath.Join(root, login.name+"-key/key.pem"))
	}
	// This SDK client authenticates independently over real SFCP/TLS. It
	// reads the same committed policy/owner reports produced by CLI operations.
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	peer := sfcp.Peer{ID: "node-a", Endpoint: endpoint, Policy: sfcp.Policy{Key: sfcp.Identity(nodeKey), Respond: true}}
	mesh, err := sfcp.NewTransport(self, clusterID, func(key sfcp.Identity) (sfcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	client := userauth.Client{Self: self, Mesh: mesh, Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	adminSession, err := client.Login(ctx, peer, "admin", keys["admin"].Private)
	if err != nil {
		t.Fatal("actual current admin TLS login", err)
	}
	policy := func() control.NodeShellPolicyView {
		t.Helper()
		reply, err := client.NodeShellPolicy(ctx, peer, adminSession)
		if err != nil || reply.NodeShellPolicy == nil {
			t.Fatal("actual policy/readiness read", err)
		}
		return *reply.NodeShellPolicy
	}
	sessions := func() []control.NodeShellSession {
		t.Helper()
		reply, err := client.NodeShellSessions(ctx, peer, adminSession, "")
		if err != nil || reply.NodeShellSessions == nil {
			t.Fatal("actual session read", err)
		}
		return reply.NodeShellSessions.Sessions
	}
	row := func(id string) (control.NodeShellSession, bool) {
		for _, r := range sessions() {
			if r.SessionID == id {
				return r, true
			}
		}
		return control.NodeShellSession{}, false
	}
	closed := func(id, reason, actor string) {
		t.Helper()
		wait("original terminal owner report "+id, func() bool {
			r, found := row(id)
			if !found || r.State != "closed" || r.End == nil {
				return false
			}
			if r.End.Reason != reason || actor == "" && r.End.ClosedBy != nil || actor != "" && (r.End.ClosedBy == nil || r.End.ClosedBy.User != actor || r.End.ClosedBy.Username != actor) {
				t.Fatal("original terminal reason/signed actor mismatch", id)
			}
			return true
		})
	}
	current := policy()
	if current.Enabled || current.Account != Account || current.MaxSessions != 4 || current.IdleSeconds != 1800 {
		t.Fatal("cluster shell default-off contract")
	}
	// Unlisted node and default-off attempts cannot manufacture a session or
	// an SSH readiness fact. The installed node is still the only member.
	if _, code := nodeShellRuntimeCLI(t, ctx, aliceHome, unixProfile, "node", "shell", "node-a", "--operation", "deny-no-grant"); code == 0 {
		t.Fatal("ungranted shell accepted")
	}
	if len(sessions()) != 0 {
		t.Fatal("denial created original session")
	}
	ok(adminHome, unixProfile, "node", "shell-grant", "alice", "--nodes", "node-a", "--expected-revision", fmt.Sprint(policy().Revision), "--operation", "grant-alice")
	disabledOutput, disabledCode := nodeShellRuntimeCLI(t, ctx, aliceHome, unixProfile, "node", "shell", "node-a", "--operation", "deny-disabled")
	var disabledResult struct{ Result state.Result }
	if disabledCode != 3 || json.Unmarshal(disabledOutput, &disabledResult) != nil || disabledResult.Result.Code != state.NodeShellDisabled || disabledResult.Result.Reason != "node-shell-disabled" {
		t.Fatal("default-off CLI did not retain explicit disabled reason", disabledCode)
	}
	if _, code := nodeShellRuntimeCLI(t, ctx, aliceHome, unixProfile, "node", "shell", "node-c", "--operation", "deny-other-node"); code == 0 {
		t.Fatal("node-scoped grant opened another node")
	}
	if len(sessions()) != 0 {
		t.Fatal("disabled/foreign node denial created session")
	}
	ok(adminHome, unixProfile, "node", "shell-node", "node-a", "--shell", "on", "--sudo", "false", "--expected-revision", fmt.Sprint(policy().Revision), "--operation", "enable-node-a")
	wait("real adapter account/key/SSH preparation reported through Raft", func() bool {
		p := policy()
		if p.Enabled {
			t.Fatal("node override changed default")
		}
		for _, n := range p.Nodes {
			if n.Node == "node-a" {
				return n.Enabled && n.Ready && !n.Sudo
			}
		}
		return false
	})
	first := startNodeShellRuntimePTY(t, ctx, aliceHome, unixProfile, "shell-bob-close")
	first.send(t, "printf 'RQ14-IDENTITY='; whoami; printf 'RQ14-ACTOR=%s\\n' \"$SFC_USER\"\n")
	wait("actual nonroot dedicated SSH attribution", func() bool { return first.contains("RQ14-IDENTITY=sfc-shell") && first.contains("RQ14-ACTOR=alice") })
	if err := unix.IoctlSetWinsize(int(first.slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 40, Col: 120}); err != nil {
		t.Fatal("owned CLI PTY resize", err)
	}
	if err := first.command.Process.Signal(syscall.SIGWINCH); err != nil {
		t.Fatal("CLI resize notification", err)
	}
	// Input and window notifications have independent CLI goroutines. Query
	// the actual PTY with a finite read-only shell wait instead of assuming
	// their scheduling order or treating a sent resize as an acknowledgement.
	first.send(t, "i=0; while [ \"$(stty size)\" != '40 120' ] && [ \"$i\" -lt 40 ]; do i=$((i+1)); sleep .05; done; printf 'RQ14-SIZE='; stty size\n")
	wait("real CLI resize reaches original SSH PTY", func() bool { return first.contains("RQ14-SIZE=40 120") })
	original := nodeShellRuntimeJournal(t, aliceHome, "shell-bob-close")
	ok(bobHome, unixProfile, "node", "shell-close", "shell-bob-close", "--operation", "bob-close-original")
	first.wait(t)
	closed("shell-bob-close", "closed", "bob")
	wait("real CLI ClosedBy bob end frame", func() bool { return first.contains("node shell closed by bob (bob)") })
	first.assertRestored(t)
	before := len(sessions())
	ok(aliceHome, unixProfile, "node", "shell", "node-a", "--operation", "shell-bob-close")
	ok(aliceHome, unixProfile, "manage", "result", "--request-id", "shell-bob-close")
	resume := startNodeShellRuntimePTY(t, ctx, aliceHome, unixProfile, "shell-bob-close", true)
	if code := resume.wait(t); code == 0 {
		t.Fatal("explicit original resume reopened closed SSH")
	}
	resume.assertRestored(t)
	if after := nodeShellRuntimeJournal(t, aliceHome, "shell-bob-close"); !bytes.Equal(original, after) || len(sessions()) != before {
		t.Fatal("original receipt replay changed signed operation or opened another SSH")
	}
	second := startNodeShellRuntimePTY(t, ctx, aliceTLSHome, tlsProfile, "shell-own-exit")
	second.send(t, "exit 7\n")
	if code := second.wait(t); code != 7 {
		t.Fatal("real SSH exit status lost", code)
	}
	closed("shell-own-exit", "exit", "")
	second.assertRestored(t)
	third := startNodeShellRuntimePTY(t, ctx, aliceHome, unixProfile, "shell-policy-close")
	wait("policy target actually opened", func() bool { r, ok := row("shell-policy-close"); return ok && r.State == "opened" })
	ok(bobHome, unixProfile, "node", "shell-node", "node-a", "--shell", "off", "--sudo", "false", "--expected-revision", fmt.Sprint(policy().Revision), "--operation", "bob-policy-off")
	third.wait(t)
	closed("shell-policy-close", "policy", "bob")
	third.assertRestored(t)
	wait("real CLI policy ClosedBy bob end frame", func() bool { return third.contains("node shell policy by bob (bob)") })
	ok(adminHome, unixProfile, "node", "shell-node", "node-a", "--shell", "on", "--sudo", "false", "--expected-revision", fmt.Sprint(policy().Revision), "--operation", "reenable-node-a")
	wait("real SSH readiness after policy restoration", func() bool {
		for _, n := range policy().Nodes {
			if n.Node == "node-a" {
				return n.Enabled && n.Ready
			}
		}
		return false
	})
	fourth := startNodeShellRuntimePTY(t, ctx, aliceTLSHome, tlsProfile, "shell-shutdown-original")
	wait("original live SSH before daemon close", func() bool { r, ok := row("shell-shutdown-original"); return ok && r.State == "opened" })
	stopDaemon()
	fourth.wait(t)
	fourth.assertRestored(t)
	// Same installation, Raft DB, account and session store; no init/reset and
	// no new shell operation. The old native transport is gone before DB reopen.
	startDaemon()
	wait("same DB daemon resumed", func() bool { _, err := client.NodeShellPolicy(ctx, peer, adminSession); return err == nil })
	closed("shell-shutdown-original", "exit", "")
	if len(sessions()) != 4 {
		t.Fatal("restart created another SSH session")
	}
	stopDaemon()
	t.Log("actual managed CLI/User/Raft readiness, Unix and TLS PTY SSH, exact grant/default-off denial, bob close/policy ClosedBy, normal exit, immutable original result, daemon Close/Wait and same-DB terminal recovery; no Docker or cross-node relay claim")
}

// Only compare private journal bytes in memory. Never print signed payloads or
// terminal content; the original generic operation result remains authoritative.
func nodeShellRuntimeJournal(t *testing.T, home, id string) []byte {
	t.Helper()
	var found []byte
	err := filepath.WalkDir(home, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 256<<10 {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var record struct {
			Operation control.UserOperation
			Result    *state.Result
		}
		if json.Unmarshal(raw, &record) == nil && record.Operation.RequestID == id {
			if record.Result == nil || record.Result.Code != state.Applied || len(found) != 0 {
				return errors.New("missing/duplicate original applied journal")
			}
			// Confirmed result lookup may add local result metadata; compare the exact
			// signed original operation rather than that local bookkeeping wrapper.
			found, err = json.Marshal(record.Operation)
			return err
		}
		return nil
	})
	if err != nil || len(found) == 0 {
		t.Fatal("original signed shell journal", err)
	}
	return found
}

type nodeShellRuntimePTY struct {
	command       *exec.Cmd
	master, slave *os.File
	original      *unix.Termios
	done          chan error
	reader        chan struct{}
	mu            sync.Mutex
	output        bytes.Buffer
	waited        bool
}

func (p *nodeShellRuntimePTY) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.output.Len()+len(data) > 64<<10 {
		return 0, errors.New("bounded fixture PTY output exceeded")
	}
	return p.output.Write(data)
}
func (p *nodeShellRuntimePTY) contains(text string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Contains(p.output.String(), text)
}
func startNodeShellRuntimePTY(t *testing.T, ctx context.Context, home, profile, id string, resume ...bool) *nodeShellRuntimePTY {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "owned-node-shell-pty")
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		t.Fatal(err)
	}
	p := &nodeShellRuntimePTY{master: master, slave: slave, done: make(chan error, 1), reader: make(chan struct{})}
	p.original, err = unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		master.Close()
		slave.Close()
		t.Fatal(err)
	}
	if err = unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
		master.Close()
		slave.Close()
		t.Fatal(err)
	}
	password := nodeShellRuntimePassword(t)
	args := []string{"--config", profile, "--wallet-password-fd", "3", "--no-input", "node", "shell", "node-a", "--operation", id}
	if len(resume) != 0 && resume[0] {
		args = append(args, "--resume-original")
	}
	p.command = exec.CommandContext(ctx, "/opt/sfc/sfcli", args...)
	p.command.Env = append(os.Environ(), "HOME="+home)
	p.command.ExtraFiles = []*os.File{password}
	p.command.Stdin, p.command.Stdout, p.command.Stderr = slave, slave, slave
	p.command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	t.Cleanup(func() {
		if p.command.Process != nil && !p.waited {
			_ = p.command.Process.Kill()
			<-p.done
			p.waited = true
		}
		_ = master.Close()
		_ = slave.Close()
		if p.command.Process != nil {
			<-p.reader
		}
	})
	if err = p.command.Start(); err != nil {
		password.Close()
		t.Fatal("actual CLI PTY start", err)
	}
	_ = password.Close()
	go func() { _, _ = io.Copy(p, master); close(p.reader) }()
	go func() { p.done <- p.command.Wait() }()
	return p
}
func (p *nodeShellRuntimePTY) send(t *testing.T, text string) {
	t.Helper()
	if _, err := io.WriteString(p.master, text); err != nil {
		t.Fatal("owned PTY input", err)
	}
}
func (p *nodeShellRuntimePTY) wait(t *testing.T) int {
	t.Helper()
	if p.waited {
		t.Fatal("CLI Wait repeated")
	}
	err := <-p.done
	p.waited = true
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatal("CLI had no process exit", err)
	}
	return exit.ExitCode()
}
func (p *nodeShellRuntimePTY) assertRestored(t *testing.T) {
	t.Helper()
	after, err := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
	if err != nil || *after != *p.original {
		t.Fatal("actual CLI terminal was not restored", err)
	}
}
