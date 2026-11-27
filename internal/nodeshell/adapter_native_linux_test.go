// SPDX-License-Identifier: Apache-2.0

package nodeshell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// RQ14 OS adapter boundary, opt-in SFC_TEST_NODE_SHELL_NATIVE=1.
//
// Preconditions: root with NEWNS/NEWNET/NEWPID/mount/chroot capability; installed
// root-owned sshd/useradd/visudo/sudo and ordinary POSIX/coreutils binaries,
// plus recursive read-only mount_setattr support. No
// package installation, downloaded image or host account preparation is used.
// A selected run fails if isolation/prerequisites are unavailable; an unselected
// root is an explicit skip, rather than a claim that native assertions ran.
//
// First changes: an owned 0700 temporary directory, then a child created in new
// mount/network/PID/UTS/IPC namespaces. The child verifies those identities and
// PID1 before any mount or account command. All propagation is made private;
// installed /usr and library paths are read-only binds. Chroot /etc,/var,/run,
// /tmp,/dev and proc/devpts are new owned state. useradd/visudo/sshd/sudo execute
// ONLY after chroot+chdir, with files-only NSS and a private loopback listener.
// Host accounts, sudoers, sshd configuration, routes and listeners are untouched.
//
// Owned resources/rollback: one temporary rootfs, one private namespace child,
// sshd and its SSH channels/PTYs. Cleanup is registered before the child starts.
// Each Session is Closed and Waited; sshd is killed and Waited. Parent death
// kills PID1 (Pdeathsig); Linux then kills all tasks in that PID namespace and
// releases its private mounts/network. Normal cleanup Waits for PID1 before
// removing the rootfs and re-hashes protected host files. On interruption the
// only persistent recovery resource is the logged owned temporary directory;
// no host account deletion or sudoers/sshd restoration command is appropriate.
//
// Scope: actual adapter Prepare/Open, dedicated nonroot whoami, literal Seafield Cluster
// attribution, sudo -i off/on/revoked, host pin, PTY size/resize, half-close,
// output EOF/exit Wait and Close. PTY half-close is SSH input EOF; this test does
// not assert that every shell command interprets it as a POSIX terminal EOF or
// that closing SSH proves arbitrary detached descendants exited. Cluster user
// authorization, original operation receipts and ClosedBy remain core/Runtime
// tests, not invented by this OS fixture.
func TestRQ14NodeShellOwnedRootFS(t *testing.T) {
	nodeShellOwnedRootFS(t, false)
}

func nodeShellOwnedRootFS(t *testing.T, runtimeTest bool) {
	if os.Getenv("SFC_NODE_SHELL_NATIVE_CHILD") == "1" {
		nodeShellNativeChild(t)
		return
	}
	if !runtimeTest && os.Getenv("SFC_TEST_NODE_SHELL_NATIVE") != "1" {
		t.Skip("set SFC_TEST_NODE_SHELL_NATIVE=1 for isolated installed SSH/account adapter")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated native adapter requires root and namespace/mount capabilities")
	}
	for _, name := range []string{"sshd", "useradd", "visudo", "sudo", "whoami", "id", "stty", "true"} {
		_ = nodeShellNativeBinary(t, name)
	}
	if runtimeTest {
		nodeShellRuntimeInputs(t)
	}
	baseline := nodeShellHostDigest(t)
	parentNet, parentMount := nodeShellNativeNS(t, "net"), nodeShellNativeNS(t, "mnt")
	root, err := os.MkdirTemp("", "sfc-node-shell-rootfs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("owned isolated node-shell rootfs", root)
	t.Cleanup(func() {
		if runtimeTest && t.Failed() {
			// PID1/daemon/sshd Wait and namespace/mount rollback run first
			// in the later-registered cleanup. Retain original accepted or
			// unknown operations, DBs and receipts for explicit diagnosis.
			if err := os.Chmod(root, 0700); err != nil {
				t.Error("restore preserved root privacy after child Wait", err)
			}
			t.Log("preserved failed runtime original state", root)
			return
		}
		if err := os.RemoveAll(root); err != nil {
			t.Error("owned rootfs cleanup", err)
		}
	})
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	budget, selector, timeout := 90*time.Second, "^TestRQ14NodeShellOwnedRootFS$", "80s"
	if runtimeTest {
		budget, selector, timeout = 240*time.Second, "^TestRQ14NodeShellManagedRuntimeOwnedRootFS$", "230s"
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	command := exec.CommandContext(ctx, self, "-test.run="+selector, "-test.v", "-test.timeout="+timeout)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "GOMAXPROCS=4", "SFC_NODE_SHELL_NATIVE_CHILD=1", "SFC_NODE_SHELL_ROOTFS=" + root, "SFC_NODE_SHELL_PARENT_NET=" + nodeShellNativeNS(t, "net"), "SFC_NODE_SHELL_PARENT_MNT=" + nodeShellNativeNS(t, "mnt"), "SFC_NODE_SHELL_PARENT_PID=" + nodeShellNativeNS(t, "pid")}
	if runtimeTest {
		command.Env = append(command.Env, "SFC_NODE_SHELL_RUNTIME_CHILD=1", "SFC_TEST_NODE_SHELL_DAEMON="+os.Getenv("SFC_TEST_NODE_SHELL_DAEMON"), "SFC_TEST_NODE_SHELL_CLI="+os.Getenv("SFC_TEST_NODE_SHELL_CLI"))
	}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWNET | syscall.CLONE_NEWPID | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC, Pdeathsig: syscall.SIGKILL}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	started, waited := false, false
	t.Cleanup(func() {
		cancel()
		if started && !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		if nodeShellNativeNS(t, "net") != parentNet || nodeShellNativeNS(t, "mnt") != parentMount {
			t.Error("parent namespace identity changed during rollback")
		}
		nodeShellNoHostMount(t, root)
		if after := nodeShellHostDigest(t); after != baseline {
			t.Error("protected host account/SSH/sudoers inputs changed")
		}
	})
	if err = command.Start(); err != nil {
		t.Fatal("isolation unavailable; no host fallback", err)
	}
	started = true
	err = command.Wait()
	waited = true
	if err != nil {
		t.Fatalf("isolated native adapter failed: %v\n%s", err, output.String())
	}
	t.Log(output.String())
	if nodeShellNativeNS(t, "net") != parentNet || nodeShellNativeNS(t, "mnt") != parentMount {
		t.Fatal("parent namespace identity changed")
	}
	nodeShellNoHostMount(t, root)
	if err = os.RemoveAll(root); err != nil {
		t.Fatal("owned rootfs cleanup after original PID1 Wait", err)
	}
	if _, err = os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned rootfs remains after cleanup", err)
	}
}

func nodeShellNoHostMount(t *testing.T, root string) {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && (fields[4] == root || strings.HasPrefix(fields[4], root+"/")) {
			t.Fatal("owned child mount leaked into parent namespace")
		}
	}
}
func nodeShellNativeNS(t *testing.T, name string) string {
	t.Helper()
	value, err := os.Readlink("/proc/self/ns/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func nodeShellNativeBinary(t *testing.T, name string) string {
	t.Helper()
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if ok && st.Uid == 0 && info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0 && info.Mode().Perm()&0111 != 0 {
			return path
		}
	}
	t.Fatalf("required installed root-owned binary unavailable: %s", name)
	return ""
}
func nodeShellHostDigest(t *testing.T) [32]byte {
	t.Helper()
	hash := sha256.New()
	count, total := 0, int64(0)
	roots := []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/subuid", "/etc/subgid", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/var/lib/sfc-shell/.ssh/authorized_keys"}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, e fs.DirEntry, walkErr error) error {
			if errors.Is(walkErr, os.ErrNotExist) {
				_, _ = fmt.Fprintf(hash, "absent:%s\n", path)
				return nil
			}
			if walkErr != nil {
				return walkErr
			}
			count++
			if count > 1024 {
				return errors.New("host baseline exceeds bounded file count")
			}
			info, err := e.Info()
			if err != nil {
				return err
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return errors.New("host baseline stat")
			}
			_, _ = fmt.Fprintf(hash, "%s:%v:%d:%d\n", path, info.Mode(), st.Uid, st.Gid)
			if e.Type()&os.ModeSymlink != 0 {
				link, err := os.Readlink(path)
				if err != nil {
					return err
				}
				_, _ = io.WriteString(hash, link)
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			total += info.Size()
			if total > 8<<20 {
				return errors.New("host baseline exceeds bounded byte count")
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			_, err = io.Copy(hash, io.LimitReader(f, info.Size()+1))
			closeErr := f.Close()
			if err != nil {
				return err
			}
			return closeErr
		})
		if err != nil {
			t.Fatal("protected host baseline", err)
		}
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func nodeShellNativeChild(t *testing.T) {
	// Fail closed before the first mount: the helper may not run in a host
	// process, even if someone supplies the child environment by hand.
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		t.Fatal("child must be root PID1 in its new PID namespace")
	}
	for name, env := range map[string]string{"net": "SFC_NODE_SHELL_PARENT_NET", "mnt": "SFC_NODE_SHELL_PARENT_MNT", "pid": "SFC_NODE_SHELL_PARENT_PID"} {
		parent := os.Getenv(env)
		if parent == "" || nodeShellNativeNS(t, name) == parent {
			t.Fatal("private namespace was not installed", name)
		}
	}
	root := os.Getenv("SFC_NODE_SHELL_ROOTFS")
	info, err := os.Lstat(root)
	if err != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || !strings.HasPrefix(filepath.Base(root), "sfc-node-shell-rootfs-") || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("owned rootfs identity invalid", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		t.Fatal("rootfs is not owned by fixture root")
	}
	if err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal("private mount propagation", err)
	}
	for _, dir := range []string{"etc/ssh", "etc/sudoers.d", "etc/default", "etc/pam.d", "var/lib", "var/log", "run/sshd", "tmp", "dev/pts", "proc", "root", "usr"} {
		if err = os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Chmod(filepath.Join(root, "root"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(root, "tmp"), 0777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"} {
		nodeShellNativeReadOnlyBind(t, root, source)
	}
	files := map[string]string{
		"/etc/passwd":  "root:x:0:0:root:/root:/bin/sh\nsshd:x:74:74:OpenSSH privilege separation:/run/sshd:/usr/sbin/nologin\n",
		"/etc/group":   "root:x:0:\nsshd:x:74:\n",
		"/etc/shadow":  "root:*:1:0:99999:7:::\nsshd:*:1:0:99999:7:::\n",
		"/etc/gshadow": "root:*::\nsshd:*::\n",
		"/etc/subuid":  "", "/etc/subgid": "",
		"/etc/nsswitch.conf":   "passwd: files\ngroup: files\nshadow: files\nhosts: files\n",
		"/etc/hosts":           "127.0.0.1 localhost\n::1 localhost\n",
		"/etc/login.defs":      "SYS_UID_MIN 100\nSYS_UID_MAX 999\nSYS_GID_MIN 100\nSYS_GID_MAX 999\nUSERGROUPS_ENAB yes\nCREATE_HOME no\n",
		"/etc/default/useradd": "GROUP=100\nHOME=/var/lib\nINACTIVE=-1\nEXPIRE=\nSHELL=/bin/sh\nSKEL=/etc/skel\nCREATE_MAIL_SPOOL=no\n",
		"/etc/shells":          "/bin/sh\n",
		"/etc/sudoers":         "root ALL=(ALL:ALL) ALL\n#includedir /etc/sudoers.d\n",
	}
	// sudo itself may use PAM even though sshd uses public keys/UsePAM=no.
	// Keep that native prerequisite explicit and local: permit the fixture OS
	// account/session through installed PAM modules; the real sudoers plugin
	// still decides off/on and -n never solicits a host password.
	pam := "auth required pam_permit.so\naccount required pam_permit.so\npassword required pam_deny.so\nsession required pam_permit.so\n"
	files["/etc/pam.d/sudo"], files["/etc/pam.d/sudo-i"] = pam, pam
	if cache, err := os.ReadFile("/etc/ld.so.cache"); err == nil {
		if err = os.WriteFile(filepath.Join(root, "etc/ld.so.cache"), cache, 0644); err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for path, value := range files {
		mode := os.FileMode(0644)
		if path == "/etc/shadow" || path == "/etc/gshadow" {
			mode = 0600
		}
		if path == "/etc/sudoers" {
			mode = 0440
		}
		if err = os.WriteFile(filepath.Join(root, strings.TrimPrefix(path, "/")), []byte(value), mode); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("SFC_NODE_SHELL_RUNTIME_CHILD") == "1" {
		nodeShellRuntimeBindInputs(t, root)
	}
	if err = unix.Chroot(root); err != nil {
		t.Fatal("owned chroot", err)
	}
	if err = os.Chdir("/"); err != nil {
		t.Fatal(err)
	}
	// The parent temporary root stays 0700 until all namespace checks and
	// chroot have succeeded. Inside the isolated filesystem, sshd's target
	// UID must be able to traverse / to its public authorized_keys path.
	// Private state, account directories and key-file modes remain separate.
	if err = os.Chmod("/", 0755); err != nil {
		t.Fatal("isolated root traversal for nonroot SSH account", err)
	}
	_ = os.Setenv("TMPDIR", "/tmp")
	_ = os.Setenv("HOME", "/root")
	_ = os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
	if err = unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		t.Fatal("private PID proc", err)
	}
	if err = unix.Mount("tmpfs", "/dev", "tmpfs", unix.MS_NOSUID, "mode=0755,size=1m"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir("/dev/pts", 0755); err != nil {
		t.Fatal(err)
	}
	for _, device := range []struct {
		name  string
		minor uint32
	}{{"null", 3}, {"zero", 5}, {"random", 8}, {"urandom", 9}} {
		if err = unix.Mknod("/dev/"+device.name, unix.S_IFCHR|0666, int(unix.Mkdev(1, device.minor))); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod("/dev/"+device.name, 0666); err != nil {
			t.Fatal(err)
		}
	}
	// devpts newinstance is private; tty/ptmx use this instance, never host PTYs.
	if err = unix.Mount("devpts", "/dev/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620,gid=0"); err != nil {
		t.Fatal("private devpts", err)
	}
	if err = os.Symlink("pts/ptmx", "/dev/ptmx"); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mknod("/dev/tty", unix.S_IFCHR|0666, int(unix.Mkdev(5, 0))); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod("/dev/tty", 0666); err != nil {
		t.Fatal(err)
	}
	loop, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = netlink.LinkSetUp(loop); err != nil {
		t.Fatal("private loopback", err)
	}
	nodeShellNativeAssertions(t)
}
func nodeShellNativeReadOnlyBind(t *testing.T, root, source string) {
	t.Helper()
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, strings.TrimPrefix(source, "/"))
	if info.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(source)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(link, target); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err = os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err = unix.Mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		t.Fatal("installed binary/library read-only bind", err)
	}
	if err = unix.MountSetattr(unix.AT_FDCWD, target, unix.AT_RECURSIVE, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}); err != nil {
		t.Fatal("recursive read-only binary/library protection", err)
	}
}

// Drain all diagnostic writes so a full bounded fixture buffer cannot break
// the owned sshd's stderr pipe. It is read only after the process has Waited.
type nodeShellNativeLog struct {
	buffer    bytes.Buffer
	truncated bool
}

func (w *nodeShellNativeLog) String() string { return w.buffer.String() }

func (w *nodeShellNativeLog) Write(p []byte) (int, error) {
	n := len(p)
	keep := min(n, 4096-w.buffer.Len())
	if keep < n {
		w.truncated = true
	}
	_, _ = w.buffer.Write(p[:keep])
	return n, nil
}

func nodeShellNativeAssertions(t *testing.T) {
	runtimeTest := os.Getenv("SFC_NODE_SHELL_RUNTIME_CHILD") == "1"
	budget, endpoint := 60*time.Second, "127.0.0.1:22022"
	if runtimeTest {
		budget, endpoint = 210*time.Second, "127.0.0.1:22"
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	key, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(key)
	if err = os.WriteFile("/etc/ssh/ssh_host_ed25519_key", encoded, 0600); err != nil {
		t.Fatal(err)
	}
	clear(encoded)
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	host := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if err = os.WriteFile("/etc/ssh/ssh_host_ed25519_key.pub", host, 0644); err != nil {
		t.Fatal(err)
	}
	configuration := `Port 22022
ListenAddress 127.0.0.1
HostKey /etc/ssh/ssh_host_ed25519_key
PidFile /run/sshd.pid
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers sfc-shell
AuthorizedKeysFile .ssh/authorized_keys
StrictModes yes
PermitTTY yes
PermitUserEnvironment no
UseDNS no
PrintMotd no
PrintLastLog no
LogLevel VERBOSE
`
	if runtimeTest {
		configuration = strings.Replace(configuration, "Port 22022", "Port 22", 1)
	}
	if err = os.WriteFile("/etc/ssh/sshd_config", []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	sshd := exec.CommandContext(ctx, nodeShellNativeBinary(t, "sshd"), "-D", "-e", "-f", "/etc/ssh/sshd_config")
	sshd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	var sshdErrors nodeShellNativeLog
	sshd.Stdout = io.Discard
	sshd.Stderr = &sshdErrors
	if err = sshd.Start(); err != nil {
		t.Fatal("private sshd", err)
	}
	done := make(chan error, 1)
	go func() { done <- sshd.Wait() }()
	defer func() {
		_ = sshd.Process.Kill()
		<-done
		if t.Failed() {
			// Read only after Wait joins the stderr writer. VERBOSE retains
			// public authentication metadata/fingerprints, never SSH commands,
			// terminal contents or private key material (DEBUG is not enabled).
			t.Logf("private sshd public diagnostic (4096-byte limit, truncated=%t): %q", sshdErrors.truncated, strings.TrimSpace(sshdErrors.String()))
		}
	}()
	readyDeadline := time.NewTimer(5 * time.Second)
	defer readyDeadline.Stop()
	readyTick := time.NewTicker(20 * time.Millisecond)
	defer readyTick.Stop()
	listening := false
	for !listening {
		select {
		case err := <-done:
			done <- err
			t.Fatal("private sshd exited before readiness", err)
		case <-readyDeadline.C:
			t.Fatal("private sshd listener not ready")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-readyTick.C:
			conn, err := net.DialTimeout("tcp", endpoint, 100*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				listening = true
			}
		}
	}
	if runtimeTest {
		nodeShellRuntimeNativeAssertions(t, ctx)
		return
	}
	config := Config{StateDir: "/var/lib/sfc-shell-state", Home: "/var/lib/sfc-shell", Endpoint: "127.0.0.1:22022", HostPublicKeyFile: "/etc/ssh/ssh_host_ed25519_key.pub", SudoersDir: "/etc/sudoers.d"}
	adapter, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if ready := adapter.Prepare(ctx, false); !ready.Ready || ready.Account != Account || ready.SudoAllowed {
		t.Fatal("actual account/key/SSH sudo-off preparation", ready)
	}
	firstAccount, err := os.ReadFile(config.StateDir + "/account.json")
	if err != nil {
		t.Fatal(err)
	}
	firstKey, err := os.ReadFile(config.StateDir + "/ssh-key.bin")
	if err != nil {
		t.Fatal(err)
	}
	firstDigest := sha256.Sum256(firstKey)
	clear(firstKey)
	t.Run("nonroot-attribution-pty-half-close-wait", func(t *testing.T) { nodeShellNativeCommand(t, ctx, adapter, false) })
	t.Run("exact-host-pin", func(t *testing.T) {
		_, wrong, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wrong)
		signer, err := ssh.NewSignerFromKey(wrong)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(config.HostPublicKeyFile, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0644); err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(config.HostPublicKeyFile, host, 0644)
		if session, err := adapter.Open(ctx, 80, 24, "alice"); err == nil {
			_ = session.Close()
			t.Fatal("substituted host key accepted by actual sshd client")
		}
	})
	t.Run("same-state-sudo-on", func(t *testing.T) {
		var err error
		adapter, err = New(config)
		if err != nil {
			t.Fatal(err)
		}
		if ready := adapter.Prepare(ctx, true); !ready.Ready || !ready.SudoAllowed {
			t.Fatal("sudo-on actual visudo/sshd probe", ready)
		}
		nodeShellNativeCommand(t, ctx, adapter, true)
		account, err := os.ReadFile(config.StateDir + "/account.json")
		if err != nil || !bytes.Equal(firstAccount, account) {
			t.Fatal("same-state account identity changed", err)
		}
		key, err := os.ReadFile(config.StateDir + "/ssh-key.bin")
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(key)
		clear(key)
		if digest != firstDigest {
			t.Fatal("same-state key was regenerated")
		}
	})
	t.Run("sudo-revoked", func(t *testing.T) {
		if err := adapter.RevokeSudo(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(config.SudoersDir + "/" + Account); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("managed sudo rule retained", err)
		}
		if ready := adapter.Prepare(ctx, false); !ready.Ready || ready.SudoAllowed {
			t.Fatal(ready)
		}
		nodeShellNativeCommand(t, ctx, adapter, false)
	})
	t.Run("close-waits-original-ssh", func(t *testing.T) {
		session, err := adapter.Open(ctx, 80, 24, "bob")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = session.Close(); _, _ = session.Wait() }()
		readDone := make(chan struct{})
		go func() { _, _ = io.Copy(io.Discard, session); close(readDone) }()
		if err = session.Close(); err != nil {
			t.Fatal(err)
		}
		waitDone := make(chan struct{})
		go func() { _, _ = session.Wait(); close(waitDone) }()
		for _, done := range []<-chan struct{}{readDone, waitDone} {
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("original SSH close/Wait did not terminate", ctx.Err())
			}
		}
		if _, err = session.Write([]byte("new work")); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("closed session accepted more stdin", err)
		}
	})
}
func nodeShellNativeCommand(t *testing.T, ctx context.Context, adapter *Adapter, allowSudo bool) {
	t.Helper()
	attribution := "alice'; printf __ATTR_INJECTED__; #"
	session, err := adapter.Open(ctx, 80, 24, attribution)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close(); _, _ = session.Wait() }()
	if err = session.Resize(120, 40); err != nil {
		t.Fatal("PTY resize", err)
	}
	// Actual commands report fixed markers. No caller name is interpolated into
	// a shell command: it is read back from the adapter-provided environment.
	program := "stty -echo; printf '\\n__WHO__'; whoami; printf '__UID__'; id -u; printf '__USER__%s\\n' \"$SFC_USER\"; printf '__SIZE__'; stty size; if value=$(sudo -n -i /usr/bin/id -u 2>/dev/null); then printf '__SUDO__%s\\n' \"$value\"; else printf '__SUDO__denied\\n'; fi; exit 7\n"
	if _, err = session.Write([]byte(program)); err != nil {
		t.Fatal(err)
	}
	if err = session.CloseWrite(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatal("SSH input half-close", err)
	}
	// The real output is drained before Wait; EOF alone is not exit proof.
	output, err := io.ReadAll(io.LimitReader(session, 32<<10))
	if err != nil || len(output) >= 32<<10 {
		t.Fatal("actual PTY output EOF/bound", err)
	}
	exit, waitErr := session.Wait()
	var status *ssh.ExitError
	if !errors.As(waitErr, &status) || exit.Code != 7 || exit.Signal != "" {
		t.Fatal("actual original SSH exit status", exit, waitErr)
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		for _, name := range []string{"WHO", "UID", "USER", "SIZE", "SUDO"} {
			prefix := "__" + name + "__"
			if strings.HasPrefix(line, prefix) {
				if _, exists := values[name]; exists {
					t.Fatal("duplicate native marker", name)
				}
				values[name] = strings.TrimPrefix(line, prefix)
			}
		}
	}
	uid, err := strconv.ParseUint(values["UID"], 10, 32)
	if err != nil || uid == 0 || values["WHO"] != Account || values["USER"] != attribution || values["SIZE"] != "40 120" {
		t.Fatal("dedicated identity/literal attribution/PTY resize mismatch", values)
	}
	want := "denied"
	if allowSudo {
		want = "0"
	}
	if values["SUDO"] != want {
		t.Fatal("actual sudo -i did not match node policy", values["SUDO"], want)
	}
}
