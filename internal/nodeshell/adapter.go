// SPDX-License-Identifier: Apache-2.0

// Package nodeshell adapts the node's installed SSH server to a dedicated
// non-root account. Cluster authorization, policy, quotas and audit attribution
// belong to the caller; preparing an account is not a shell-open permission.
package nodeshell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const Account = "sfc-shell"

var ErrNotReady = errors.New("node-shell-not-ready")
var ErrSession = errors.New("invalid node shell session")

type Config struct {
	StateDir          string
	Account           string
	Home              string
	Endpoint          string
	HostPublicKeyFile string
	SudoersDir        string
}

// PublicReady deliberately contains no key, host path, command output or SSH
// transcript. Reason is a bounded product code, not a raw provisioning error.
type PublicReady struct {
	Ready       bool
	Reason      string
	Account     string
	SudoAllowed bool
}

type Adapter struct {
	mu     sync.Mutex
	config Config
	ready  PublicReady
	lookup func(string) (*user.User, error)
	run    func(context.Context, string, ...string) error
}

func New(c Config) (*Adapter, error) {
	if c.Account == "" {
		c.Account = Account
	}
	if c.Home == "" {
		c.Home = "/var/lib/sfc-shell"
	}
	if c.Endpoint == "" {
		c.Endpoint = "127.0.0.1:22"
	}
	if c.HostPublicKeyFile == "" {
		c.HostPublicKeyFile = "/etc/ssh/ssh_host_ed25519_key.pub"
	}
	if c.SudoersDir == "" {
		c.SudoersDir = "/etc/sudoers.d"
	}
	host, port, err := net.SplitHostPort(c.Endpoint)
	address := net.ParseIP(host)
	p, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || portErr != nil || p == 0 || address == nil || !address.IsLoopback() || c.Account != Account {
		return nil, ErrNotReady
	}
	for _, path := range []string{c.StateDir, c.Home, c.HostPublicKeyFile, c.SudoersDir} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return nil, ErrNotReady
		}
	}
	if c.StateDir == c.Home || strings.HasPrefix(c.StateDir, c.Home+"/") {
		return nil, ErrNotReady
	}
	return &Adapter{config: c, ready: PublicReady{Account: Account, Reason: "account-not-prepared"}, lookup: user.Lookup, run: func(ctx context.Context, name string, args ...string) error {
		binary, err := systemCommand(name)
		if err != nil {
			return err
		}
		command := exec.CommandContext(ctx, binary, args...)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
		command.Stdout, command.Stderr = io.Discard, io.Discard
		return command.Run()
	}}, nil
}

func systemCommand(name string) (string, error) {
	if name != "useradd" && name != "visudo" {
		return "", ErrNotReady
	}
	for _, dir := range []string{"/usr/sbin", "/sbin"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if ok && st.Uid == 0 {
			return path, nil
		}
	}
	return "", ErrNotReady
}

type accountRecord struct {
	Schema  uint8
	Account string
	Home    string
	UID     string
	GID     string
}

// Prepare creates only this adapter's account/key/authorized_keys and managed
// sudoers entry. It never installs packages, starts sshd, changes its global
// configuration or adopts an arbitrary pre-existing account.
func (a *Adapter) Prepare(ctx context.Context, allowSudo bool) PublicReady {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ready = PublicReady{Account: Account, Reason: "preparation-failed"}
	fail := func(reason string) PublicReady {
		a.ready.Reason = publicReason(reason)
		return a.ready
	}
	if ctx.Err() != nil {
		return fail("cancelled")
	}
	if os.Geteuid() != 0 {
		return fail("root-required")
	}
	if _, err := a.hostKey(); err != nil {
		return fail("host-key-unavailable")
	}
	if err := ownedDirectory(a.config.StateDir, 0700); err != nil {
		return fail("private-state-unavailable")
	}
	if err := a.prepareAccount(ctx); err != nil {
		return fail("account-unavailable")
	}
	signer, err := a.signer(true)
	if err != nil {
		return fail("private-key-unavailable")
	}
	if err = ownedDirectory(filepath.Join(a.config.Home, ".ssh"), 0755); err != nil {
		return fail("authorized-key-unavailable")
	}
	authorized := append([]byte("from=\"127.0.0.1,::1\",no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-user-rc "), ssh.MarshalAuthorizedKey(signer.PublicKey())...)
	if err = createOrMatch(filepath.Join(a.config.Home, ".ssh", "authorized_keys"), authorized, 0644); err != nil {
		return fail("authorized-key-conflict")
	}
	if err = a.prepareSudo(ctx, allowSudo); err != nil {
		return fail("sudo-policy-unavailable")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client, err := a.connect(probeCtx)
	if err != nil {
		return fail("ssh-unavailable")
	}
	defer client.Close()
	stop := context.AfterFunc(probeCtx, func() { _ = client.Close() })
	defer stop()
	probe, err := client.NewSession()
	if err != nil {
		return fail("ssh-probe-failed")
	}
	defer probe.Close()
	if err := probe.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		return fail("ssh-probe-failed")
	}
	// The command is fixed; neither the Seafield Cluster username nor caller input is
	// interpolated into the readiness probe. A separate root-owned rule must
	// not silently grant sudo when the effective node policy says disabled.
	var out bytes.Buffer
	probe.Stdout, probe.Stderr = &probeOutput{buffer: &out, remaining: 1024}, io.Discard
	err = probe.Run("PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; id -u; if sudo -n -u root /usr/bin/true >/dev/null 2>&1; then printf 'sudo\\n'; else printf 'nosudo\\n'; fi")
	if err != nil {
		return fail("ssh-probe-failed")
	}
	record, err := a.account()
	want := record.UID + "\nnosudo\n"
	if allowSudo {
		want = record.UID + "\nsudo\n"
	}
	if err != nil || strings.ReplaceAll(out.String(), "\r\n", "\n") != want {
		return fail("sudo-policy-mismatch")
	}
	a.ready = PublicReady{Ready: true, Account: Account, SudoAllowed: allowSudo}
	return a.ready
}

func publicReason(reason string) string {
	switch reason {
	case "host-key-unavailable", "private-state-unavailable", "private-key-unavailable", "authorized-key-unavailable", "authorized-key-conflict":
		return "key-unavailable"
	case "sudo-policy-unavailable", "sudo-policy-mismatch":
		return "sudo-unavailable"
	case "ssh-unavailable", "ssh-probe-failed":
		return "ssh-unavailable"
	default:
		return "account-unavailable"
	}
}

func (a *Adapter) account() (accountRecord, error) {
	raw, err := readOwned(filepath.Join(a.config.StateDir, "account.json"), 0600, 2048)
	var record accountRecord
	if err != nil || json.Unmarshal(raw, &record) != nil || record.Schema != 1 || record.Account != Account || record.Home != a.config.Home {
		return record, ErrNotReady
	}
	return record, nil
}

func (a *Adapter) prepareAccount(ctx context.Context) error {
	path := filepath.Join(a.config.StateDir, "account.json")
	record, recordErr := a.account()
	u, lookupErr := a.lookup(Account)
	if recordErr != nil {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) || lookupErr == nil {
			return ErrNotReady
		}
		var missing user.UnknownUserError
		if !errors.As(lookupErr, &missing) {
			return ErrNotReady
		}
		record = accountRecord{Schema: 1, Account: Account, Home: a.config.Home}
		raw, _ := json.Marshal(record)
		if err := createOrMatch(path, raw, 0600); err != nil {
			return err
		}
	}
	if lookupErr != nil {
		var missing user.UnknownUserError
		if record.UID != "" || !errors.As(lookupErr, &missing) || ownedDirectory(a.config.Home, 0755) != nil {
			return ErrNotReady
		}
		// A non-password credential avoids OpenSSH's locked-account prefix
		// without enabling password login. Only our daemon's SSH key is used.
		if err := a.run(ctx, "useradd", "--system", "--user-group", "--no-create-home", "--home-dir", a.config.Home, "--shell", "/bin/sh", "--comment", "Seafield Cluster node shell", "--password", "*", Account); err != nil {
			return err
		}
		u, lookupErr = a.lookup(Account)
	}
	if lookupErr != nil || u == nil {
		return ErrNotReady
	}
	uid, uidErr := strconv.ParseUint(u.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(u.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 || u.Username != Account || u.HomeDir != a.config.Home || u.Name != "Seafield Cluster node shell" || record.UID != "" && (record.UID != u.Uid || record.GID != u.Gid) {
		return ErrNotReady
	}
	if err := ownedDirectory(a.config.Home, 0755); err != nil {
		return err
	}
	if record.UID == "" {
		record.UID, record.GID = u.Uid, u.Gid
		raw, _ := json.Marshal(record)
		return replaceOwned(path, raw, 0600)
	}
	return nil
}

func (a *Adapter) checkAccountIdentity() error {
	record, err := a.account()
	if err != nil || record.UID == "" || record.GID == "" {
		return ErrNotReady
	}
	u, err := a.lookup(Account)
	if err != nil || u == nil {
		return ErrNotReady
	}
	uid, uidErr := strconv.ParseUint(u.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(u.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 || u.Username != Account || u.HomeDir != a.config.Home || u.Name != "Seafield Cluster node shell" || u.Uid != record.UID || u.Gid != record.GID {
		return ErrNotReady
	}
	return nil
}

func (a *Adapter) signer(create bool) (ssh.Signer, error) {
	path := filepath.Join(a.config.StateDir, "ssh-key.bin")
	seed, err := readOwned(path, 0600, ed25519.SeedSize)
	if create && errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err = rand.Read(seed); err == nil {
			err = createOrMatch(path, seed, 0600)
		}
	}
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrNotReady
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	return ssh.NewSignerFromKey(key)
}

type probeOutput struct {
	buffer    *bytes.Buffer
	remaining int
}

func (w *probeOutput) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, ErrNotReady
	}
	w.remaining -= len(p)
	return w.buffer.Write(p)
}

const sudoRule = "# Managed by Seafield Cluster node-shell; do not edit.\nsfc-shell ALL=(root) NOPASSWD: ALL\n"

func (a *Adapter) prepareSudo(ctx context.Context, allow bool) error {
	if _, err := os.Lstat(a.config.SudoersDir); errors.Is(err, os.ErrNotExist) && !allow {
		return nil
	}
	info, err := os.Lstat(a.config.SudoersDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return ErrNotReady
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return ErrNotReady
	}
	path := filepath.Join(a.config.SudoersDir, Account)
	old, err := readOwned(path, 0440, 4096)
	if err != nil && !errors.Is(err, os.ErrNotExist) || err == nil && string(old) != sudoRule {
		return ErrNotReady
	}
	if !allow {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		return syncDirectory(a.config.SudoersDir)
	}
	check, err := os.CreateTemp(a.config.StateDir, ".sudo-check-")
	if err != nil {
		return err
	}
	name := check.Name()
	defer os.Remove(name)
	if _, err = io.WriteString(check, sudoRule); err == nil {
		err = check.Sync()
	}
	closeErr := check.Close()
	if err != nil || closeErr != nil {
		return ErrNotReady
	}
	if err = a.run(ctx, "visudo", "-c", "-f", name); err != nil {
		return err
	}
	if old != nil {
		return nil
	}
	return writeAtomic(path, []byte(sudoRule), 0440, false)
}

// RevokeSudo removes only this adapter's exact managed rule. Disabled nodes
// use this path without creating an account, key, home or SSH connection.
func (a *Adapter) RevokeSudo(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ready = PublicReady{Account: Account, Reason: "account-not-prepared"}
	if ctx.Err() != nil || os.Geteuid() != 0 {
		return ErrNotReady
	}
	return a.prepareSudo(ctx, false)
}

func ownedDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
	} else if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return checkedDirectory(path, mode)
}

func checkedDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != mode {
		return ErrNotReady
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		return ErrNotReady
	}
	return nil
}

func readOwned(path string, mode os.FileMode, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != mode || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || info.Size() > limit {
		return nil, ErrNotReady
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit+1))
}

func createOrMatch(path string, data []byte, mode os.FileMode) error {
	old, err := readOwned(path, mode, int64(len(data)))
	if err == nil {
		if string(old) != string(data) {
			return ErrNotReady
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrNotReady
	}
	return syncDirectory(filepath.Dir(path))
}

func replaceOwned(path string, data []byte, mode os.FileMode) error {
	return writeAtomic(path, data, mode, true)
}

func writeAtomic(path string, data []byte, mode os.FileMode, replace bool) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".sfc-shell-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(mode); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return ErrNotReady
	}
	if replace {
		err = os.Rename(name, path)
	} else {
		// Publication must not replace an operator file that appeared after
		// the initial conflict check and candidate syntax validation.
		err = unix.Renameat2(unix.AT_FDCWD, name, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
