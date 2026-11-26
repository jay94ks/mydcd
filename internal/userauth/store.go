// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
)

type Stored struct {
	Username string
	// TargetTenant is an invocation-only CLI constraint, never persisted or
	// signed into the original session/operation.
	TargetTenant string
	Session      access.Session
	Tenant       string
	Self         *identity.Identity
	Pending      *control.UserOperation
}

func (Stored) MarshalJSON() ([]byte, error) { return nil, ErrPrivateState }
func (Stored) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted user session]") }

type privateRecord struct {
	Schema  uint8
	Profile [32]byte
	Session access.Session
	Seed    [32]byte
	Tenant  string
	Pending *control.UserOperation `json:",omitempty"`
}

// Profile names this client's local namespace (login records, journals).
// It is the cluster alone: trusting another node or changing endpoints
// keeps the same saved logins and operations.
func (c Client) Profile() [32]byte {
	return sha256.Sum256(append([]byte("mydc-user-profile-2\x00"), c.Cluster[:]...))
}

// JournalProfile is the namespace of retained operation journals.
func (c Client) JournalProfile() [32]byte { return c.Profile() }

func safeID(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, v := range []byte(s) {
		if !(v >= 'a' && v <= 'z' || v >= '0' && v <= '9' || v == '-') {
			return false
		}
	}
	return true
}

func privateInfo(info os.FileInfo, directory bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && (directory && info.IsDir() || !directory && info.Mode().IsRegular())
}

func descend(parent *os.Root, name string, create bool) (*os.Root, error) {
	if create {
		if err := parent.Mkdir(name, 0700); err != nil && !os.IsExist(err) {
			return nil, ErrPrivateState
		}
		// The final file/leaf-directory sync cannot persist a newly created
		// ancestor's name. Sync each parent before publishing private state.
		dir, err := parent.Open(".")
		if err != nil {
			return nil, ErrPrivateState
		}
		err = dir.Sync()
		closeErr := dir.Close()
		if err != nil || closeErr != nil {
			return nil, ErrPrivateState
		}
	}
	info, err := parent.Lstat(name)
	if !create && os.IsNotExist(err) {
		// A wallet login need not have created any legacy session/journal
		// directories. Preserve absence separately from an unsafe existing path.
		return nil, fmt.Errorf("%w: %w", ErrPrivateState, os.ErrNotExist)
	}
	if err != nil || !privateInfo(info, true) {
		return nil, ErrPrivateState
	}
	r, err := parent.OpenRoot(name)
	if err != nil {
		return nil, ErrPrivateState
	}
	return r, nil
}

func clusterRoot(home string, cluster [32]byte, create bool) (*os.Root, error) {
	if cluster == ([32]byte{}) {
		return nil, ErrPrivateState
	}
	r, err := os.OpenRoot(home)
	if err != nil {
		return nil, ErrPrivateState
	}
	for _, part := range []string{".mydc", "sessions", hex.EncodeToString(cluster[:])} {
		next, err := descend(r, part, create)
		_ = r.Close()
		if err != nil {
			return nil, err
		}
		r = next
	}
	return r, nil
}

func profileRoot(home string, c Client, create bool) (*os.Root, error) {
	return profileRootID(home, c.Cluster, c.Profile(), create)
}

func profileRootID(home string, cluster, profile [32]byte, create bool) (*os.Root, error) {
	if profile == [32]byte{} {
		return nil, ErrPrivateState
	}
	r, err := clusterRoot(home, cluster, create)
	if err != nil {
		return nil, err
	}
	for _, part := range []string{"profiles", hex.EncodeToString(profile[:])} {
		next, err := descend(r, part, create)
		_ = r.Close()
		if err != nil {
			return nil, err
		}
		r = next
	}
	return r, nil
}

func readPrivate(root *os.Root, name string, out any) error {
	return readPrivateLimit(root, name, out, 65536)
}

func readPrivateLimit(root *os.Root, name string, out any, limit int) error {
	if limit < 1 || limit > 512<<10 {
		return ErrPrivateState
	}
	original, err := root.Lstat(name)
	if err != nil || !privateInfo(original, false) {
		return ErrPrivateState
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrPrivateState
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateInfo(info, false) || !os.SameFile(original, info) {
		return ErrPrivateState
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	defer clear(b)
	if err != nil || len(b) > limit || strict(b, out) != nil {
		return ErrPrivateState
	}
	return nil
}

func writePrivate(root *os.Root, name string, value any) error {
	return writePrivateLimit(root, name, value, 65536)
}

func writePrivateLimit(root *os.Root, name string, value any, limit int) error {
	if limit < 1 || limit > 512<<10 {
		return ErrPrivateState
	}
	if info, err := root.Lstat(name); err == nil {
		if !privateInfo(info, false) {
			return ErrPrivateState
		}
	} else if !os.IsNotExist(err) {
		return ErrPrivateState
	}
	b, err := json.Marshal(value)
	defer clear(b)
	if err != nil || len(b) > limit {
		return ErrPrivateState
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrPrivateState
	}
	// A unique owned temporary name cannot collide with a concurrent writer or
	// remove another writer's file after our rename has already completed.
	temp := name + ".new-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrPrivateState
	}
	defer root.Remove(temp)
	n, err := f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil || root.Rename(temp, name) != nil {
		return ErrPrivateState
	}
	dir, err := root.Open(".")
	if err != nil {
		return ErrPrivateState
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return ErrPrivateState
	}
	return nil
}

func Save(home string, c Client, session access.Session, tenant string) error {
	if c.Credentials != nil {
		return c.Credentials.saveSession(c, session, tenant)
	}
	if c.Self == nil || c.Verify(session) != nil || !safeID(session.User) || tenant != "" && !safeID(tenant) {
		return ErrPrivateState
	}
	root, err := profileRoot(home, c, true)
	if err != nil {
		return err
	}
	defer root.Close()
	unlock, err := lockProfile(root)
	if err != nil {
		return err
	}
	defer unlock()
	var pending *control.UserOperation
	if _, err := root.Lstat("session.json"); err == nil {
		var previous privateRecord
		defer clear(previous.Seed[:])
		if readPrivate(root, "session.json", &previous) != nil || previous.Schema != 1 || previous.Profile != c.Profile() {
			return ErrPrivateState
		}
		if previous.Pending != nil {
			if previous.Session.User != session.User || previous.Pending.Session.User != session.User || sameSession(previous.Session, session) || !previous.Pending.SelfLogout() || previous.Pending.VerifyOriginal(c.Cluster) != nil {
				return ErrPrivateState
			}
			pending = previous.Pending
		}
	} else if !os.IsNotExist(err) {
		return ErrPrivateState
	}
	profile := c.Profile()
	record := privateRecord{Schema: 1, Profile: profile, Session: session, Tenant: tenant, Pending: pending}
	copy(record.Seed[:], c.Self.Private.Seed())
	defer clear(record.Seed[:])
	// Active user, proof key, signed session and tenant selection have one
	// atomic commit. No pointer/file pair can publish a partially saved login.
	return writePrivate(root, "session.json", record)
}

func Load(home string, c Client) (Stored, error) {
	if c.Credentials != nil {
		return c.Credentials.Load(c, c.Username)
	}
	root, err := profileRoot(home, c, false)
	if err != nil {
		return Stored{}, err
	}
	defer root.Close()
	profile := c.Profile()
	var record privateRecord
	defer clear(record.Seed[:])
	if readPrivate(root, "session.json", &record) != nil || record.Schema != 1 || record.Profile != profile || !safeID(record.Session.User) || record.Tenant != "" && !safeID(record.Tenant) {
		return Stored{}, ErrPrivateState
	}
	self, err := identity.FromSeed(record.Seed[:])
	if err != nil {
		return Stored{}, ErrPrivateState
	}
	c.Self = self
	valid := c.Verify(record.Session) == nil
	if record.Pending != nil {
		op := *record.Pending
		if sameSession(op.Session, record.Session) {
			valid = c.verifyAt(record.Session, op.At) == nil
		}
		valid = valid && op.Session.User == record.Session.User && op.SelfLogout() && op.VerifyOriginal(c.Cluster) == nil
	}
	if !valid {
		expired := record.Pending == nil && c.expired(record.Session)
		clear(self.Private)
		if expired {
			return Stored{}, ErrSessionExpired
		}
		return Stored{}, ErrPrivateState
	}
	return Stored{Session: record.Session, Tenant: record.Tenant, Self: self, Pending: record.Pending}, nil
}

func lockProfile(root *os.Root) (func(), error) {
	// Root.OpenFile can resolve a symlink whose target is still inside Root.
	// Reject that name before opening and bind the actual descriptor to it.
	original, err := root.Lstat("session.lock")
	if err == nil && !privateInfo(original, false) || err != nil && !os.IsNotExist(err) {
		return nil, ErrPrivateState
	}
	f, err := root.OpenFile("session.lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrPrivateState
	}
	info, err := f.Stat()
	named, namedErr := root.Lstat("session.lock")
	if err != nil || !privateInfo(info, false) || namedErr != nil || !privateInfo(named, false) || !os.SameFile(named, info) || original != nil && !os.SameFile(original, info) || syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		_ = f.Close()
		return nil, ErrPrivateState
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

// StageLogout syncs the original signed intent before any possible write to
// the network. Concurrent login/tenant writes cannot erase unresolved intent.
func StageLogout(home string, c Client, op control.UserOperation) error {
	if c.Self == nil || op.Session.Key != c.Self.Public || c.Verify(op.Session) != nil || op.Change.Action != "revoke-session" || op.Change.Principal != op.Session.User || op.Change.Expected != op.Session.AccountRevision || !ed25519.Verify(ed25519.PublicKey(c.Self.Public[:]), control.OperationBytes(op), op.Signature) {
		return ErrPrivateState
	}
	var target control.SessionRevocation
	if strict(op.Change.Payload, &target) != nil || target.User != op.Session.User || target.Session != op.Session.ID {
		return ErrPrivateState
	}
	if c.Credentials != nil {
		return c.Credentials.stageLogout(c, op)
	}
	root, err := profileRoot(home, c, false)
	if err != nil {
		return err
	}
	defer root.Close()
	unlock, err := lockProfile(root)
	if err != nil {
		return err
	}
	defer unlock()
	var record privateRecord
	defer clear(record.Seed[:])
	if readPrivate(root, "session.json", &record) != nil || record.Schema != 1 || record.Profile != c.Profile() || !sameSession(record.Session, op.Session) || !bytes.Equal(record.Seed[:], c.Self.Private.Seed()) || record.Pending != nil {
		return ErrPrivateState
	}
	record.Pending = &op
	return writePrivate(root, "session.json", record)
}

// SettleLogout is called only with a definitive matching retained result. An
// absent result or transport loss never permits local intent/key deletion.
func SettleLogout(home string, c Client, op control.UserOperation, result state.Result) error {
	// Expiry describes lost retention, never the original logout's outcome.
	if result.Code == state.Expired {
		return ErrPrivateState
	}
	if c.Credentials != nil {
		return c.Credentials.settleLogout(c, op, result)
	}
	root, err := profileRoot(home, c, false)
	if err != nil {
		return err
	}
	defer root.Close()
	unlock, err := lockProfile(root)
	if err != nil {
		return err
	}
	defer unlock()
	var record privateRecord
	defer clear(record.Seed[:])
	if result.Index == 0 || readPrivate(root, "session.json", &record) != nil || record.Schema != 1 || record.Profile != c.Profile() || record.Pending == nil || record.Session.User != op.Session.User || !bytes.Equal(control.OperationBytes(*record.Pending), control.OperationBytes(op)) || !bytes.Equal(record.Pending.Signature, op.Signature) {
		return ErrPrivateState
	}
	if result.Code != state.Applied || !sameSession(record.Session, op.Session) {
		record.Pending = nil
		return writePrivate(root, "session.json", record)
	}
	if root.Remove("session.json") != nil {
		return ErrPrivateState
	}
	dir, err := root.Open(".")
	if err != nil {
		return ErrPrivateState
	}
	defer dir.Close()
	return dir.Sync()
}
