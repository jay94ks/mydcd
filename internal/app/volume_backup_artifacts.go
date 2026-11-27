// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

var errBackupArtifact = errors.New("original backup artifact unavailable or unsettled")

// The backend performs actual native work; fakes belong only in tests. This
// store owns files and uses the same A2 journal as the other native modules.
type backupArtifactBackend interface {
	Authorize(context.Context, control.VolumeBackupBinding, bool) error
	Source(context.Context, control.VolumeBackupBinding) (volumes.ColdSource, error)
	Export(context.Context, control.VolumeBackupBinding, *os.File) (volumes.ArchiveReceipt, error)
	CloseReader(context.Context, control.VolumeBackupBinding) error
}

type backupArtifactCompletion struct {
	Schema  uint8
	Binding [32]byte
	Source  volumes.ColdSource
	Receipt volumes.ArchiveReceipt
}

type backupArtifacts struct {
	mu            sync.Mutex
	root          *os.Root
	lock          *storage.Lock
	journal       *reconcile.Journal
	cluster, node [32]byte
	backend       backupArtifactBackend
	moveBackend   moveArtifactBackend
	closed        bool
	syncFile      func(*os.File) error
	writeBytes    func(*os.File, []byte) (int, error)
}

func backupArtifactName(b control.VolumeBackupBinding) string {
	d := b.Digest()
	return hex.EncodeToString(d[:])
}
func backupArtifactKey(b control.VolumeBackupBinding) string {
	return "backup/" + backupArtifactName(b)
}
func backupPrivate(info os.FileInfo, dir bool) bool {
	mode := os.FileMode(0600)
	if dir {
		mode = 0700
	}
	if info == nil || info.Mode().Perm() != mode {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && (dir && info.IsDir() || !dir && info.Mode().IsRegular() && stat.Nlink == 1)
}
func (m *backupArtifacts) syncDirectory(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(m.syncFile(f), f.Close())
}
func backupRead(root *os.Root, name string, limit int64) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil || !backupPrivate(before, false) || before.Size() > limit {
		return nil, errBackupArtifact
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(before, current) {
		return nil, errBackupArtifact
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errBackupArtifact
	}
	return raw, nil
}
func (m *backupArtifacts) writeFile(root *os.Root, name string, raw []byte) error {
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	n, err := m.writeBytes(f, raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = m.syncFile(f)
	}
	return errors.Join(err, f.Close())
}

func openBackupArtifacts(path string, cluster, node [32]byte, backend backupArtifactBackend, moves ...moveArtifactBackend) (*backupArtifacts, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || cluster == ([32]byte{}) || node == ([32]byte{}) || backend == nil || len(moves) > 1 {
		return nil, errBackupArtifact
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	canonical, e := filepath.EvalSymlinks(path)
	if err != nil || e != nil || canonical != path || !backupPrivate(info, true) {
		return nil, errBackupArtifact
	}
	m := &backupArtifacts{cluster: cluster, node: node, backend: backend, syncFile: (*os.File).Sync, writeBytes: (*os.File).Write}
	if len(moves) == 1 {
		m.moveBackend = moves[0]
	}
	if m.lock, err = storage.LockRoot(path); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = m.Close()
		}
	}()
	if m.root, err = os.OpenRoot(path); err != nil {
		return nil, err
	}
	header, _ := json.Marshal(struct {
		Schema        uint8
		Cluster, Node [32]byte
	}{1, cluster, node})
	if _, err = m.root.Lstat("owner.json"); os.IsNotExist(err) {
		// A missing owner cannot adopt an existing journal or artifact root.
		dir, e := m.root.Open(".")
		if e != nil {
			return nil, e
		}
		names, e := dir.Readdirnames(3)
		_ = dir.Close()
		if e != nil && !errors.Is(e, io.EOF) || len(names) != 1 || names[0] != "node.lock" {
			return nil, errBackupArtifact
		}
		if err = m.writeFile(m.root, "owner.json", header); err != nil {
			return nil, err
		}
		if err = m.syncDirectory(m.root); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	raw, err := backupRead(m.root, "owner.json", 4096)
	if err != nil || !bytes.Equal(raw, header) {
		return nil, errBackupArtifact
	}
	if err = m.syncOwnedFile(m.root, "owner.json"); err != nil {
		return nil, err
	}
	if err = m.syncDirectory(m.root); err != nil {
		return nil, err
	}
	if m.journal, err = reconcile.OpenJournal(filepath.Join(path, "journal.db")); err != nil {
		return nil, err
	}
	for _, key := range m.journal.Keys() {
		r, err := m.journal.Read(key)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(key, "move-receive/") {
			if err = m.validateReceiveRecord(key, r); err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(key, "move-artifact/") {
			if err = m.validateMoveArtifactRecord(key, r); err != nil {
				return nil, err
			}
			continue
		}
		if r.Checkpoint != nil {
			b, e := m.binding(key, r.Checkpoint.Target)
			if e != nil || validateBackupDirectoryCheckpoint(b, r.Checkpoint) != nil {
				return nil, errBackupArtifact
			}
		}
		resources := []reconcile.Resource{r.State.Desired.Resource, r.State.Applied}
		if r.State.Pending != nil {
			resources = append(resources, r.State.Pending.Target)
		}
		for _, resource := range resources {
			if !resource.Present {
				continue
			}
			b, err := m.binding(key, resource)
			if err != nil || backupArtifactKey(b) != key {
				return nil, errBackupArtifact
			}
		}
	}
	ok = true
	return m, nil
}

func (m *backupArtifacts) binding(key string, resource reconcile.Resource) (control.VolumeBackupBinding, error) {
	b, err := schema.Decode[control.VolumeBackupBinding]([]byte(resource.Spec))
	if err != nil || !resource.Present || resource.Generation != 1 || b.Schema != 1 || b.Scope.Cluster != m.cluster || b.Source.Owner.Key != m.node || b.Source.Verify() != nil || b.Source.Spec.Scope != b.Scope || b.Origin.VerifyOriginal(m.cluster) != nil || backupArtifactKey(b) != key {
		return b, errBackupArtifact
	}
	return b, nil
}

func (m *backupArtifacts) directory(b control.VolumeBackupBinding) (*os.Root, error) {
	name := backupArtifactName(b)
	before, err := m.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !backupPrivate(before, true) {
		return nil, errBackupArtifact
	}
	dir, err := m.root.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	current, err := dir.Stat(".")
	raw, e := backupRead(dir, "intent.json", 256<<10)
	expected, _ := json.Marshal(b)
	if err != nil || !os.SameFile(before, current) || e != nil || !bytes.Equal(raw, expected) {
		_ = dir.Close()
		return nil, errBackupArtifact
	}
	return dir, nil
}

func (m *backupArtifacts) completion(ctx context.Context, b control.VolumeBackupBinding, hash bool) (backupArtifactCompletion, error) {
	var out backupArtifactCompletion
	dir, err := m.directory(b)
	if err != nil {
		return out, err
	}
	defer dir.Close()
	raw, err := backupRead(dir, "complete.json", 256<<10)
	if err != nil {
		return out, err
	}
	out, err = schema.Decode[backupArtifactCompletion](raw)
	if err != nil || out.Schema != 1 || out.Binding != b.Digest() || !backupSourceMatches(out.Source, b) || out.Receipt.Validate(b.Options()) != nil {
		return out, errBackupArtifact
	}
	if !hash {
		return out, nil
	}
	before, err := dir.Lstat("archive.tar")
	if err != nil || !backupPrivate(before, false) || uint64(before.Size()) != out.Receipt.Bytes {
		return out, errBackupArtifact
	}
	f, err := dir.OpenFile("archive.tar", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return out, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) {
		return out, errBackupArtifact
	}
	h := sha256.New()
	buffer := make([]byte, 64<<10)
	var total uint64
	for {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		n, e := f.Read(buffer)
		if n > 0 {
			total += uint64(n)
			if total > out.Receipt.Bytes {
				return out, errBackupArtifact
			}
			_, _ = h.Write(buffer[:n])
		}
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return out, e
		}
	}
	if total != out.Receipt.Bytes || !bytes.Equal(h.Sum(nil), out.Receipt.Digest[:]) {
		return out, errBackupArtifact
	}
	return out, nil
}

// syncOwnedFile flushes a positively identified private original. It never
// creates, truncates or replaces it, including after an earlier sync failure.
func (m *backupArtifacts) syncOwnedFile(root *os.Root, name string) error {
	before, err := root.Lstat(name)
	if err != nil || !backupPrivate(before, false) {
		return errBackupArtifact
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	after, err := f.Stat()
	if err == nil && !os.SameFile(before, after) {
		err = errBackupArtifact
	}
	if err == nil {
		err = m.syncFile(f)
	}
	return errors.Join(err, f.Close())
}

// syncCompletion recovers durability on the original positively identified
// files. A readable hash after failed directory sync is not durable publication.
// Neither file bytes nor metadata are rewritten and no new copy is dispatched.
func (m *backupArtifacts) syncCompletion(ctx context.Context, b control.VolumeBackupBinding) error {
	if _, err := m.completion(ctx, b, true); err != nil {
		return err
	}
	dir, err := m.directory(b)
	if err != nil {
		return err
	}
	defer dir.Close()
	for _, name := range []string{"archive.tar", "complete.json"} {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = m.syncOwnedFile(dir, name); err != nil {
			return err
		}
	}
	if err = m.syncDirectory(dir); err != nil {
		return err
	}
	return m.syncDirectory(m.root)
}

// Step never automatically repeats a dispatched copy. Recovery may inspect a
// synced original completion or retire that same local worker's files. Partial
// archives without completion stay Unknown until an explicit shared cancel.
func (m *backupArtifacts) Step(ctx context.Context, job control.VolumeBackup) (*backupArtifactCompletion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := job.Binding
	key := backupArtifactKey(b)
	if m.closed || b.Scope.Cluster != m.cluster || b.Source.Owner.Key != m.node {
		return nil, errBackupArtifact
	}
	cleanup := job.Phase == "Cancelling" || job.Phase == "Deleting"
	if job.Phase != "Reserved" && !cleanup {
		return nil, errBackupArtifact
	}
	if err := m.backend.Authorize(ctx, b, cleanup); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(b)
	d := reconcile.Desired{Revision: job.Revision, Resource: reconcile.Resource{Generation: 1, Spec: string(raw), Present: true}}
	if _, err := m.binding(key, d.Resource); err != nil {
		return nil, err
	}
	r, err := m.journal.Read(key)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return nil, err
	}
	missing := errors.Is(err, storage.ErrMissing)
	var proof []byte
	if !missing && r.Checkpoint != nil {
		if validateBackupDirectoryCheckpoint(b, r.Checkpoint) != nil {
			return nil, errBackupArtifact
		}
		proof = r.Checkpoint.Data
		if e := m.checkDirectoryIdentity(b, proof); e != nil && !os.IsNotExist(e) {
			return nil, e
		}
	}
	driver := backupCheckpointDriver{backupArtifactDriver{m: m, cleanup: cleanup, proof: proof}}
	if job.Phase == "Deleting" {
		if err != nil {
			return nil, errBackupArtifact
		}
		// A shared Ready published by some other producer cannot authorize
		// deleting/settling an artifact that this journal never materialized.
		if r.State.Pending != nil && r.State.Pending.Kind == reconcile.Apply {
			if err = m.journal.Step(ctx, key, driver); err != nil {
				return nil, err
			}
			r, err = m.journal.Read(key)
			if err != nil {
				return nil, err
			}
		}
		if r.State.Applied.Present && (r.State.Pending == nil || r.State.Pending.Kind != reconcile.Remove) {
			c, e := m.completion(ctx, b, false)
			if e != nil || job.Receipt == nil || *job.Receipt != c.Receipt {
				return nil, errBackupArtifact
			}
		} else if !(r.State.Pending != nil && r.State.Pending.Kind == reconcile.Remove) && !(r.State.Pending == nil && !r.State.Applied.Present && !r.State.Desired.Present && r.State.Desired.Revision == job.Revision && r.State.LastID >= 2) {
			return nil, errBackupArtifact
		}
	}
	if cleanup {
		// This serialized local worker owns no external child/RPC copy.
		// Stop/Wait is achieved by this mutex and process-exclusive root lock.
		if job.Phase == "Cancelling" {
			if err = m.backend.CloseReader(ctx, b); err != nil {
				return nil, err
			}
		}
		if missing {
			original := d
			original.Revision = 1 // accepted begin precedes shared cancellation
			if err = m.journal.Desired(key, original, 1); err != nil {
				return nil, err
			}
		}
		d.Resource = reconcile.Resource{}
		d.Retiring = 1
	}
	if err = m.journal.Desired(key, d, 1); err != nil {
		return nil, err
	}
	if err = m.journal.Step(ctx, key, driver); err != nil {
		return nil, err
	}
	r, err = m.journal.Read(key)
	if err != nil || r.State.Pending != nil {
		return nil, errors.Join(reconcile.ErrPending, err)
	}
	if cleanup {
		if r.State.Applied.Present {
			return nil, reconcile.ErrPending
		}
		// Prepared/never-planned cancellation still checks the original path.
		if err = m.remove(ctx, b, proof); err != nil {
			return nil, err
		}
		if err = m.backend.Authorize(ctx, b, true); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if !r.State.Applied.Present {
		return nil, reconcile.ErrPending
	}
	if err = m.syncCompletion(ctx, b); err != nil {
		return nil, err
	}
	c, err := m.completion(ctx, b, false)
	if err != nil {
		return nil, err
	}
	if err = m.backend.CloseReader(ctx, b); err != nil {
		return nil, err
	}
	if err = m.backend.Authorize(ctx, b, false); err != nil {
		return nil, err
	}
	return &c, nil
}

type backupArtifactDriver struct {
	m       *backupArtifacts
	cleanup bool
	proof   []byte
}

type backupCheckpointDriver struct{ backupArtifactDriver }

func (d backupCheckpointDriver) ExecuteCheckpoint(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	return d.execute(ctx, key, op, save)
}

func (d backupArtifactDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	return d.execute(ctx, key, op, nil)
}
func (d backupArtifactDriver) execute(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	b, err := d.m.binding(key, op.Target)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind == reconcile.Remove {
		err = d.m.remove(ctx, b, d.proof)
		if err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply || d.cleanup {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if err = d.m.backend.Authorize(ctx, b, false); err != nil {
		return reconcile.EffectUnknown, err
	}
	source, err := d.m.backend.Source(ctx, b)
	if err != nil || !backupSourceMatches(source, b) {
		if err == nil {
			err = errBackupArtifact
		}
		return reconcile.EffectUnknown, err
	}
	name := backupArtifactName(b)
	if err = d.m.root.Mkdir(name, 0700); err != nil {
		return reconcile.EffectUnknown, err
	}
	dir, err := d.m.root.OpenRoot(name)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	defer dir.Close()
	if save != nil {
		proof, e := d.m.captureDirectoryIdentity(b, dir)
		if e != nil {
			return reconcile.EffectUnknown, e
		}
		if e = save(proof); e != nil {
			return reconcile.EffectUnknown, e
		}
		d.proof = proof
	}
	raw, _ := json.Marshal(b)
	if err = d.m.writeFile(dir, "intent.json", raw); err == nil {
		err = d.m.syncDirectory(dir)
	}
	if err == nil {
		err = d.m.syncDirectory(d.m.root)
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	f, err := dir.OpenFile("archive.tar", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	receipt, err := d.m.backend.Export(ctx, b, f)
	if err == nil {
		err = d.m.syncFile(f)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if err = d.m.backend.Authorize(ctx, b, false); err != nil {
		return reconcile.EffectUnknown, err
	}
	completion := backupArtifactCompletion{Schema: 1, Binding: b.Digest(), Source: source, Receipt: receipt}
	raw, _ = json.Marshal(completion)
	if err = d.m.writeFile(dir, "complete.tmp", raw); err == nil {
		err = dir.Rename("complete.tmp", "complete.json")
	}
	if err == nil {
		err = d.m.syncDirectory(dir)
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	return d.Recover(ctx, key, op)
}
func (d backupArtifactDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	b, err := d.m.binding(key, op.Target)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if err = d.m.backend.Authorize(ctx, b, d.cleanup); err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind == reconcile.Remove {
		if err = d.m.remove(ctx, b, d.proof); err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if err = d.m.syncCompletion(ctx, b); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}
func (d backupArtifactDriver) Retire(ctx context.Context, key string, op reconcile.Operation, _ []byte, _ func([]byte) error) (bool, error) {
	b, err := d.m.binding(key, op.Target)
	if err != nil || !d.cleanup {
		return false, errBackupArtifact
	}
	if err = d.m.remove(ctx, b, d.proof); err != nil {
		return false, err
	}
	return true, nil
}
func (m *backupArtifacts) remove(ctx context.Context, b control.VolumeBackupBinding, proof []byte) error {
	if err := m.backend.Authorize(ctx, b, true); err != nil {
		return err
	}
	if len(proof) != 0 {
		if err := m.checkDirectoryIdentity(b, proof); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	dir, err := m.directory(b)
	if os.IsNotExist(err) {
		// With the original local worker stopped there can be no late file
		// create. This is closure of local I/O, not external RPC absence.
		return m.syncDirectory(m.root)
	}
	if err != nil {
		if len(proof) != 0 {
			return m.removeIncompleteIntent(b, proof)
		}
		return err
	}
	defer dir.Close()
	f, err := dir.Open(".")
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(5)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	for _, name := range names {
		if name != "intent.json" && name != "archive.tar" && name != "complete.json" && name != "complete.tmp" {
			return errBackupArtifact
		}
		info, e := dir.Lstat(name)
		if e != nil || !backupPrivate(info, false) {
			return errBackupArtifact
		}
	}
	for _, name := range []string{"archive.tar", "complete.json", "complete.tmp"} {
		if err = dir.Remove(name); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	// Keep the bounded immutable intent as a tombstone, so interruption
	// during deletion never erases the original path's ownership evidence.
	return m.syncDirectory(dir)
}
func (m *backupArtifacts) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var err error
	if m.journal != nil {
		err = errors.Join(err, m.journal.Close())
	}
	if m.root != nil {
		err = errors.Join(err, m.root.Close())
	}
	if m.lock != nil {
		err = errors.Join(err, m.lock.Close())
	}
	return err
}
