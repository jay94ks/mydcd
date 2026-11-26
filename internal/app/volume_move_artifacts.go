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
	"strings"
	"syscall"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

type moveArtifactBackend interface {
	Authorize(context.Context, moveArtifactIntent, bool) error
	Source(context.Context, moveArtifactIntent) (volumes.ColdSource, error)
	Export(context.Context, moveArtifactIntent, *os.File) (volumes.ArchiveReceipt, error)
	CloseReader(context.Context, moveArtifactIntent) error
}
type moveArtifactIntent struct {
	Schema uint8
	Job    control.VolumeMove
	Reader volumes.Consumer
}

func (b moveArtifactIntent) digest() [32]byte { raw, _ := json.Marshal(b); return sha256.Sum256(raw) }
func moveArtifactName(b moveArtifactIntent) string {
	d := b.digest()
	return "move-" + hex.EncodeToString(d[:])
}
func moveArtifactKey(b moveArtifactIntent) string {
	d := b.digest()
	return "move-artifact/" + hex.EncodeToString(d[:])
}

type moveArtifactCompletion struct {
	Schema  uint8
	Binding [32]byte
	Source  volumes.ColdSource
	Receipt volumes.ArchiveReceipt
}

func (m *backupArtifacts) moveBinding(key string, r reconcile.Resource) (moveArtifactIntent, error) {
	b, err := schema.Decode[moveArtifactIntent]([]byte(r.Spec))
	if err != nil || b.Schema != 1 || b.Job.Verify() != nil || b.Job.Binding.Scope.Cluster != m.cluster || b.Job.Binding.Source.Key != m.node || !b.Job.Binding.MatchesReader(b.Reader) || !r.Present || r.Generation != 1 || key != moveArtifactKey(b) {
		return b, errBackupArtifact
	}
	return b, nil
}
func (m *backupArtifacts) validateMoveArtifactRecord(key string, r reconcile.Record) error {
	resources := []reconcile.Resource{r.State.Desired.Resource, r.State.Applied}
	if r.State.Pending != nil {
		resources = append(resources, r.State.Pending.Target)
	}
	for _, target := range resources {
		if target.Present {
			if _, err := m.moveBinding(key, target); err != nil {
				return err
			}
		}
	}
	if r.Checkpoint != nil {
		b, err := m.moveBinding(key, r.Checkpoint.Target)
		if err != nil || validateMoveDirectoryProof(b, r.Checkpoint) != nil {
			return errBackupArtifact
		}
	}
	return nil
}
func validateMoveDirectoryProof(b moveArtifactIntent, c *reconcile.EffectCheckpoint) error {
	if c == nil || c.Operation != 1 || !c.Target.Present || c.Target.Generation != 1 {
		return errBackupArtifact
	}
	id, err := schema.Decode[backupDirectoryIdentity](c.Data)
	raw, _ := json.Marshal(b)
	if err != nil || id.Schema != 1 || id.Binding != b.digest() || id.Inode == 0 || c.Target.Spec != string(raw) {
		return errBackupArtifact
	}
	return nil
}
func (m *backupArtifacts) moveDirectory(b moveArtifactIntent, proof []byte) (*os.Root, error) {
	id, err := schema.Decode[backupDirectoryIdentity](proof)
	if err != nil || id.Schema != 1 || id.Binding != b.digest() {
		return nil, errBackupArtifact
	}
	before, err := m.root.Lstat(moveArtifactName(b))
	if err != nil {
		return nil, err
	}
	if !sameBackupDirectory(before, id) {
		return nil, errBackupArtifact
	}
	dir, err := m.root.OpenRoot(moveArtifactName(b))
	if err != nil {
		return nil, err
	}
	current, err := dir.Stat(".")
	if err != nil || !os.SameFile(before, current) {
		_ = dir.Close()
		return nil, errBackupArtifact
	}
	return dir, nil
}
func (m *backupArtifacts) moveCompletion(ctx context.Context, b moveArtifactIntent, proof []byte, resync bool) (moveArtifactCompletion, error) {
	var out moveArtifactCompletion
	dir, err := m.moveDirectory(b, proof)
	if err != nil {
		return out, err
	}
	defer dir.Close()
	expected, _ := json.Marshal(b)
	raw, err := backupRead(dir, "intent.json", 256<<10)
	if err != nil || !bytes.Equal(raw, expected) {
		return out, errBackupArtifact
	}
	raw, err = backupRead(dir, "complete.json", 256<<10)
	if err != nil {
		return out, err
	}
	out, err = schema.Decode[moveArtifactCompletion](raw)
	if err != nil || out.Schema != 1 || out.Binding != b.digest() || !backupSourceMatches(out.Source, control.VolumeBackupBinding{Scope: b.Job.Binding.Scope, Source: b.Job.Source, Compatibility: b.Job.Binding.Compatibility}) || out.Receipt.Validate(b.Job.Options()) != nil {
		return out, errBackupArtifact
	}
	before, err := dir.Lstat("archive.tar")
	if err != nil || !backupPrivate(before, false) || uint64(before.Size()) != out.Receipt.Bytes {
		return out, errBackupArtifact
	}
	f, err := dir.OpenFile("archive.tar", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return out, err
	}
	info, err := f.Stat()
	if err == nil && !os.SameFile(before, info) {
		err = errBackupArtifact
	}
	if err == nil {
		err = volumes.VerifyArchive(ctx, f, out.Receipt, b.Job.Options())
	}
	if err == nil && resync {
		err = m.syncFile(f)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return moveArtifactCompletion{}, err
	}
	if resync {
		if err = m.syncOwnedFile(dir, "complete.json"); err == nil {
			err = m.syncDirectory(dir)
		}
		if err == nil {
			err = m.syncDirectory(m.root)
		}
	}
	return out, err
}

// StepMove owns the exclusive original source worker and uses the SAME A2
// journal as backup artifacts. Unknown copy recovery only reads/resyncs the
// original receipt; it never recreates/truncates/recopies a partial archive.
func (m *backupArtifacts) StepMove(ctx context.Context, job control.VolumeMove, reader volumes.Consumer, cleanup bool) (*moveArtifactCompletion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := moveArtifactIntent{Schema: 1, Job: job, Reader: reader}
	key := moveArtifactKey(b)
	raw, _ := json.Marshal(b)
	resource := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	if m.closed || m.moveBackend == nil {
		return nil, errBackupArtifact
	}
	if _, err := m.moveBinding(key, resource); err != nil {
		return nil, err
	}
	if err := m.moveBackend.Authorize(ctx, b, cleanup); err != nil {
		return nil, err
	}
	old, err := m.journal.Read(key)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return nil, err
	}
	var proof []byte
	if err == nil && old.Checkpoint != nil {
		if validateMoveDirectoryProof(b, old.Checkpoint) != nil {
			return nil, errBackupArtifact
		}
		proof = old.Checkpoint.Data
	}
	if !cleanup || errors.Is(err, storage.ErrMissing) {
		if err = m.journal.Desired(key, reconcile.Desired{Revision: 1, Resource: resource}, 1); err != nil {
			return nil, err
		}
	}
	if cleanup {
		// This mutex is also the join barrier for every source file worker.
		// A failed stream retains THIS exact local reference; explicit cancel
		// may return it after the worker has exited, without claiming anything
		// about the remote target's staging or its shared reservation.
		for consumer, pin := range old.Consumers {
			if consumer != moveStreamConsumer(b) || pin.Generation != 1 {
				return nil, reconcile.ErrLease
			}
			if err = m.journal.Return(key, consumer, pin); err != nil {
				return nil, err
			}
		}
		if err = m.moveBackend.CloseReader(ctx, b); err != nil {
			return nil, err
		}
		if err = m.journal.Desired(key, reconcile.Desired{Revision: 2, Resource: reconcile.Resource{}, Retiring: 1}, 1); err != nil {
			return nil, err
		}
	}
	driver := moveArtifactDriver{m: m, b: b, proof: proof, cleanup: cleanup}
	if err = m.journal.Step(ctx, key, driver); err != nil {
		return nil, err
	}
	row, err := m.journal.Read(key)
	if err != nil || row.State.Pending != nil {
		return nil, errors.Join(reconcile.ErrPending, err)
	}
	if cleanup {
		if row.State.Applied.Present {
			return nil, reconcile.ErrPending
		}
		if err = m.removeMoveArtifact(b, proof); err != nil {
			return nil, err
		}
		return nil, m.moveBackend.Authorize(ctx, b, true)
	}
	if !row.State.Applied.Present || row.Checkpoint == nil {
		return nil, reconcile.ErrPending
	}
	c, err := m.moveCompletion(ctx, b, row.Checkpoint.Data, true)
	if err != nil {
		return nil, err
	}
	if err = m.moveBackend.CloseReader(ctx, b); err != nil {
		return nil, err
	}
	if err = m.moveBackend.Authorize(ctx, b, false); err != nil {
		return nil, err
	}
	return &c, nil
}

func moveStreamConsumer(b moveArtifactIntent) string {
	return "move-stream/" + hex.EncodeToString(b.Job.Binding.Target.Key[:])
}

func (m *backupArtifacts) withMoveFile(ctx context.Context, b moveArtifactIntent, receipt volumes.ArchiveReceipt, read func(io.ReadSeeker) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.moveBackend == nil || read == nil {
		return errBackupArtifact
	}
	if err := m.moveBackend.Authorize(ctx, b, false); err != nil {
		return err
	}
	key := moveArtifactKey(b)
	row, err := m.journal.Read(key)
	if err != nil || row.State.Pending != nil || !row.State.Applied.Present || row.Checkpoint == nil {
		return errBackupArtifact
	}
	original, err := m.moveBinding(key, row.State.Applied)
	if err != nil || original.digest() != b.digest() {
		return errBackupArtifact
	}
	completion, err := m.moveCompletion(ctx, b, row.Checkpoint.Data, true)
	if err != nil || completion.Receipt != receipt {
		return errors.Join(errBackupArtifact, err)
	}
	pin, err := m.journal.Borrow(key, moveStreamConsumer(b), 1)
	if err != nil {
		return err
	}
	dir, err := m.moveDirectory(b, row.Checkpoint.Data)
	if err != nil {
		return err
	}
	defer dir.Close()
	before, err := dir.Lstat("archive.tar")
	if err != nil || !backupPrivate(before, false) {
		return errBackupArtifact
	}
	f, err := dir.OpenFile("archive.tar", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	current, err := f.Stat()
	if err == nil && !os.SameFile(before, current) {
		err = errBackupArtifact
	}
	if err == nil {
		err = read(f)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	} // Preserve the exact original reference through uncertainty.
	return m.journal.Return(key, moveStreamConsumer(b), pin)
}

type moveArtifactDriver struct {
	m       *backupArtifacts
	b       moveArtifactIntent
	proof   []byte
	cleanup bool
}

func (d moveArtifactDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	return d.execute(ctx, key, op, nil)
}
func (d moveArtifactDriver) ExecuteCheckpoint(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	return d.execute(ctx, key, op, save)
}
func (d moveArtifactDriver) execute(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	b, err := d.m.moveBinding(key, op.Target)
	if err != nil || b.digest() != d.b.digest() {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if op.Kind == reconcile.Remove {
		err = d.m.removeMoveArtifact(b, d.proof)
		if err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply || d.cleanup || save == nil {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if err = d.m.moveBackend.Authorize(ctx, b, false); err != nil {
		return reconcile.EffectUnknown, err
	}
	source, err := d.m.moveBackend.Source(ctx, b)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if err = d.m.root.Mkdir(moveArtifactName(b), 0700); err != nil {
		return reconcile.EffectUnknown, err
	}
	dir, err := d.m.root.OpenRoot(moveArtifactName(b))
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	defer dir.Close()
	before, err := d.m.root.Lstat(moveArtifactName(b))
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	current, err := dir.Stat(".")
	if err != nil || !os.SameFile(before, current) || !backupPrivate(current, true) {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	st, ok := current.Sys().(*syscall.Stat_t)
	if !ok || st.Ino == 0 {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	proof, _ := json.Marshal(backupDirectoryIdentity{Schema: 1, Binding: b.digest(), Device: uint64(st.Dev), Inode: st.Ino})
	if err = save(proof); err != nil {
		return reconcile.EffectUnknown, err
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
	receipt, err := d.m.moveBackend.Export(ctx, b, f)
	if err == nil {
		err = d.m.syncFile(f)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if err = d.m.moveBackend.Authorize(ctx, b, false); err != nil {
		return reconcile.EffectUnknown, err
	}
	raw, _ = json.Marshal(moveArtifactCompletion{Schema: 1, Binding: b.digest(), Source: source, Receipt: receipt})
	if err = d.m.writeFile(dir, "complete.tmp", raw); err == nil {
		err = dir.Rename("complete.tmp", "complete.json")
	}
	if err == nil {
		err = d.m.syncDirectory(dir)
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	_, err = d.m.moveCompletion(ctx, b, proof, true)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}
func (d moveArtifactDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	if err := d.m.moveBackend.Authorize(ctx, d.b, d.cleanup); err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind == reconcile.Remove {
		if err := d.m.removeMoveArtifact(d.b, d.proof); err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if _, err := d.m.moveCompletion(ctx, d.b, d.proof, true); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}
func (d moveArtifactDriver) Retire(ctx context.Context, key string, op reconcile.Operation, _ []byte, _ func([]byte) error) (bool, error) {
	if !d.cleanup || key != moveArtifactKey(d.b) {
		return false, errBackupArtifact
	}
	if err := d.m.moveBackend.Authorize(ctx, d.b, true); err != nil {
		return false, err
	}
	if err := d.m.removeMoveArtifact(d.b, d.proof); err != nil {
		return false, err
	}
	return true, nil
}
func (m *backupArtifacts) removeMoveArtifact(b moveArtifactIntent, proof []byte) error {
	// Journal.Step owns the original entry lock while invoking its driver.
	// StepMove checked users before entering Step under the store-wide worker
	// mutex; the journal also drains its A3 pins before dispatching Remove.
	_, err := m.root.Lstat(moveArtifactName(b))
	if os.IsNotExist(err) {
		return m.syncDirectory(m.root)
	}
	if err != nil {
		return err
	}
	dir, err := m.moveDirectory(b, proof)
	if err != nil {
		return err
	}
	defer dir.Close()
	f, err := dir.Open(".")
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(6)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	expected, _ := json.Marshal(b)
	intent, err := backupRead(dir, "intent.json", int64(len(expected)))
	complete := err == nil && bytes.Equal(intent, expected)
	if !complete && !(os.IsNotExist(err) && len(names) == 0 || err == nil && len(names) == 1 && names[0] == "intent.json" && len(intent) < len(expected) && bytes.HasPrefix(expected, intent)) {
		return errBackupArtifact
	}
	for _, name := range names {
		if name != "intent.json" && name != "archive.tar" && name != "complete.tmp" && name != "complete.json" {
			return errBackupArtifact
		}
		info, err := dir.Lstat(name)
		if err != nil || !backupPrivate(info, false) {
			return errBackupArtifact
		}
	}
	for _, name := range []string{"complete.json", "complete.tmp", "archive.tar", "intent.json"} {
		if err = dir.Remove(name); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err = m.syncDirectory(dir); err != nil {
		return err
	}
	current, err := m.root.Lstat(moveArtifactName(b))
	if err != nil {
		return err
	}
	id, err := schema.Decode[backupDirectoryIdentity](proof)
	if err != nil || !sameBackupDirectory(current, id) {
		return errBackupArtifact
	}
	if err = m.root.Remove(moveArtifactName(b)); err != nil {
		return err
	}
	return m.syncDirectory(m.root)
}

// The original signed shared reader receipt supplies this exact local A2 key.
// The mutex joins every file worker/stream before the terminal journal and
// synced directory absence are inspected. Missing history is not closure.
func (m *backupArtifacts) moveSourceClosed(ctx context.Context, b moveArtifactIntent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || b.Job.Binding.Scope.Cluster != m.cluster || b.Job.Binding.Source.Key != m.node || !b.Job.Binding.MatchesReader(b.Reader) {
		return errBackupArtifact
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	row, err := m.journal.Read(moveArtifactKey(b))
	if err != nil {
		return err
	}
	if row.State.Pending != nil || row.State.Applied.Present || row.State.Desired.Present || row.State.GenerationFloor != 1 || row.State.Desired.Revision < 2 || row.State.LastID < 2 || len(row.Consumers) != 0 {
		return reconcile.ErrPending
	}
	if _, err = m.root.Lstat(moveArtifactName(b)); !os.IsNotExist(err) {
		return errors.Join(reconcile.ErrPending, err)
	}
	return m.syncDirectory(m.root)
}

// Called only after the CURRENT shared generation floors prove this move has
// never acquired a source reader. The mutex joins all admitted local workers;
// a contradictory original local intent remains Unknown rather than discarded.
func (m *backupArtifacts) moveSourceIdle(ctx context.Context, job control.VolumeMove) error {
	return m.moveTransferIdle(ctx, job, false)
}

func (m *backupArtifacts) moveTargetIdle(ctx context.Context, job control.VolumeMove) error {
	return m.moveTransferIdle(ctx, job, true)
}

func (m *backupArtifacts) moveTransferIdle(ctx context.Context, job control.VolumeMove, target bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	owner, prefix := job.Binding.Source.Key, "move-artifact/"
	if target {
		owner, prefix = job.Binding.Target.Key, "move-receive/"
	}
	if m.closed || job.Verify() != nil || job.Binding.Scope.Cluster != m.cluster || owner != m.node {
		return errBackupArtifact
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, key := range m.journal.Keys() {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		row, err := m.journal.Read(key)
		if err != nil {
			return err
		}
		resources := []reconcile.Resource{row.State.Desired.Resource, row.State.Applied}
		if row.State.Pending != nil {
			resources = append(resources, row.State.Pending.Target)
		}
		if row.Checkpoint != nil {
			resources = append(resources, row.Checkpoint.Target)
		}
		for _, resource := range resources {
			if !resource.Present {
				continue
			}
			var recorded control.VolumeMove
			if target {
				b, err := m.receiveBinding(key, resource)
				if err != nil {
					return err
				}
				recorded = b.Job
			} else {
				b, err := m.moveBinding(key, resource)
				if err != nil {
					return err
				}
				recorded = b.Job
			}
			if recorded.Digest() == job.Digest() {
				return reconcile.ErrPending
			}
		}
	}
	return m.syncDirectory(m.root)
}
