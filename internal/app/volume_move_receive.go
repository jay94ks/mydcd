// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"syscall"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Receipt/offset files record local I/O, never a second ownership authority.
// The shared Volume State remains the only move/fence/owner state machine.
type moveReceiveIntent struct {
	Schema   uint8
	Job      control.VolumeMove
	Manifest volumes.Manifest
}

func (b moveReceiveIntent) digest() [32]byte { raw, _ := json.Marshal(b); return sha256.Sum256(raw) }
func moveReceiveName(b moveReceiveIntent) string {
	d := b.digest()
	return "receive-" + hex.EncodeToString(d[:])
}
func moveReceiveKey(b moveReceiveIntent) string {
	d := b.digest()
	return "move-receive/" + hex.EncodeToString(d[:])
}

type moveReceiveBackend interface {
	Authorize(context.Context, moveReceiveIntent, bool) error
	Transfer(context.Context, moveReceiveIntent, uint64, [32]byte, mydcp.VolumeSink) error
}
type moveReceiveProgress struct {
	Schema                uint8
	Binding               [32]byte
	Device, Inode, Offset uint64
	Prefix                [32]byte
}
type moveReceiveCompletion struct {
	Schema  uint8
	Binding [32]byte
	Receipt volumes.ArchiveReceipt
}

func (m *backupArtifacts) receiveBinding(key string, r reconcile.Resource) (moveReceiveIntent, error) {
	b, err := schema.Decode[moveReceiveIntent]([]byte(r.Spec))
	if err != nil || !r.Present || r.Generation != 1 || b.Schema != 1 || b.Job.Verify() != nil || b.Job.Binding.Scope.Cluster != m.cluster || b.Job.Binding.Target.Key != m.node || key != moveReceiveKey(b) || b.Manifest.Binding != b.Job.Binding || !b.Manifest.ReadOnly || b.Manifest.ArchiveReceipt().Validate(b.Job.Options()) != nil || !ed25519.Verify(b.Job.Binding.Source.Key[:], volumes.ManifestBytes(b.Manifest), b.Manifest.Signature) {
		return b, errBackupArtifact
	}
	return b, nil
}
func (m *backupArtifacts) validateReceiveRecord(key string, row reconcile.Record) error {
	all := []reconcile.Resource{row.State.Desired.Resource, row.State.Applied}
	if row.State.Pending != nil {
		all = append(all, row.State.Pending.Target)
	}
	for _, r := range all {
		if r.Present {
			if _, err := m.receiveBinding(key, r); err != nil {
				return err
			}
		}
	}
	if row.Checkpoint != nil {
		b, err := m.receiveBinding(key, row.Checkpoint.Target)
		if err != nil || row.Checkpoint.Operation != 1 {
			return errBackupArtifact
		}
		id, err := schema.Decode[backupDirectoryIdentity](row.Checkpoint.Data)
		if err != nil || id.Schema != 1 || id.Binding != b.digest() || id.Inode == 0 {
			return errBackupArtifact
		}
	}
	return nil
}
func (m *backupArtifacts) receiveDirectory(b moveReceiveIntent, proof []byte) (*os.Root, error) {
	id, err := schema.Decode[backupDirectoryIdentity](proof)
	if err != nil || id.Schema != 1 || id.Binding != b.digest() {
		return nil, errBackupArtifact
	}
	before, err := m.root.Lstat(moveReceiveName(b))
	if err != nil {
		return nil, err
	}
	if !sameBackupDirectory(before, id) {
		return nil, errBackupArtifact
	}
	dir, err := m.root.OpenRoot(moveReceiveName(b))
	if err != nil {
		return nil, err
	}
	now, err := dir.Stat(".")
	if err != nil || !os.SameFile(before, now) {
		_ = dir.Close()
		return nil, errBackupArtifact
	}
	return dir, nil
}

// StepReceive holds the store's exclusive file-worker/join barrier. A2 Recover
// resumes this very file and original operation; it does not execute a new copy.
func (m *backupArtifacts) StepReceive(ctx context.Context, b moveReceiveIntent, backend moveReceiveBackend, cleanup bool) (*moveReceiveCompletion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stepReceive(ctx, b, backend, cleanup)
}

// finishReceivedMove retires only the original, positively recorded receive.
// Active completion cannot manufacture a replacement journal from absence or
// retire a still-unknown transfer. The same mutex joins all file/restore users.
func (m *backupArtifacts) finishReceivedMove(ctx context.Context, b moveReceiveIntent, backend moveReceiveBackend) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || backend == nil {
		return errBackupArtifact
	}
	raw, _ := json.Marshal(b)
	resource := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	if _, err := m.receiveBinding(moveReceiveKey(b), resource); err != nil {
		return err
	}
	row, err := m.journal.Read(moveReceiveKey(b))
	if err != nil {
		return err
	}
	if row.State.Pending != nil && (row.State.Pending.Kind != reconcile.Remove || row.State.Pending.Target != resource) {
		return reconcile.ErrPending
	}
	if row.State.Applied.Present && row.State.Applied != resource || row.State.Desired.Present && row.State.Desired.Resource != resource {
		return errBackupArtifact
	}
	if !row.State.Applied.Present && (row.State.GenerationFloor != 1 || row.State.Desired.Revision < 2 || row.State.Desired.Present || row.State.Pending != nil || row.State.LastID < 2) {
		return reconcile.ErrPending
	}
	_, err = m.stepReceive(ctx, b, backend, true)
	return err
}

// The target's prepare/restore worker is joined and its original native target
// is positively Gone before calling this cancellation path. A missing local
// intent therefore needs no synthetic receive Apply. Existing dispatches still
// use their original A2 retirement and file-identity checks.
func (m *backupArtifacts) cancelReceivedMove(ctx context.Context, b moveReceiveIntent, backend moveReceiveBackend) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || backend == nil {
		return errBackupArtifact
	}
	raw, _ := json.Marshal(b)
	if _, err := m.receiveBinding(moveReceiveKey(b), reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}); err != nil {
		return err
	}
	if err := backend.Authorize(ctx, b, true); err != nil {
		return err
	}
	if _, err := m.journal.Read(moveReceiveKey(b)); errors.Is(err, storage.ErrMissing) {
		if _, err = m.root.Lstat(moveReceiveName(b)); !os.IsNotExist(err) {
			return errors.Join(errBackupArtifact, err)
		}
		return m.syncDirectory(m.root)
	} else if err != nil {
		return err
	}
	_, err := m.stepReceive(ctx, b, backend, true)
	return err
}

// Caller owns m.mu for the full worker lifetime.
func (m *backupArtifacts) stepReceive(ctx context.Context, b moveReceiveIntent, backend moveReceiveBackend, cleanup bool) (*moveReceiveCompletion, error) {
	raw, _ := json.Marshal(b)
	resource := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	key := moveReceiveKey(b)
	if m.closed || backend == nil {
		return nil, errBackupArtifact
	}
	if _, err := m.receiveBinding(key, resource); err != nil {
		return nil, err
	}
	if err := backend.Authorize(ctx, b, cleanup); err != nil {
		return nil, err
	}
	row, err := m.journal.Read(key)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return nil, err
	}
	var proof []byte
	if row.Checkpoint != nil {
		proof = row.Checkpoint.Data
	}
	if !cleanup || errors.Is(err, storage.ErrMissing) {
		if err = m.journal.Desired(key, reconcile.Desired{Revision: 1, Resource: resource}, 1); err != nil {
			return nil, err
		}
	}
	if cleanup {
		// A future native restore must hold an A3 reference, not be silently
		// stopped or forgotten by the transfer's cleanup.
		if len(row.Consumers) != 0 {
			return nil, reconcile.ErrLease
		}
		if err = m.journal.Desired(key, reconcile.Desired{Revision: 2, Retiring: 1}, 1); err != nil {
			return nil, err
		}
	}
	d := moveReceiveDriver{m: m, b: b, backend: backend, proof: proof, cleanup: cleanup}
	if err = m.journal.Step(ctx, key, d); err != nil {
		return nil, err
	}
	row, err = m.journal.Read(key)
	if err != nil || row.State.Pending != nil {
		return nil, errors.Join(reconcile.ErrPending, err)
	}
	if cleanup {
		if row.State.Applied.Present {
			return nil, reconcile.ErrPending
		}
		return nil, m.removeReceive(b, proof)
	}
	if !row.State.Applied.Present || row.Checkpoint == nil {
		return nil, reconcile.ErrPending
	}
	sink, err := m.openReceive(ctx, b, row.Checkpoint.Data, backend)
	if err != nil {
		return nil, err
	}
	err = sink.Finish(ctx)
	err = errors.Join(err, sink.file.Close(), sink.dir.Close())
	if err != nil {
		return nil, err
	}
	c, err := m.receiveComplete(ctx, b, row.Checkpoint.Data)
	if err != nil {
		return nil, err
	}
	return &c, backend.Authorize(ctx, b, false)
}

type moveReceiveDriver struct {
	m       *backupArtifacts
	b       moveReceiveIntent
	backend moveReceiveBackend
	proof   []byte
	cleanup bool
}

func (d moveReceiveDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	return d.execute(ctx, key, op, nil)
}
func (d moveReceiveDriver) ExecuteCheckpoint(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	return d.execute(ctx, key, op, save)
}
func (d moveReceiveDriver) execute(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	if key != moveReceiveKey(d.b) {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if op.Kind == reconcile.Remove {
		err := d.m.removeReceive(d.b, d.proof)
		if err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply || d.cleanup || save == nil {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if err := d.backend.Authorize(ctx, d.b, false); err != nil {
		return reconcile.EffectUnknown, err
	}
	if err := d.m.root.Mkdir(moveReceiveName(d.b), 0700); err != nil {
		return reconcile.EffectUnknown, err
	}
	dir, err := d.m.root.OpenRoot(moveReceiveName(d.b))
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	defer dir.Close()
	before, err := d.m.root.Lstat(moveReceiveName(d.b))
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	info, err := dir.Stat(".")
	if err != nil || !backupPrivate(info, true) || !os.SameFile(info, before) {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	proof, _ := json.Marshal(backupDirectoryIdentity{Schema: 1, Binding: d.b.digest(), Device: uint64(st.Dev), Inode: st.Ino})
	if err = save(proof); err != nil {
		return reconcile.EffectUnknown, err
	}
	raw, _ := json.Marshal(d.b)
	if err = d.m.writeFile(dir, "intent.json", raw); err != nil {
		return reconcile.EffectUnknown, err
	}
	f, err := dir.OpenFile("archive.tar", os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	info, err = f.Stat()
	if err == nil {
		err = d.m.syncFile(f)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	st, ok = info.Sys().(*syscall.Stat_t)
	if !ok || !backupPrivate(info, false) {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	p := moveReceiveProgress{Schema: 1, Binding: d.b.digest(), Device: uint64(st.Dev), Inode: st.Ino, Prefix: sha256.Sum256(nil)}
	if err = d.m.saveReceiveProgress(dir, p); err == nil {
		err = d.m.syncDirectory(d.m.root)
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	d.proof = proof
	return d.resume(ctx)
}
func (d moveReceiveDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	if key != moveReceiveKey(d.b) {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if err := d.backend.Authorize(ctx, d.b, d.cleanup); err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind == reconcile.Remove {
		err := d.m.removeReceive(d.b, d.proof)
		if err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply || d.cleanup {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	return d.resume(ctx)
}
func (d moveReceiveDriver) Retire(ctx context.Context, key string, _ reconcile.Operation, _ []byte, _ func([]byte) error) (bool, error) {
	if key != moveReceiveKey(d.b) || !d.cleanup {
		return false, errBackupArtifact
	}
	if err := d.backend.Authorize(ctx, d.b, true); err != nil {
		return false, err
	}
	err := d.m.removeReceive(d.b, d.proof)
	return err == nil, err
}
func (d moveReceiveDriver) resume(ctx context.Context) (reconcile.Outcome, error) {
	s, err := d.m.openReceive(ctx, d.b, d.proof, d.backend)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	defer s.dir.Close()
	defer s.file.Close()
	if _, err = s.dir.Lstat("complete.json"); err == nil {
		if err = s.Finish(ctx); err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	} else if !os.IsNotExist(err) {
		return reconcile.EffectUnknown, err
	}
	if err = d.backend.Transfer(ctx, d.b, s.progress.Offset, s.progress.Prefix, s); err != nil {
		return reconcile.EffectUnknown, err
	}
	if !s.finished {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if err = d.backend.Authorize(ctx, d.b, false); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}

type moveReceiveSink struct {
	m        *backupArtifacts
	b        moveReceiveIntent
	backend  moveReceiveBackend
	dir      *os.Root
	file     *os.File
	progress moveReceiveProgress
	prefix   hash.Hash
	finished bool
}

func (m *backupArtifacts) openReceive(ctx context.Context, b moveReceiveIntent, proof []byte, backend moveReceiveBackend) (*moveReceiveSink, error) {
	dir, err := m.receiveDirectory(b, proof)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = dir.Close()
		}
	}()
	expected, _ := json.Marshal(b)
	raw, err := backupRead(dir, "intent.json", 256<<10)
	if err != nil || !bytes.Equal(raw, expected) {
		return nil, errBackupArtifact
	}
	raw, err = backupRead(dir, "progress.json", 4096)
	if err != nil {
		return nil, err
	}
	p, err := schema.Decode[moveReceiveProgress](raw)
	if err != nil || p.Schema != 1 || p.Binding != b.digest() || p.Inode == 0 || p.Offset > b.Manifest.Bytes || p.Offset != b.Manifest.Bytes && p.Offset%mydcp.VolumeChunkSize != 0 {
		return nil, errBackupArtifact
	}
	f, err := dir.OpenFile("archive.tar", os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	s := &moveReceiveSink{m: m, b: b, backend: backend, dir: dir, file: f, progress: p, prefix: sha256.New()}
	size, err := s.originalFile()
	if err != nil || size < p.Offset || size > min(b.Manifest.Bytes, p.Offset+mydcp.VolumeChunkSize) {
		return nil, errBackupArtifact
	}
	buffer := make([]byte, mydcp.VolumeChunkSize)
	defer clear(buffer)
	for offset := uint64(0); offset < p.Offset; {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		n := min(uint64(len(buffer)), p.Offset-offset)
		if _, err = f.ReadAt(buffer[:n], int64(offset)); err != nil {
			return nil, err
		}
		_, _ = s.prefix.Write(buffer[:n])
		offset += n
	}
	if !bytes.Equal(s.prefix.Sum(nil), p.Prefix[:]) {
		return nil, errBackupArtifact
	}
	// Revalidate and resync the ORIGINAL file/checkpoint before advertising
	// an offset, including a checkpoint whose last ACK was never received.
	if err = m.syncFile(f); err == nil {
		err = m.syncOwnedFile(dir, "progress.json")
	}
	if err == nil {
		err = m.syncDirectory(dir)
	}
	if err == nil {
		err = m.syncDirectory(m.root)
	}
	if err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}
func (s *moveReceiveSink) originalFile() (uint64, error) {
	before, err := s.dir.Lstat("archive.tar")
	if err != nil {
		return 0, err
	}
	now, err := s.file.Stat()
	if err != nil || !backupPrivate(before, false) || !backupPrivate(now, false) || !os.SameFile(before, now) {
		return 0, errBackupArtifact
	}
	st, ok := now.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != s.progress.Device || st.Ino != s.progress.Inode || now.Size() < 0 {
		return 0, errBackupArtifact
	}
	return uint64(now.Size()), nil
}
func (m *backupArtifacts) saveReceiveProgress(dir *os.Root, p moveReceiveProgress) error {
	// Only the private, known temporary metadata name may be replaced after
	// an interrupted metadata write. Original data is never truncated.
	if info, err := dir.Lstat("progress.tmp"); err == nil {
		if !backupPrivate(info, false) {
			return errBackupArtifact
		}
		if err = dir.Remove("progress.tmp"); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, _ := json.Marshal(p)
	if err := m.writeFile(dir, "progress.tmp", raw); err != nil {
		return err
	}
	if err := dir.Rename("progress.tmp", "progress.json"); err != nil {
		return err
	}
	return m.syncDirectory(dir)
}
func (s *moveReceiveSink) WriteChunk(ctx context.Context, offset uint64, data []byte) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.finished || offset != s.progress.Offset || offset >= s.b.Manifest.Bytes || uint64(len(data)) != min(uint64(mydcp.VolumeChunkSize), s.b.Manifest.Bytes-offset) {
		return 0, errBackupArtifact
	}
	if err := s.backend.Authorize(ctx, s.b, false); err != nil {
		return 0, err
	}
	size, err := s.originalFile()
	if err != nil || size < offset || size > offset+uint64(len(data)) {
		return 0, errBackupArtifact
	}
	tail := make([]byte, size-offset)
	defer clear(tail)
	if len(tail) > 0 {
		if _, err = s.file.ReadAt(tail, int64(offset)); err != nil {
			return 0, err
		}
		if !bytes.Equal(tail, data[:len(tail)]) {
			return 0, errBackupArtifact
		}
	}
	if len(tail) < len(data) {
		// WriteAt may return a short write plus error. Keep the exact tail;
		// recovery compares it with this same original chunk before appending.
		if _, err = s.file.Seek(int64(size), io.SeekStart); err != nil {
			return 0, err
		}
		n, err := s.m.writeBytes(s.file, data[len(tail):])
		if err != nil {
			return 0, err
		}
		if n != len(data)-len(tail) {
			return 0, io.ErrShortWrite
		}
	}
	if err = s.m.syncFile(s.file); err != nil {
		return 0, err
	}
	_, _ = s.prefix.Write(data)
	p := s.progress
	p.Offset = offset + uint64(len(data))
	copy(p.Prefix[:], s.prefix.Sum(nil))
	if err = s.m.saveReceiveProgress(s.dir, p); err != nil {
		return 0, err
	}
	s.progress = p
	if err = s.backend.Authorize(ctx, s.b, false); err != nil {
		return 0, err
	}
	return p.Offset, nil
}
func (s *moveReceiveSink) Finish(ctx context.Context) error {
	if err := s.backend.Authorize(ctx, s.b, false); err != nil {
		return err
	}
	size, err := s.originalFile()
	if err != nil || size != s.b.Manifest.Bytes || s.progress.Offset != size {
		return errBackupArtifact
	}
	if err = volumes.VerifyArchive(ctx, s.file, s.b.Manifest.ArchiveReceipt(), s.b.Job.Options()); err != nil {
		return err
	}
	if err = s.m.syncFile(s.file); err != nil {
		return err
	}
	c := moveReceiveCompletion{Schema: 1, Binding: s.b.digest(), Receipt: s.b.Manifest.ArchiveReceipt()}
	raw, _ := json.Marshal(c)
	if _, err = s.dir.Lstat("complete.json"); os.IsNotExist(err) {
		// A failed prior write may leave only the private completion temporary.
		if info, e := s.dir.Lstat("complete.tmp"); e == nil {
			if !backupPrivate(info, false) {
				return errBackupArtifact
			}
			if e = s.dir.Remove("complete.tmp"); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		if err = s.m.writeFile(s.dir, "complete.tmp", raw); err != nil {
			return err
		}
		if err = s.dir.Rename("complete.tmp", "complete.json"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		stored, e := backupRead(s.dir, "complete.json", 4096)
		if e != nil || !bytes.Equal(stored, raw) {
			return errBackupArtifact
		}
	}
	if err = s.m.syncOwnedFile(s.dir, "complete.json"); err == nil {
		err = s.m.syncDirectory(s.dir)
	}
	if err == nil {
		err = s.m.syncDirectory(s.m.root)
	}
	if err != nil {
		return err
	}
	if err = s.backend.Authorize(ctx, s.b, false); err != nil {
		return err
	}
	s.finished = true
	return nil
}
func (m *backupArtifacts) receiveComplete(ctx context.Context, b moveReceiveIntent, proof []byte) (moveReceiveCompletion, error) {
	var out moveReceiveCompletion
	dir, err := m.receiveDirectory(b, proof)
	if err != nil {
		return out, err
	}
	defer dir.Close()
	raw, err := backupRead(dir, "complete.json", 4096)
	if err != nil {
		return out, err
	}
	out, err = schema.Decode[moveReceiveCompletion](raw)
	if err != nil || out.Schema != 1 || out.Binding != b.digest() || out.Receipt != b.Manifest.ArchiveReceipt() {
		return moveReceiveCompletion{}, errBackupArtifact
	}
	return out, nil
}
func (m *backupArtifacts) removeReceive(b moveReceiveIntent, proof []byte) error {
	if _, err := m.root.Lstat(moveReceiveName(b)); os.IsNotExist(err) {
		return m.syncDirectory(m.root)
	} else if err != nil {
		return err
	}
	dir, err := m.receiveDirectory(b, proof)
	if err != nil {
		return err
	}
	defer dir.Close()
	f, err := dir.Open(".")
	if err != nil {
		return err
	}
	names, err := f.Readdirnames(8)
	_ = f.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	expected, _ := json.Marshal(b)
	raw, e := backupRead(dir, "intent.json", 256<<10)
	if e != nil || !bytes.Equal(raw, expected) {
		if !(len(names) == 0 || e == nil && len(names) == 1 && names[0] == "intent.json" && bytes.HasPrefix(expected, raw)) {
			return errBackupArtifact
		}
	}
	for _, name := range names {
		if name != "intent.json" && name != "archive.tar" && name != "progress.json" && name != "progress.tmp" && name != "complete.json" && name != "complete.tmp" {
			return errBackupArtifact
		}
		info, e := dir.Lstat(name)
		if e != nil || !backupPrivate(info, false) {
			return errBackupArtifact
		}
	}
	for _, name := range []string{"complete.json", "complete.tmp", "progress.json", "progress.tmp", "archive.tar", "intent.json"} {
		if err = dir.Remove(name); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err = m.syncDirectory(dir); err != nil {
		return err
	}
	before, err := m.root.Lstat(moveReceiveName(b))
	id, e := schema.Decode[backupDirectoryIdentity](proof)
	if err != nil || e != nil || !sameBackupDirectory(before, id) {
		return errBackupArtifact
	}
	if err = m.root.Remove(moveReceiveName(b)); err != nil {
		return err
	}
	return m.syncDirectory(m.root)
}
