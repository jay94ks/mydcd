// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

type receiveFake struct {
	data          []byte
	requests      []uint64
	deny, loseACK bool
}

func (f *receiveFake) Authorize(ctx context.Context, _ moveReceiveIntent, cleanup bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.deny && !cleanup {
		return mydcp.ErrAdmission
	}
	return nil
}
func (f *receiveFake) Transfer(ctx context.Context, _ moveReceiveIntent, offset uint64, prefix [32]byte, sink mydcp.VolumeSink) error {
	f.requests = append(f.requests, offset)
	if sha256.Sum256(f.data[:offset]) != prefix {
		return mydcp.ErrFrame
	}
	for offset < uint64(len(f.data)) {
		end := min(offset+mydcp.VolumeChunkSize, uint64(len(f.data)))
		next, err := sink.WriteChunk(ctx, offset, f.data[offset:end])
		if err != nil {
			return err
		}
		if next != end {
			return mydcp.ErrFrame
		}
		offset = next
		if f.loseACK {
			f.loseACK = false
			return errors.New("original ACK not observed")
		}
	}
	return sink.Finish(ctx)
}
func receiveFixture(t *testing.T) (moveReceiveIntent, *backupArtifactFake, *receiveFake, string) {
	t.Helper()
	source, backup, _ := moveArtifactFixture(t)
	j := source.Job
	j.Binding.MaxBytes = 1 << 20
	j.CapacityBytes = 1 << 20
	q, err := schema.Decode[control.VolumeMoveBegin](j.Origin.Change.Payload)
	if err != nil {
		t.Fatal(err)
	}
	q.MaxBytes = j.Binding.MaxBytes
	q.CapacityBytes = j.CapacityBytes
	j.Origin.Change.Payload, _ = json.Marshal(q)
	user := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, 32))
	j.Origin.Signature = ed25519.Sign(user, control.OperationBytes(j.Origin))
	if err = j.Verify(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(backup.data, "row"), bytes.Repeat([]byte("original SQL data\x00"), 22000), 0640); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(backup.data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var archive bytes.Buffer
	receipt, err := volumes.WriteArchive(context.Background(), root, &archive, j.Options())
	if err != nil {
		t.Fatal(err)
	}
	manifest := volumes.Manifest{Binding: j.Binding, Artifact: receipt.Digest, Bytes: receipt.Bytes, DataBytes: receipt.DataBytes, Files: receipt.Entries, ReadOnly: true}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	manifest.Signature = ed25519.Sign(key, volumes.ManifestBytes(manifest))
	return moveReceiveIntent{Schema: 1, Job: j, Manifest: manifest}, backup, &receiveFake{data: archive.Bytes()}, filepath.Join(t.TempDir(), "receiver")
}
func openReceiverFixture(t *testing.T, path string, b moveReceiveIntent, backup backupArtifactBackend) *backupArtifacts {
	t.Helper()
	m, err := openBackupArtifacts(path, b.Job.Binding.Scope.Cluster, b.Job.Binding.Target.Key, backup)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMoveReceiveFinalCleanupRequiresOriginalHistoryAndReturnsOnlyTransferFiles(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	b, backup, f, path := receiveFixture(t)
	ctx := context.Background()
	m := openReceiverFixture(t, path, b, backup)
	defer func() { _ = m.Close() }()
	if err := m.finishReceivedMove(ctx, b, f); err == nil || len(m.journal.Keys()) != 0 {
		t.Fatal("missing receive history was synthesized as completion", err)
	}
	if _, err := m.StepReceive(ctx, b, f, false); err != nil {
		t.Fatal(err)
	}
	requests := len(f.requests)
	pin, err := m.journal.Borrow(moveReceiveKey(b), moveRestoreConsumer(b), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.finishReceivedMove(ctx, b, f); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("restore still owns the original receive file", err)
	}
	if err = m.journal.Return(moveReceiveKey(b), moveRestoreConsumer(b), pin); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("receive cleanup sync failed")
	m.syncFile = func(*os.File) error { return injected }
	if err = m.finishReceivedMove(ctx, b, f); !errors.Is(err, injected) {
		t.Fatal("unsynced cleanup was reported complete", err)
	}
	row, err := m.journal.Read(moveReceiveKey(b))
	if err != nil || row.State.Pending == nil || row.State.Pending.Kind != reconcile.Remove {
		t.Fatal("original cleanup intent lost after sync failure", err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m = openReceiverFixture(t, path, b, backup)
	if err = m.finishReceivedMove(ctx, b, f); err != nil {
		t.Fatal("original cleanup did not recover", err)
	}
	if err = m.finishReceivedMove(ctx, b, f); err != nil || len(f.requests) != requests {
		t.Fatal("cleanup replay resumed/replaced original transfer", err)
	}
	row, err = m.journal.Read(moveReceiveKey(b))
	if err != nil || row.State.Pending != nil || row.State.Applied.Present || row.State.Desired.Present || row.State.LastID != 2 || len(row.Consumers) != 0 {
		t.Fatal("original transfer was not fully retired", err)
	}
	if _, err = m.root.Lstat(moveReceiveName(b)); !os.IsNotExist(err) {
		t.Fatal("original receive files remain", err)
	}
}

func TestMoveReceiveCancellationDoesNotFabricateAnUndispatchedTransfer(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	b, backup, f, path := receiveFixture(t)
	m := openReceiverFixture(t, path, b, backup)
	defer m.Close()
	ctx := context.Background()
	// The actual caller must first join its native worker and prove target Gone.
	if err := m.cancelReceivedMove(ctx, b, f); err != nil || len(m.journal.Keys()) != 0 || len(f.requests) != 0 {
		t.Fatal("cancelling an undispatched transfer created an Apply", err)
	}
	if err := m.root.Mkdir(moveReceiveName(b), 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.cancelReceivedMove(ctx, b, f); err == nil {
		t.Fatal("orphan files were inferred to be absent/owned from missing history")
	}
	if err := m.root.Remove(moveReceiveName(b)); err != nil {
		t.Fatal(err)
	}
	f.loseACK = true
	if _, err := m.StepReceive(ctx, b, f, false); err == nil {
		t.Fatal("lost original transfer response was not injected")
	}
	requests := len(f.requests)
	if err := m.cancelReceivedMove(ctx, b, f); err != nil || len(f.requests) != requests {
		t.Fatal("original partial transfer retirement resumed/replaced it", err)
	}
	row, err := m.journal.Read(moveReceiveKey(b))
	if err != nil || row.State.Pending != nil || row.State.Applied.Present || row.State.Desired.Present || len(row.Consumers) != 0 {
		t.Fatal("original partial transfer was not settled", err)
	}
}

func TestMoveReceiveDurableOffsetResumeAfterIOFailure(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	for _, stage := range []string{"data-sync", "progress-sync", "directory-sync", "short-data-write", "lost-ack"} {
		t.Run(stage, func(t *testing.T) {
			b, backup, f, path := receiveFixture(t)
			ctx := context.Background()
			m := openReceiverFixture(t, path, b, backup)
			defer func() { _ = m.Close() }()
			failed, wrote := false, false
			if stage == "lost-ack" {
				f.loseACK = true
			}
			m.writeBytes = func(file *os.File, data []byte) (int, error) {
				if filepath.Base(file.Name()) == "archive.tar" {
					wrote = true
					if stage == "short-data-write" && !failed {
						failed = true
						n, err := file.Write(data[:len(data)/2])
						return n, errors.Join(io.ErrShortWrite, err)
					}
				}
				return file.Write(data)
			}
			m.syncFile = func(file *os.File) error {
				if !failed && wrote {
					info, err := file.Stat()
					if err != nil {
						return err
					}
					if stage == "data-sync" && filepath.Base(file.Name()) == "archive.tar" || stage == "progress-sync" && filepath.Base(file.Name()) == "progress.tmp" || stage == "directory-sync" && info.IsDir() {
						failed = true
						return errors.New("original " + stage + " failed")
					}
				}
				return file.Sync()
			}
			if _, err := m.StepReceive(ctx, b, f, false); err == nil {
				t.Fatal("unsettled I/O/ACK reported complete")
			}
			if !failed && stage != "lost-ack" {
				t.Fatal("failure not injected")
			}
			row, err := m.journal.Read(moveReceiveKey(b))
			if err != nil || row.State.Pending == nil || row.State.LastID != 1 || row.Checkpoint == nil {
				t.Fatal("original A2/identity lost", err)
			}
			dir, err := m.receiveDirectory(b, row.Checkpoint.Data)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := backupRead(dir, "progress.json", 4096)
			if err != nil {
				t.Fatal(err)
			}
			progress, err := schema.Decode[moveReceiveProgress](raw)
			if err != nil {
				t.Fatal(err)
			}
			info, err := dir.Stat("archive.tar")
			_ = dir.Close()
			if err != nil {
				t.Fatal(err)
			}
			if err = m.Close(); err != nil {
				t.Fatal(err)
			}
			m = openReceiverFixture(t, path, b, backup)
			complete, err := m.StepReceive(ctx, b, f, false)
			if err != nil || complete == nil || complete.Receipt != b.Manifest.ArchiveReceipt() {
				t.Fatal("same original receiver resume", err)
			}
			if len(f.requests) != 2 || f.requests[1] != progress.Offset {
				t.Fatal("new copy or wrong offset", f.requests, progress.Offset)
			}
			row, err = m.journal.Read(moveReceiveKey(b))
			if err != nil || row.State.Pending != nil || row.State.LastID != 1 || !row.State.Applied.Present {
				t.Fatal("replaced operation", err)
			}
			dir, err = m.receiveDirectory(b, row.Checkpoint.Data)
			if err != nil {
				t.Fatal(err)
			}
			now, err := dir.Stat("archive.tar")
			if err != nil || !os.SameFile(info, now) {
				t.Fatal("replaced original file", err)
			}
			data, err := backupRead(dir, "archive.tar", int64(len(f.data)))
			_ = dir.Close()
			if err != nil || !bytes.Equal(data, f.data) {
				t.Fatal("different resumed archive", err)
			}
			f.deny = true
			if _, err = m.StepReceive(ctx, b, f, false); err == nil {
				t.Fatal("completed file bypassed current authority")
			}
			if _, err = m.StepReceive(ctx, b, f, true); err != nil {
				t.Fatal("explicit original file cleanup", err)
			}
			if _, err = m.root.Lstat(moveReceiveName(b)); !os.IsNotExist(err) {
				t.Fatal("owned receiving files remain", err)
			}
		})
	}
}
func TestMoveReceiveRejectsChangedOriginalFileOrPrefix(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	for _, change := range []string{"inode", "prefix", "tail"} {
		t.Run(change, func(t *testing.T) {
			b, backup, f, path := receiveFixture(t)
			ctx := context.Background()
			m := openReceiverFixture(t, path, b, backup)
			defer func() { _ = m.Close() }()
			f.loseACK = true
			if _, err := m.StepReceive(ctx, b, f, false); err == nil {
				t.Fatal("missing interruption")
			}
			filePath := filepath.Join(path, moveReceiveName(b), "archive.tar")
			if change == "inode" {
				if err := os.Rename(filePath, filePath+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filePath, f.data[:mydcp.VolumeChunkSize], 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				file, err := os.OpenFile(filePath, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				offset := int64(0)
				if change == "tail" {
					offset = mydcp.VolumeChunkSize
				}
				_, err = file.WriteAt([]byte{0xff}, offset)
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			info, err := os.Stat(filePath)
			if err != nil {
				t.Fatal(err)
			}
			if err = m.Close(); err != nil {
				t.Fatal(err)
			}
			m = openReceiverFixture(t, path, b, backup)
			if _, err = m.StepReceive(ctx, b, f, false); err == nil {
				t.Fatal("different original accepted")
			}
			now, err := os.Stat(filePath)
			if err != nil || !os.SameFile(info, now) || info.Size() != now.Size() {
				t.Fatal("failure truncated/replaced file", err)
			}
			row, err := m.journal.Read(moveReceiveKey(b))
			if err != nil || row.State.Pending == nil || row.State.LastID != 1 {
				t.Fatal("uncertainty lost", err)
			}
		})
	}
}
