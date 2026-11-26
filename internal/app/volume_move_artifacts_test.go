// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

type moveArtifactFake struct{ original *backupArtifactFake }

func (f moveArtifactFake) Authorize(ctx context.Context, _ moveArtifactIntent, cleanup bool) error {
	return f.original.Authorize(ctx, control.VolumeBackupBinding{}, cleanup)
}
func (f moveArtifactFake) Source(context.Context, moveArtifactIntent) (volumes.ColdSource, error) {
	return f.original.source, nil
}
func (f moveArtifactFake) Export(ctx context.Context, b moveArtifactIntent, out *os.File) (volumes.ArchiveReceipt, error) {
	return f.original.Export(ctx, control.VolumeBackupBinding{Scope: b.Job.Binding.Scope, Source: b.Job.Source, MaxBytes: b.Job.Binding.MaxBytes, MaxEntries: b.Job.MaxEntries}, out)
}
func (f moveArtifactFake) CloseReader(ctx context.Context, _ moveArtifactIntent) error {
	return f.original.CloseReader(ctx, control.VolumeBackupBinding{})
}

func moveArtifactFixture(t *testing.T) (moveArtifactIntent, *backupArtifactFake, string) {
	t.Helper()
	backup, f, path := artifactFixture(t)
	node := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	user := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, 32))
	targetKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{64}, 32))
	b := backup.Binding
	c, err := access.New([32]byte(user.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Enroll([32]byte(user.Public().(ed25519.PublicKey)), access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(user.Public().(ed25519.PublicKey)), Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant("admin", b.Scope.Tenant, 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant(b.Scope.Tenant)
	c, err = c.SetNodes("admin", b.Scope.Tenant, tenant.Revision, []string{"node-a", "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	target := b.Source.Spec
	target.Node = "node-b"
	target.NodeKey = [32]byte(targetKey.Public().(ed25519.PublicKey))
	target.Materialization = "m-move"
	raw, _ := json.Marshal(target)
	docker := engine.Client{Owner: engine.Owner(b.Scope.Cluster, target.NodeKey)}
	id, err := docker.Identity("volume", volumes.NativeKey(target), reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	core, err := volumes.New(c, "admin", b.Scope, b.Source.Owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Prepare(c, "admin", 1, 1, "move", volumes.Owner{Node: target.Node, Key: target.NodeKey, Native: id.Name}, b.Compatibility, b.MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	move, _ := core.Move("move")
	fence := volumes.FenceProof{Binding: move.Binding, FenceThrough: 1, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
	fence.Signature = ed25519.Sign(node, volumes.FenceBytes(fence))
	core, err = core.RecordFence(fence)
	if err != nil {
		t.Fatal(err)
	}
	core, reader, err := core.AcquireMoveReader(c, "admin", core.Revision(), move.Binding)
	if err != nil {
		t.Fatal(err)
	}
	_ = core
	q := control.VolumeMoveBegin{Scope: b.Scope, ID: "move", OwnerRevision: 1, Target: target, Compatibility: b.Compatibility, MaxBytes: b.MaxBytes, MaxEntries: b.MaxEntries, CapacityBytes: b.MaxBytes, ExpiresAt: 1000}
	raw, _ = json.Marshal(q)
	origin := b.Origin
	origin.RequestID = "move"
	origin.Change = control.Change{Schema: 1, Action: "begin-volume-move", Principal: "admin", Expected: 1, Payload: raw}
	origin.Signature = ed25519.Sign(user, control.OperationBytes(origin))
	job := control.VolumeMove{Schema: 1, Binding: move.Binding, Source: b.Source, Target: target, MaxEntries: b.MaxEntries, CapacityBytes: b.MaxBytes, ExpiresAt: 1000, Origin: origin}
	if err = job.Verify(); err != nil {
		t.Fatal(err)
	}
	return moveArtifactIntent{Schema: 1, Job: job, Reader: reader}, f, path
}
func TestMoveArtifactOriginalCompletionRestartAndCleanup(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	b, f, path := moveArtifactFixture(t)
	ctx := context.Background()
	open := func() *backupArtifacts {
		t.Helper()
		m, err := openBackupArtifacts(path, b.Job.Binding.Scope.Cluster, b.Job.Binding.Source.Key, f, moveArtifactFake{f})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := open()
	defer func() { _ = m.Close() }()
	first, err := m.StepMove(ctx, b.Job, b.Reader, false)
	if err != nil {
		t.Fatal(err)
	}
	if first.Receipt.DataBytes == 0 || f.exports != 1 {
		t.Fatal("no original archive")
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m = open()
	again, err := m.StepMove(ctx, b.Job, b.Reader, false)
	if err != nil || again.Receipt != first.Receipt || f.exports != 1 {
		t.Fatal("recovery recopied/replaced original", err)
	}
	if _, err = m.StepMove(ctx, b.Job, b.Reader, true); err != nil {
		t.Fatal(err)
	}
	if _, err = m.StepMove(ctx, b.Job, b.Reader, true); err != nil {
		t.Fatal("cleanup original replay", err)
	}
	if _, err = m.root.Lstat(moveArtifactName(b)); !os.IsNotExist(err) {
		t.Fatal("owned artifact still exists", err)
	}
	if f.exports != 1 {
		t.Fatal("cleanup copied source")
	}
}
func TestMoveArtifactPartialAndReplacementRemainUnknown(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "partial", true: "replacement"}[replace], func(t *testing.T) {
			b, f, path := moveArtifactFixture(t)
			f.partial = true
			ctx := context.Background()
			m, err := openBackupArtifacts(path, b.Job.Binding.Scope.Cluster, b.Job.Binding.Source.Key, f, moveArtifactFake{f})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Close() }()
			if _, err = m.StepMove(ctx, b.Job, b.Reader, false); err == nil {
				t.Fatal("partial archive published")
			}
			row, err := m.journal.Read(moveArtifactKey(b))
			if err != nil || row.Checkpoint == nil || row.State.Pending == nil {
				t.Fatal("original unknown/checkpoint lost", err)
			}
			original := filepath.Join(path, moveArtifactName(b))
			held := original + "-held"
			if replace {
				if err = os.Rename(original, held); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(original, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err = m.Close(); err != nil {
				t.Fatal(err)
			}
			m, err = openBackupArtifacts(path, b.Job.Binding.Scope.Cluster, b.Job.Binding.Source.Key, f, moveArtifactFake{f})
			if err != nil {
				t.Fatal(err)
			}
			f.partial = false
			if _, err = m.StepMove(ctx, b.Job, b.Reader, false); err == nil || f.exports != 1 {
				t.Fatal("unknown became fresh copy", err)
			}
			if replace {
				if _, err = m.StepMove(ctx, b.Job, b.Reader, true); err == nil {
					t.Fatal("replacement inode adopted for cleanup")
				}
				if err = os.Remove(original); err != nil {
					t.Fatal(err)
				}
				if err = os.Rename(held, original); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = m.StepMove(ctx, b.Job, b.Reader, true); err != nil {
				t.Fatal("original partial cleanup", err)
			}
		})
	}
}
func TestMoveArtifactSyncFailureNeverPublishesOrRecopies(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	b, f, path := moveArtifactFixture(t)
	ctx := context.Background()
	m, err := openBackupArtifacts(path, b.Job.Binding.Scope.Cluster, b.Job.Binding.Source.Key, f, moveArtifactFake{f})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	m.syncFile = func(file *os.File) error {
		if filepath.Base(file.Name()) == "archive.tar" {
			return errors.New("original file sync failed")
		}
		return file.Sync()
	}
	if _, err = m.StepMove(ctx, b.Job, b.Reader, false); err == nil {
		t.Fatal("failed sync published receipt")
	}
	m.syncFile = (*os.File).Sync
	if _, err = m.StepMove(ctx, b.Job, b.Reader, false); err == nil || f.exports != 1 {
		t.Fatal("missing receipt triggered recopy", err)
	}
	if _, err = m.StepMove(ctx, b.Job, b.Reader, true); err != nil {
		t.Fatal(err)
	}
}

func TestMoveArtifactUncertainStreamPreservesOriginalReferenceUntilExplicitCleanup(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	b, f, path := moveArtifactFixture(t)
	ctx := context.Background()
	open := func() *backupArtifacts {
		t.Helper()
		m, err := openBackupArtifacts(path, b.Job.Binding.Scope.Cluster, b.Job.Binding.Source.Key, f, moveArtifactFake{f})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := open()
	defer func() { _ = m.Close() }()
	complete, err := m.StepMove(ctx, b.Job, b.Reader, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.withMoveFile(ctx, b, complete.Receipt, func(in io.ReadSeeker) error {
		if m.mu.TryLock() {
			m.mu.Unlock()
			t.Fatal("file worker lost its exclusive join barrier")
		}
		return errors.New("receiver ACK outcome unknown")
	}); err == nil {
		t.Fatal("uncertain receiver counted as positive closure")
	}
	row, err := m.journal.Read(moveArtifactKey(b))
	if err != nil || len(row.Consumers) != 1 || row.Consumers[moveStreamConsumer(b)].Token == 0 {
		t.Fatal("original stream reference lost", err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m = open()
	if _, err = m.StepMove(ctx, b.Job, b.Reader, true); err != nil {
		t.Fatal("joined original worker cleanup", err)
	}
	row, err = m.journal.Read(moveArtifactKey(b))
	if err != nil || len(row.Consumers) != 0 || row.State.Applied.Present || f.exports != 1 {
		t.Fatal("cleanup lost exact reference/copied source", err)
	}
}

func TestMoveArtifactClosureRequiresOriginalTerminalJournalAndSyncedAbsence(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	b, f, path := moveArtifactFixture(t)
	ctx := context.Background()
	open := func() *backupArtifacts {
		t.Helper()
		m, err := openBackupArtifacts(path, b.Job.Binding.Scope.Cluster, b.Job.Binding.Source.Key, f, moveArtifactFake{f})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := open()
	defer func() { _ = m.Close() }()
	if err := m.moveSourceClosed(ctx, b); err == nil {
		t.Fatal("missing history was treated as original worker closure")
	}
	if _, err := m.StepMove(ctx, b.Job, b.Reader, false); err != nil {
		t.Fatal(err)
	}
	if err := m.moveSourceClosed(ctx, b); err == nil {
		t.Fatal("live artifact was treated as closed")
	}
	if _, err := m.StepMove(ctx, b.Job, b.Reader, true); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m = open()
	if err := m.moveSourceClosed(ctx, b); err != nil || f.exports != 1 {
		t.Fatal("original terminal journal did not survive restart", err)
	}
	other := b
	other.Reader.Lease.Token++
	if err := m.moveSourceClosed(ctx, other); err == nil {
		t.Fatal("different original consumer borrowed closure")
	}
	if err := m.root.Mkdir(moveArtifactName(b), 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.moveSourceClosed(ctx, b); err == nil {
		t.Fatal("reappeared artifact directory counted as gone")
	}
	if err := m.root.Remove(moveArtifactName(b)); err != nil {
		t.Fatal(err)
	}
	syncFile := m.syncFile
	injected := errors.New("source directory sync failed")
	m.syncFile = func(*os.File) error { return injected }
	if err := m.moveSourceClosed(ctx, b); !errors.Is(err, injected) {
		t.Fatal("unsynced absence was published", err)
	}
	m.syncFile = syncFile
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := m.moveSourceClosed(cancelled, b); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled observation published closure", err)
	}
	if err := m.moveSourceClosed(ctx, b); err != nil {
		t.Fatal("exact original cleanup could not be confirmed", err)
	}
}
