// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/moby/moby/client"
)

func TestRealBoundaryColdVolumeArchiveAndInactiveRestore(t *testing.T) {
	testRealColdVolumeArchive(t, false)
}
func TestRealBoundaryColdRestoreOriginalReadOnlyRecovery(t *testing.T) {
	testRealColdVolumeArchive(t, true)
}
func testRealColdVolumeArchive(t *testing.T, recovery bool) {
	ctx, engine, spec := realNativeVolume(t)
	db := filepath.Join(t.TempDir(), "native.db")
	m, err := OpenNative(db, engine)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if m != nil {
			_ = m.Close()
		}
	}()
	prepare := func(s NativeSpec) NativeReady {
		t.Helper()
		key, err := m.Desired(s, 1, 1, 4)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.Step(ctx, key); err != nil {
			t.Fatal(err)
		}
		ready, err := m.Ready(ctx, key, makeFixture(t).a)
		if err != nil {
			t.Fatal(err)
		}
		return ready
	}
	source := prepare(spec)
	sourceDisk, err := engine.API.VolumeInspect(ctx, source.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("cold original volume data\n")
	originalFile := filepath.Join(sourceDisk.Volume.Mountpoint, "row")
	if err = os.WriteFile(originalFile, data, 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(originalFile, int(spec.UID), int(spec.GID)); err != nil {
		t.Fatal(err)
	}
	catalog := makeFixture(t).c
	sourceCore, err := New(catalog, "admin", spec.Scope, source.Owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	sourceCore, reader, err := sourceCore.Acquire(catalog, "admin", sourceCore.Revision(), "backup", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = sourceCore.Acquire(catalog, "admin", sourceCore.Revision(), "writer", 1, true); err == nil {
		t.Fatal("writer overlapped cold reader")
	}
	authorizeSource := func(_ context.Context, ready NativeReady, c Consumer) error {
		if ready.Owner != source.Owner || ready.Spec != source.Spec || c.Writable || catalog.Authorize("admin", spec.Scope.Tenant, access.ManageVolumes, "node-a") != nil {
			return ErrVolume
		}
		return sourceCore.CheckActivation(c)
	}
	o := ArchiveOptions{MaxBytes: 128 << 10, MaxEntries: 16, MaxDepth: 8, UID: spec.UID, GID: spec.GID, RootMode: spec.Mode}
	artifact, err := os.OpenFile(filepath.Join(t.TempDir(), "backup.tar"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	receipt, err := m.ExportCold(ctx, source, reader, authorizeSource, artifact, o)
	if err != nil || receipt.DataBytes != uint64(len(data)) || receipt.Entries != 2 {
		t.Fatal("actual source archive", receipt, err)
	}
	// Source data/identity survive; a target is a fresh inactive materialization.
	targetSpec := spec
	targetSpec.Scope.ID = "restored"
	targetSpec.Materialization = "restore"
	target := prepare(targetSpec)
	targetCore, err := New(catalog, "admin", targetSpec.Scope, target.Owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	targetCore, writer, err := targetCore.Acquire(catalog, "admin", targetCore.Revision(), "restore", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	authorizeTarget := func(_ context.Context, ready NativeReady, c Consumer) error {
		if ready.Owner != target.Owner || !c.Writable {
			return ErrVolume
		}
		return targetCore.CheckActivation(c)
	}
	if err = m.RestoreCold(ctx, target, writer, authorizeTarget, artifact, receipt, o); err != nil {
		t.Fatal("actual inactive restore", err)
	}
	targetDisk, err := engine.API.VolumeInspect(ctx, target.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(targetDisk.Volume.Mountpoint, "row"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("restored original bytes", err)
	}
	originalInfo, e := os.Stat(originalFile)
	if e != nil {
		t.Fatal(e)
	}
	restoredInfo, e := os.Stat(filepath.Join(targetDisk.Volume.Mountpoint, "row"))
	if e != nil {
		t.Fatal(e)
	}
	restoredStat, ok := restoredInfo.Sys().(*syscall.Stat_t)
	if !ok || restoredStat.Uid != spec.UID || restoredStat.Gid != spec.GID || restoredInfo.Mode().Perm() != 0640 || !restoredInfo.ModTime().Equal(originalInfo.ModTime()) {
		t.Fatal("restored native metadata")
	}

	got, err = os.ReadFile(originalFile)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("source changed", err)
	}
	if err = m.RestoreCold(ctx, target, writer, authorizeTarget, artifact, receipt, o); err == nil {
		t.Fatal("nonempty restored target overwritten")
	}
	if recovery {
		// Persist the exact original local target pin, then reopen the native
		// DB as after process interruption. Verification must consume that
		// original token and read the same target without reapplying Restore.
		if _, err = m.journal.Borrow(NativeKey(target.Spec), coldPinName(writer), target.Generation); err != nil {
			t.Fatal(err)
		}
		if err = m.Close(); err != nil {
			t.Fatal(err)
		}
		m, err = OpenNative(db, engine)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.VerifyRestoreCold(ctx, target, writer, authorizeTarget, receipt, o); err != nil {
			t.Fatal("original readonly recovery", err)
		}
		row, err := m.View(NativeKey(target.Spec))
		if err != nil || row.State.LastID != 1 || row.State.Pending != nil || len(row.Consumers) != 0 {
			t.Fatal("lost original native identity/pin", err)
		}
		foreign, err := m.journal.Borrow(NativeKey(target.Spec), "foreign", target.Generation)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.VerifyRestoreCold(ctx, target, writer, authorizeTarget, receipt, o); err == nil {
			t.Fatal("foreign native consumer accepted")
		}
		if err = m.journal.Return(NativeKey(target.Spec), "foreign", foreign); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(targetDisk.Volume.Mountpoint, "row"), []byte("partial original target"), 0640); err != nil {
			t.Fatal(err)
		}
		if err = m.VerifyRestoreCold(ctx, target, writer, authorizeTarget, receipt, o); err == nil {
			t.Fatal("partial target falsely verified")
		}
		if _, err = m.journal.Borrow(NativeKey(target.Spec), coldPinName(writer), target.Generation); err != nil {
			t.Fatal(err)
		}
		if err = m.CheckColdReleased(target, writer); err == nil {
			t.Fatal("unreturned original staging pin reported closed")
		}
		if err = m.CloseRestoreCold(ctx, target, writer, o); err != nil {
			t.Fatal("original inactive writer close", err)
		}
		if err = m.CheckColdReleased(target, writer); err != nil {
			t.Fatal("exact original staging pin closure", err)
		}
		got, err = os.ReadFile(filepath.Join(targetDisk.Volume.Mountpoint, "row"))
		if err != nil || string(got) != "partial original target" {
			t.Fatal("recovery overwrote original partial data", err)
		}
		// An empty target after an interrupted dispatch is still not fresh
		// permission to write when its original native token remains held.
		if err = os.Remove(filepath.Join(targetDisk.Volume.Mountpoint, "row")); err != nil {
			t.Fatal(err)
		}
		if _, err = m.journal.Borrow(NativeKey(target.Spec), coldPinName(writer), target.Generation); err != nil {
			t.Fatal(err)
		}
		if err = m.RestoreCold(ctx, target, writer, authorizeTarget, artifact, receipt, o); err == nil {
			t.Fatal("retained original token allowed a fresh restore write")
		}
		if _, err = os.Stat(filepath.Join(targetDisk.Volume.Mountpoint, "row")); !os.IsNotExist(err) {
			t.Fatal("empty interrupted target was recopied", err)
		}
		if err = m.CloseRestoreCold(ctx, target, writer, o); err != nil {
			t.Fatal(err)
		}
		t.Log("same native DB/materialization + retained original writable cold token -> read-only exact archive verification/no Restore replay -> foreign consumer refusal -> partial mismatch preserved -> exact writer-token close without data removal")
	} else {
		// A completed file is still unpublished when the final authority check fails.
		rejected, err := os.OpenFile(filepath.Join(t.TempDir(), "unpublished.tar"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer rejected.Close()
		calls := 0
		rejectFinal := func(ctx context.Context, ready NativeReady, c Consumer) error {
			calls++
			if calls == 2 {
				return access.ErrDenied
			}
			return authorizeSource(ctx, ready, c)
		}
		if r, e := m.ExportCold(ctx, source, reader, rejectFinal, rejected, o); !errors.Is(e, access.ErrDenied) || r != (ArchiveReceipt{}) {
			t.Fatal("late revoked archive published", r, e)
		}
	}
	for _, ready := range []NativeReady{source, target} {
		r, e := m.View(NativeKey(ready.Spec))
		if e != nil || len(r.Consumers) != 0 || r.State.Pending != nil || r.State.LastID != 1 {
			t.Fatal("native reader/writer references not closed", e)
		}
	}
	release := func(core State, c Consumer) State {
		t.Helper()
		proof := Gone{Scope: core.Scope(), Consumer: c, Stopped: true, MountsGone: true}
		proof.Signature = ed25519.Sign(makeFixture(t).a, GoneBytes(proof))
		next, e := core.Release(proof)
		if e != nil {
			t.Fatal(e)
		}
		return next
	}
	sourceCore = release(sourceCore, reader)
	targetCore = release(targetCore, writer)
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m = nil
	m, err = OpenNative(db, engine)
	if err != nil {
		t.Fatal(err)
	}
	for _, ready := range []NativeReady{source, target} {
		owner, scope, e := m.Owner(ctx, NativeKey(ready.Spec))
		if e != nil || owner != ready.Owner || scope != ready.Spec.Scope {
			t.Fatal("same native ID/root", e)
		}
		if err = m.DeleteDesired(NativeKey(ready.Spec), 2, 1); err != nil {
			t.Fatal(err)
		}
		if err = m.Step(ctx, NativeKey(ready.Spec)); err != nil {
			t.Fatal(err)
		}
		if gone, e := m.Gone(ctx, NativeKey(ready.Spec), 2, 1); e != nil || !gone {
			t.Fatal("original explicit native delete", e)
		}
	}
	if len(sourceCore.Consumers()) != 0 || len(targetCore.Consumers()) != 0 {
		t.Fatal("original product-core references remain")
	}
	if !recovery {
		t.Log("actual owned local Volume -> private synced archive -> separate empty inactive Volume; original data and native identity retained; exact mode/uid/gid/mtime profile, source cold reader blocks writer, exclusive target writer, original A3 pins closed, late authority refusal returns no receipt, no overwrite, same native DB and explicit nonforce source/stage deletion/Gone. Authority callback uses the existing pure product core, not a real Raft boundary; no SQL consistency/shared backup operation/CLI or full D2.04 claim.")
	}
}
