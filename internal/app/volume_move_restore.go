// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func moveRestoreKey(b moveReceiveIntent) string {
	d := b.Job.Digest()
	return "move/" + hex.EncodeToString(d[:])
}

func (r *Runtime) moveRestoreBinding(key string, resource reconcile.Resource) (moveReceiveIntent, error) {
	b, err := schema.Decode[moveReceiveIntent]([]byte(resource.Spec))
	if err != nil || key != moveRestoreKey(b) || r.backupArtifacts == nil {
		return b, errBackupArtifact
	}
	return r.backupArtifacts.receiveBinding(moveReceiveKey(b), resource)
}
func (r *Runtime) moveRestoreTarget(ctx context.Context, b moveReceiveIntent) (volumes.NativeReady, error) {
	// Existing native create/Ready consumes only this exact target recipe and
	// original A2 ID. A dispatched absent Create remains Unknown.
	return r.restoreTarget(ctx, control.VolumeRestoreBinding{Target: b.Job.Target, Consumer: b.Job.StagingConsumer()})
}
func (r *Runtime) moveRestoreAuthority(b moveReceiveIntent) volumes.ColdAuthority {
	return func(ctx context.Context, ready volumes.NativeReady, consumer volumes.Consumer) error {
		if ready.Spec != b.Job.Target || ready.Generation != 1 || ready.Owner != b.Job.Binding.Target || consumer != b.Job.StagingConsumer() {
			return sfcp.ErrAdmission
		}
		return (runtimeMoveReceiver{r}).Authorize(ctx, b, false)
	}
}
func (r *Runtime) verifyMoveRestore(ctx context.Context, b moveReceiveIntent) error {
	if err := (runtimeMoveReceiver{r}).Authorize(ctx, b, false); err != nil {
		return err
	}
	ready, err := r.moveRestoreTarget(ctx, b)
	if err != nil {
		return err
	}
	consumer := b.Job.StagingConsumer()
	if err = r.nativeVolumes.CloseRestoreCold(ctx, ready, consumer, b.Job.Options()); err != nil {
		return err
	}
	if err = r.nativeVolumes.VerifyRestoreCold(ctx, ready, consumer, r.moveRestoreAuthority(b), b.Manifest.ArchiveReceipt(), b.Job.Options()); err != nil {
		return err
	}
	return r.backupArtifacts.returnReceivedMoveFile(b)
}

type volumeMoveRestoreDriver struct{ r *Runtime }

func (d volumeMoveRestoreDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	b, err := d.r.moveRestoreBinding(key, op.Target)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind == reconcile.Remove {
		err = d.r.cancelMoveRestore(ctx, b)
		if err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	err = d.r.backupArtifacts.withReceivedMoveFile(ctx, b, runtimeMoveReceiver{d.r}, func(file *os.File) error {
		if _, err := d.r.nativeVolumes.Desired(b.Job.Target, 1, 1, 1); err != nil {
			return err
		}
		if err := d.r.nativeVolumes.Step(ctx, volumes.NativeKey(b.Job.Target)); err != nil {
			return err
		}
		ready, err := d.r.moveRestoreTarget(ctx, b)
		if err != nil {
			return err
		}
		return d.r.nativeVolumes.RestoreCold(ctx, ready, b.Job.StagingConsumer(), d.r.moveRestoreAuthority(b), file, b.Manifest.ArchiveReceipt(), b.Job.Options())
	})
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	return d.Recover(ctx, key, op)
}
func (d volumeMoveRestoreDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	b, err := d.r.moveRestoreBinding(key, op.Target)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind == reconcile.Remove {
		err = d.r.cancelMoveRestore(ctx, b)
		if err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if err = d.r.verifyMoveRestore(ctx, b); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}
func (d volumeMoveRestoreDriver) Retire(ctx context.Context, key string, op reconcile.Operation, _ []byte, _ func([]byte) error) (bool, error) {
	b, err := d.r.moveRestoreBinding(key, op.Target)
	if err != nil {
		return false, err
	}
	err = d.r.cancelMoveRestore(ctx, b)
	return err == nil, err
}

func (r *Runtime) cancelMoveRestore(ctx context.Context, b moveReceiveIntent) error {
	if err := (runtimeMoveReceiver{r}).Authorize(ctx, b, true); err != nil {
		return err
	}
	key := volumes.NativeKey(b.Job.Target)
	row, err := r.nativeVolumes.View(key)
	if errors.Is(err, storage.ErrMissing) {
		gone, e := r.nativeVolumes.UnrecordedAbsent(ctx, b.Job.Target, 1)
		if e != nil || !gone {
			return errors.Join(reconcile.ErrPending, e)
		}
	} else if err != nil {
		return err
	} else {
		raw, _ := json.Marshal(b.Job.Target)
		expected := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
		resources := []reconcile.Resource{row.State.Applied, row.State.Desired.Resource}
		if row.State.Pending != nil {
			resources = append(resources, row.State.Pending.Target)
		}
		for _, resource := range resources {
			if resource.Present && resource != expected {
				return sfcp.ErrAdmission
			}
		}
		if row.State.Pending == nil && row.State.Applied.Present && row.State.Desired.Present {
			ready, e := r.moveRestoreTarget(ctx, b)
			if e != nil {
				return e
			}
			if e = r.nativeVolumes.CloseRestoreCold(ctx, ready, b.Job.StagingConsumer(), b.Job.Options()); e != nil {
				return e
			}
		}
		if err = r.nativeVolumes.DeleteDesired(key, 2, 1); err != nil {
			return err
		}
		for i := 0; i < 2; i++ {
			if err = r.nativeVolumes.Step(ctx, key); err != nil {
				return err
			}
			gone, e := r.nativeVolumes.Gone(ctx, key, 2, 1)
			if e != nil {
				return e
			}
			if gone {
				break
			}
			if i == 1 {
				return reconcile.ErrPending
			}
		}
	}
	// The exclusive restore A2 worker is joined before the original file pin
	// is returned. Missing receive intent means no file could be borrowed.
	if err = r.backupArtifacts.returnReceivedMoveFile(b); err != nil && !errors.Is(err, storage.ErrMissing) {
		return err
	}
	return (runtimeMoveReceiver{r}).Authorize(ctx, b, true)
}

func (r *Runtime) stepMoveRestore(ctx context.Context, b moveReceiveIntent, cleanup bool) error {
	r.volumeMoveTargetMu.Lock()
	defer r.volumeMoveTargetMu.Unlock()
	return r.stepMoveRestoreLocked(ctx, b, cleanup)
}

func (r *Runtime) stepMoveRestoreLocked(ctx context.Context, b moveReceiveIntent, cleanup bool) error {
	if r.nativeVolumes == nil || r.volumeRestores == nil {
		return reconcile.ErrPending
	}
	if err := (runtimeMoveReceiver{r}).Authorize(ctx, b, cleanup); err != nil {
		return err
	}
	key := moveRestoreKey(b)
	raw, _ := json.Marshal(b)
	resource := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	row, err := r.volumeRestores.Read(key)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return err
	}
	if !cleanup || errors.Is(err, storage.ErrMissing) {
		if err = r.volumeRestores.Desired(key, reconcile.Desired{Revision: 1, Resource: resource}, 1); err != nil {
			return err
		}
	}
	if cleanup {
		if err = r.volumeRestores.Desired(key, reconcile.Desired{Revision: 2, Retiring: 1}, 1); err != nil {
			return err
		}
	}
	alreadyApplied := row.State.Pending == nil && row.State.Applied == resource
	if err = r.volumeRestores.Step(ctx, key, volumeMoveRestoreDriver{r}); err != nil {
		return err
	}
	row, err = r.volumeRestores.Read(key)
	if err != nil || row.State.Pending != nil {
		return errors.Join(reconcile.ErrPending, err)
	}
	if cleanup {
		if row.State.Applied.Present {
			return reconcile.ErrPending
		}
		return r.cancelMoveRestore(ctx, b)
	}
	if !row.State.Applied.Present {
		return reconcile.ErrPending
	}
	if alreadyApplied {
		if err = r.verifyMoveRestore(ctx, b); err != nil {
			return err
		}
	}
	permit, err := r.volumeMovePermit(ctx, b.Job, "receive")
	if err != nil {
		return err
	}
	ready, err := r.moveRestoreTarget(ctx, b)
	if err != nil {
		return err
	}
	proof := volumes.CopyProof{Binding: b.Job.Binding, Artifact: b.Manifest.Artifact, Bytes: b.Manifest.Bytes, DigestVerified: true, Synced: true, NoWriters: true}
	proof.Signature = ed25519.Sign(r.Identity.Private, volumes.CopyBytes(proof))
	return r.commitVolumeMoveReport(ctx, control.VolumeMoveReport{Operation: "move", Schema: 1, Selection: b.Job.Selection(), Binding: b.Job.Digest(), Epoch: permit.Epoch, RootRevision: permit.RootRevision, Revision: permit.Revision, At: time.Now().Unix(), Kind: "copied", Copy: &proof, Target: &ready, ArtifactReturned: true})
}
