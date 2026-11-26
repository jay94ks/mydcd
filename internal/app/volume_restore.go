// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func restoreJobKey(b control.VolumeRestoreBinding) string {
	d := b.Digest()
	return "restore/" + hex.EncodeToString(d[:])
}
func restoreJobSelection(b control.VolumeRestoreBinding) control.VolumeRestoreSelection {
	return control.VolumeRestoreSelection{Backup: b.Backup, ID: b.ID}
}
func restoreOptions(b control.VolumeRestoreBinding) volumes.ArchiveOptions {
	return volumes.ArchiveOptions{MaxBytes: b.Receipt.Bytes, MaxEntries: b.Receipt.Entries, MaxDepth: 64, UID: b.Target.UID, GID: b.Target.GID, RootMode: b.Target.Mode}
}
func (r *Runtime) restoreBinding(key string, resource reconcile.Resource) (control.VolumeRestoreBinding, error) {
	b, err := schema.Decode[control.VolumeRestoreBinding]([]byte(resource.Spec))
	if err != nil || !resource.Present || resource.Generation != 1 || b.Schema != 1 || b.Target.Validate() != nil || b.Target.Scope.Cluster != r.controlPolicy.Cluster || b.Target.NodeKey != r.Identity.Public || b.Origin.VerifyOriginal(r.controlPolicy.Cluster) != nil || restoreJobKey(b) != key {
		return b, errBackupArtifact
	}
	return b, nil
}
func (r *Runtime) validateRestoreJournal() error {
	keys := r.volumeRestores.Keys()
	if len(keys) > 256 {
		return errBackupArtifact
	}
	for _, key := range keys {
		row, err := r.volumeRestores.Read(key)
		if err != nil {
			return err
		}
		resources := []reconcile.Resource{row.State.Desired.Resource, row.State.Applied}
		if row.State.Pending != nil {
			resources = append(resources, row.State.Pending.Target)
		}
		for _, resource := range resources {
			if resource.Present {
				if strings.HasPrefix(key, "move/") {
					_, err = r.moveRestoreBinding(key, resource)
				} else {
					_, err = r.restoreBinding(key, resource)
				}
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func (r *Runtime) restorePermit(ctx context.Context, b control.VolumeRestoreBinding, cleanup bool) error {
	raw, _ := json.Marshal(control.VolumeRestorePermitRequest{Selection: restoreJobSelection(b), Cleanup: cleanup})
	reply, err := r.appCall(ctx, "volume-restore-permit", raw)
	if err != nil {
		return err
	}
	j, err := schema.Decode[control.VolumeRestore](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || j.Binding.Digest() != b.Digest() {
		return mydcp.ErrAdmission
	}
	return nil
}
func (r *Runtime) restoreTarget(ctx context.Context, b control.VolumeRestoreBinding) (volumes.NativeReady, error) {
	key := volumes.NativeKey(b.Target)
	row, err := r.nativeVolumes.View(key)
	if err != nil {
		return volumes.NativeReady{}, err
	}
	for _, resource := range []reconcile.Resource{row.State.Desired.Resource, row.State.Applied} {
		if resource.Present {
			raw, _ := json.Marshal(b.Target)
			if resource.Generation != 1 || resource.Spec != string(raw) {
				return volumes.NativeReady{}, errBackupArtifact
			}
		}
	}
	if row.State.Pending != nil || !row.State.Applied.Present {
		// Native A2 recovers its SAME create ID; a dispatched absent create is
		// Unknown. No new spec/generation or SDK retry replaces it here.
		if err = r.nativeVolumes.Step(ctx, key); err != nil {
			return volumes.NativeReady{}, err
		}
	}
	ready, err := r.nativeVolumes.Ready(ctx, key, r.Identity.Private)
	if err != nil || ready.Spec != b.Target || ready.Generation != 1 || ready.Owner != b.Consumer.Owner {
		return volumes.NativeReady{}, errors.Join(errBackupArtifact, err)
	}
	return ready, nil
}
func (r *Runtime) restoreAuthority(b control.VolumeRestoreBinding) volumes.ColdAuthority {
	return func(ctx context.Context, ready volumes.NativeReady, c volumes.Consumer) error {
		if ready.Spec != b.Target || ready.Generation != 1 || c != b.Consumer {
			return mydcp.ErrAdmission
		}
		return r.restorePermit(ctx, b, false)
	}
}
func (r *Runtime) verifyOriginalRestore(ctx context.Context, b control.VolumeRestoreBinding) error {
	if err := r.restorePermit(ctx, b, false); err != nil {
		return err
	}
	ready, err := r.restoreTarget(ctx, b)
	if err != nil {
		return err
	}
	if err = r.nativeVolumes.CloseRestoreCold(ctx, ready, b.Consumer, restoreOptions(b)); err != nil {
		return err
	}
	if err = r.nativeVolumes.VerifyRestoreCold(ctx, ready, b.Consumer, r.restoreAuthority(b), b.Receipt, restoreOptions(b)); err != nil {
		return err
	}
	return r.backupArtifacts.returnRestoreArtifact(b)
}

type volumeRestoreDriver struct{ r *Runtime }

func (d volumeRestoreDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	b, err := d.r.restoreBinding(key, op.Target)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind == reconcile.Remove {
		if err = d.r.cancelOriginalRestore(ctx, b); err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if err = d.r.restorePermit(ctx, b, false); err != nil {
		return reconcile.EffectUnknown, err
	}
	err = d.r.backupArtifacts.withRestoreFile(ctx, b, func(file *os.File) error {
		if _, e := d.r.nativeVolumes.Desired(b.Target, 1, 1, 1); e != nil {
			return e
		}
		if e := d.r.nativeVolumes.Step(ctx, volumes.NativeKey(b.Target)); e != nil {
			return e
		}
		ready, e := d.r.restoreTarget(ctx, b)
		if e != nil {
			return e
		}
		return d.r.nativeVolumes.RestoreCold(ctx, ready, b.Consumer, d.r.restoreAuthority(b), file, b.Receipt, restoreOptions(b))
	})
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	return d.Recover(ctx, key, op)
}
func (d volumeRestoreDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	b, err := d.r.restoreBinding(key, op.Target)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind == reconcile.Remove {
		if err = d.r.cancelOriginalRestore(ctx, b); err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errBackupArtifact
	}
	if err = d.r.verifyOriginalRestore(ctx, b); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}
func (d volumeRestoreDriver) Retire(ctx context.Context, key string, op reconcile.Operation, _ []byte, _ func([]byte) error) (bool, error) {
	b, err := d.r.restoreBinding(key, op.Target)
	if err != nil {
		return false, err
	}
	if err = d.r.cancelOriginalRestore(ctx, b); err != nil {
		return false, err
	}
	return true, nil
}

func (r *Runtime) cancelOriginalRestore(ctx context.Context, b control.VolumeRestoreBinding) error {
	if err := r.restorePermit(ctx, b, true); err != nil {
		return err
	}
	key := volumes.NativeKey(b.Target)
	row, err := r.nativeVolumes.View(key)
	if errors.Is(err, storage.ErrMissing) {
		// The local worker is serialized/stopped. Without a synced native
		// intent this implementation could not have dispatched SDK Create.
		gone, e := r.docker.Gone(ctx, "volume", key)
		if e != nil || !gone {
			return errors.Join(reconcile.ErrPending, e)
		}
	} else if err != nil {
		return err
	} else {
		if row.State.Pending == nil && row.State.Applied.Present && row.State.Desired.Present {
			ready, e := r.restoreTarget(ctx, b)
			if e != nil {
				return e
			}
			if e = r.nativeVolumes.CloseRestoreCold(ctx, ready, b.Consumer, restoreOptions(b)); e != nil {
				return e
			}
		}
		if err = r.nativeVolumes.DeleteDesired(key, 2, 1); err != nil {
			return err
		}
		// One native transition may settle an original Apply; a later call
		// removes that same object. An unresolved dispatch is never reset.
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
	if err = r.backupArtifacts.returnRestoreArtifact(b); err != nil {
		return err
	}
	return r.restorePermit(ctx, b, true)
}

func (r *Runtime) reconcileVolumeRestores(ctx context.Context, registry control.Volumes) error {
	var failed error
	for _, job := range registry.Restores() {
		if job.Binding.Target.NodeKey != r.Identity.Public || job.Phase != "Reserved" && job.Phase != "Cancelling" {
			continue
		}
		if err := r.stepVolumeRestore(ctx, job); err != nil {
			failed = errors.Join(failed, err)
		}
		if ctx.Err() != nil {
			break
		}
	}
	return failed
}
func (r *Runtime) stepVolumeRestore(ctx context.Context, job control.VolumeRestore) error {
	b := job.Binding
	cleanup := job.Phase == "Cancelling"
	if err := r.restorePermit(ctx, b, cleanup); err != nil {
		return err
	}
	key := restoreJobKey(b)
	raw, _ := json.Marshal(b)
	d := reconcile.Desired{Revision: job.Revision, Resource: reconcile.Resource{Generation: 1, Spec: string(raw), Present: true}}
	if cleanup {
		if _, err := r.volumeRestores.Read(key); errors.Is(err, storage.ErrMissing) {
			original := d
			original.Revision = 1
			if err = r.volumeRestores.Desired(key, original, 1); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		d.Resource = reconcile.Resource{}
		d.Retiring = 1
	}
	if err := r.volumeRestores.Desired(key, d, 1); err != nil {
		return err
	}
	before, err := r.volumeRestores.Read(key)
	if err != nil {
		return err
	}
	alreadyApplied := before.State.Pending == nil && before.State.Applied.Present && before.State.Applied == d.Resource
	if err := r.volumeRestores.Step(ctx, key, volumeRestoreDriver{r}); err != nil {
		return err
	}
	row, err := r.volumeRestores.Read(key)
	if err != nil || row.State.Pending != nil {
		return errors.Join(reconcile.ErrPending, err)
	}
	if cleanup {
		if row.State.Applied.Present {
			return reconcile.ErrPending
		}
		// Prepared or never-observed cancellation also positively closes the
		// exact original native path/reference before reporting settlement.
		if err = r.cancelOriginalRestore(ctx, b); err != nil {
			return err
		}
	} else {
		if !row.State.Applied.Present {
			return reconcile.ErrPending
		}
		if alreadyApplied {
			if err = r.verifyOriginalRestore(ctx, b); err != nil {
				return err
			}
		}
	}
	return r.publishVolumeRestore(ctx, job)
}
func (r *Runtime) publishVolumeRestore(ctx context.Context, job control.VolumeRestore) error {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	b := job.Binding
	report := control.VolumeRestoreReport{Operation: "restore", Schema: 1, Selection: restoreJobSelection(b), Binding: b.Digest(), Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.VolumesKey).Revision, Revision: job.Revision, At: time.Now().Unix(), ArtifactReturned: true, Closed: volumes.Gone{Scope: b.Target.Scope, Consumer: b.Consumer, Stopped: true, MountsGone: true}}
	report.Closed.Signature = ed25519.Sign(r.Identity.Private, volumes.GoneBytes(report.Closed))
	if job.Phase == "Cancelling" {
		report.Kind = "cancelled"
		report.TargetGone = true
	} else {
		ready, e := r.restoreTarget(ctx, b)
		if e != nil {
			return e
		}
		report.Kind = "restored"
		report.Target = &ready
		report.FilesSynced, report.CopyVerified = true, true
	}
	report.Signature = ed25519.Sign(r.Identity.Private, control.VolumeRestoreReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "volume-restore-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return errBackupArtifact
	}
	return nil
}
