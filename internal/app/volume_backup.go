// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Compatibility pins the exact original public writer recipe, including its
// immutable image/process and mount inputs. A restore must separately validate
// that recipe/platform/keyring and prove database recovery before activation.
func backupCompatibility(source volumes.ColdSource) [32]byte {
	return sha256.Sum256(append([]byte("sfc-volume-cold-recipe-1\x00"), []byte(source.Writer.Task.Spec)...))
}
func backupSourceMatches(source volumes.ColdSource, b control.VolumeBackupBinding) bool {
	r := source.Writer
	id, err := hex.DecodeString(source.NativeID)
	if r.Validate() != nil || r.Scope != b.Scope || !r.Consumer.Writable || r.Consumer.Owner != b.Source.Owner || r.NativeKey != volumes.NativeKey(b.Source.Spec) || r.NativeGeneration != b.Source.Generation || !source.Exit.Clean() || err != nil || len(id) != 32 || hex.EncodeToString(id) != source.NativeID || backupCompatibility(source) != b.Compatibility {
		return false
	}
	s, err := workload.DecodeContainer(r.Task.Spec)
	if err != nil || s.Process == nil || s.Node != engine.Owner(b.Scope.Cluster, b.Source.Owner.Key) {
		return false
	}
	count := 0
	for _, mount := range s.Volumes {
		if mount.Scope == b.Scope {
			if mount.Consumer != r.Consumer || mount.NativeKey != r.NativeKey || mount.NativeGeneration != r.NativeGeneration {
				return false
			}
			count++
		}
	}
	return count == 1
}

type runtimeBackupBackend struct{ r *Runtime }

func (d runtimeBackupBackend) Authorize(ctx context.Context, b control.VolumeBackupBinding, cleanup bool) error {
	body, _ := json.Marshal(control.VolumeBackupPermitRequest{Selection: control.VolumeBackupSelection{Scope: b.Scope, ID: b.ID}, Cleanup: cleanup})
	reply, err := d.r.appCall(ctx, "volume-backup-permit", body)
	if err != nil {
		return err
	}
	job, err := schema.Decode[control.VolumeBackup](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || job.Binding.Digest() != b.Digest() {
		return sfcp.ErrAdmission
	}
	return nil
}
func (d runtimeBackupBackend) Source(ctx context.Context, b control.VolumeBackupBinding) (volumes.ColdSource, error) {
	source, err := d.r.activations.ColdSource(ctx, b.Source)
	if err != nil || !backupSourceMatches(source, b) {
		return volumes.ColdSource{}, errors.Join(errBackupArtifact, err)
	}
	return source, nil
}
func (d runtimeBackupBackend) Export(ctx context.Context, b control.VolumeBackupBinding, out *os.File) (volumes.ArchiveReceipt, error) {
	return d.r.nativeVolumes.ExportCold(ctx, b.Source, b.Consumer, func(ctx context.Context, ready volumes.NativeReady, c volumes.Consumer) error {
		if ready.Owner != b.Source.Owner || c != b.Consumer {
			return sfcp.ErrAdmission
		}
		return d.Authorize(ctx, b, false)
	}, out, b.Options())
}
func (d runtimeBackupBackend) CloseReader(ctx context.Context, b control.VolumeBackupBinding) error {
	return d.r.nativeVolumes.CloseCold(ctx, b.Source, b.Consumer, b.Options())
}

func (r *Runtime) volumeBackupLoop() {
	for {
		changed := r.Engine().Changes()
		view, err := r.Engine().Read(r.ctx, false)
		if err == nil {
			err = r.reconcileVolumeWork(r.ctx, view)
		}
		r.mu.Lock()
		r.volumeBackupError = err
		r.mu.Unlock()
		// A pass can publish its own facts while the old subscription closes.
		// Reuse the existing post-pass coalescing rule; neither that notice nor
		// an elapsed ticker should immediately repeat this complete scan.
		if !waitModulePass(r.ctx, changed, true, 2*time.Second) {
			return
		}
	}
}

// Every consumer below already used this exact immutable view. Decode it once
// per pass; effects and reports still obtain their own current permits.
func (r *Runtime) reconcileVolumeWork(ctx context.Context, view cluster.View) error {
	registry, err := r.controlPolicy.Volumes(view.State)
	if err != nil {
		return err
	}
	return errors.Join(r.reconcileVolumeArchives(ctx, view, registry), r.reconcileVolumeBackups(ctx, registry), r.reconcileVolumeRestores(ctx, registry), r.reconcileVolumeDeletions(ctx, registry), r.reconcileVolumeCreations(ctx, registry), r.reconcileVolumeMoveSources(ctx, view, registry), r.reconcileVolumeMoveTargetsInView(ctx, view, registry))
}

func (r *Runtime) reconcileVolumeBackups(ctx context.Context, registry control.Volumes) error {
	var failed error
	for _, job := range registry.Backups() {
		if job.Binding.Source.Owner.Key != r.Identity.Public || job.Phase != "Reserved" && job.Phase != "Cancelling" && job.Phase != "Deleting" {
			continue
		}
		completion, err := r.backupArtifacts.Step(ctx, job)
		if err == nil {
			err = r.publishVolumeBackup(ctx, job, completion)
		}
		failed = errors.Join(failed, err)
		if ctx.Err() != nil {
			break
		}
	}
	return failed
}

func (r *Runtime) publishVolumeBackup(ctx context.Context, job control.VolumeBackup, completion *backupArtifactCompletion) error {
	// A local follower may lag the permit's quorum view. A stale report is a
	// normal CAS rejection; the next observed view retries facts, never copy.
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	registry, err := r.controlPolicy.Volumes(v.State)
	if err != nil {
		return err
	}
	current, ok := registry.Backup(job.Binding.Scope, job.Binding.ID)
	if !ok || current.Binding.Digest() != job.Binding.Digest() || current.Revision != job.Revision {
		return reconcile.ErrPending
	}
	report := control.VolumeBackupReport{Schema: 1, Scope: job.Binding.Scope, ID: job.Binding.ID, Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.VolumesKey).Revision, Revision: job.Revision, At: time.Now().Unix(), Binding: job.Binding.Digest(), DirectorySynced: true}
	if job.Phase == "Deleting" {
		report.Kind = "gone"
		report.ArtifactGone = true
	} else {
		closed := volumes.Gone{Scope: job.Binding.Scope, Consumer: job.Binding.Consumer, Stopped: true, MountsGone: true}
		closed.Signature = ed25519.Sign(r.Identity.Private, volumes.GoneBytes(closed))
		report.Closed = &closed
		if completion != nil {
			report.Kind = "ready"
			report.CleanShutdown, report.Compatible = true, true
			report.Receipt = completion.Receipt
		} else if job.Phase == "Cancelling" {
			report.Kind = "failed"
			report.Failure = "cancelled"
			report.ArtifactGone = true
		} else {
			return errBackupArtifact
		}
	}
	report.Signature = ed25519.Sign(r.Identity.Private, control.VolumeBackupReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "volume-backup-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return errBackupArtifact
	}
	return nil
}
