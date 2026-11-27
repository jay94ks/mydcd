// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
)

type imageBuildReclaimLocal struct {
	Schema              uint8
	Scope               imagebuild.UploadScope
	Version             [32]byte
	Started             bool
	Lease               reconcile.Lease
	Native              [32]byte
	Returning, Returned bool
	Receipt             *imagebuild.ReclaimReceipt `json:",omitempty"`
}

func imageBuildReclaimKey(scope imagebuild.UploadScope) string {
	h := scope.Hash()
	return "image-build/reclaim/" + hex.EncodeToString(h[:])
}
func (r *Runtime) saveImageBuildReclaim(local imageBuildReclaimLocal) error {
	raw, err := json.Marshal(local)
	if err != nil || len(raw) > 16<<10 {
		return imagebuild.ErrStorage
	}
	return r.reports.Write(map[string][]byte{imageBuildReclaimKey(local.Scope): raw})
}
func (r *Runtime) imageBuildArtifactWork(ctx context.Context, u control.ImageBuildUploadRecord) (control.ImageBuildArtifactWork, error) {
	raw, _ := json.Marshal(control.ImageBuildArtifactSelection{Tenant: u.Scope.Tenant, Upload: u.Scope.Upload})
	reply, err := r.appCall(ctx, "image-build-artifact-work", raw)
	if err != nil {
		return control.ImageBuildArtifactWork{}, err
	}
	work, err := schema.Decode[control.ImageBuildArtifactWork](reply.Data)
	if err != nil || work.Schema != 1 || work.Cluster != r.controlPolicy.Cluster || work.Upload.Scope != u.Scope || work.Upload.Scope.Root.Key != r.Identity.Public || work.Root.Reference(work.Cluster) != u.Scope.Root || work.Index == 0 || work.Epoch == 0 {
		return control.ImageBuildArtifactWork{}, sfcp.ErrAdmission
	}
	return work, nil
}
func (r *Runtime) publishImageBuildOwner(ctx context.Context, work control.ImageBuildArtifactWork, report control.ImageBuildOwnerReport) error {
	report.Schema, report.Cluster, report.Owner = 1, r.controlPolicy.Cluster, r.Identity.Public
	report.Tenant, report.Upload = work.Upload.Scope.Tenant, work.Upload.Scope.Upload
	report.Expected, report.RootRevision, report.Epoch = work.Upload.Revision, work.RootRevision, work.Epoch
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.ImageBuildOwnerReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "image-build-owner-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return imagebuild.ErrConflict
	}
	return nil
}
func (r *Runtime) reclaimImageBuild(ctx context.Context, u control.ImageBuildUploadRecord) error {
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.nodeRoots == nil || r.reports == nil {
		return sfcp.ErrAdmission
	}
	r.imageBuildMu.Lock()
	defer r.imageBuildMu.Unlock()
	work, err := r.imageBuildArtifactWork(ctx, u)
	if err != nil {
		return err
	}
	if !work.Reclaim || !work.Upload.Closed || work.Upload.Reclaimed != nil {
		return imagebuild.ErrUsed
	}
	if r.imageBuildTree != nil && r.imageBuildTree.scope == u.Scope.Hash() {
		if err := r.imageBuildTree.Close(); err != nil {
			return err
		}
		r.imageBuildTree = nil
	}
	var local imageBuildReclaimLocal
	raw, err := r.reports.GetBounded(imageBuildReclaimKey(u.Scope), 16<<10)
	if errors.Is(err, storage.ErrMissing) {
		pin, held, err := r.nodeRoots.RecordedPin(u.Scope.Root, buildArtifactConsumer(u.Scope))
		if err != nil {
			return err
		}
		local = imageBuildReclaimLocal{Schema: 1, Scope: u.Scope, Version: work.Upload.Version, Started: held, Lease: pin.Lease}
		if err := r.saveImageBuildReclaim(local); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		local, err = schema.Decode[imageBuildReclaimLocal](raw)
		if err != nil {
			return imagebuild.ErrStorage
		}
	}
	if local.Schema != 1 || local.Scope != u.Scope || local.Version != work.Upload.Version || local.Started && (local.Lease.Generation != u.Scope.Root.Generation || local.Lease.Token == 0) || !local.Started && local.Lease.Token != 0 || local.Returned && !local.Returning || local.Returning && local.Native == ([32]byte{}) || local.Receipt != nil && (!local.Returned || !local.Receipt.Valid(u.Scope, local.Version)) {
		return imagebuild.ErrStorage
	}
	if local.Native == ([32]byte{}) {
		if local.Started {
			pin, err := r.nodeRoots.OpenRecordedPin(u.Scope.Root, buildArtifactConsumer(u.Scope))
			if err != nil || pin.Directory == nil {
				return errors.Join(imagebuild.ErrStorage, err)
			}
			defer pin.Directory.Close()
			if pin.Lease != local.Lease {
				return imagebuild.ErrStorage
			}
			spool, err := imagebuild.OpenSpool(pin.Directory.FD(), u.Scope.Root, r.reports)
			if err != nil {
				return err
			}
			defer spool.Close()
			core := imagebuild.Upload{Scope: u.Scope, Revision: work.Upload.Revision, Closed: true, Version: work.Upload.Version}
			if err := spool.Reclaim(core, false); err != nil {
				return err
			}
			local.Native, err = spool.ReclaimEvidence(u.Scope)
			if err != nil {
				return err
			}
			if err := spool.Close(); err != nil {
				return err
			}
			if err := pin.Directory.Close(); err != nil {
				return err
			}
		} else {
			// Creation is required to hold this exact durable dependency before
			// any filesystem mutation. A healthy original root journal with no
			// such consumer, under the closed shared/gated scope, proves that
			// native staging never began; a missing journal is an error above.
			_, held, err := r.nodeRoots.RecordedPin(u.Scope.Root, buildArtifactConsumer(u.Scope))
			if err != nil || held {
				return errors.Join(imagebuild.ErrStorage, err)
			}
			proof, _ := json.Marshal(struct {
				Scope         imagebuild.UploadScope
				NeverBorrowed bool
			}{u.Scope, true})
			local.Native = sha256.Sum256(append([]byte("sfc-imagebuild-unstarted-1\x00"), proof...))
		}
		if err := r.saveImageBuildReclaim(local); err != nil {
			return err
		}
	}
	if !local.Returned {
		if !local.Returning {
			local.Returning = true
			if err := r.saveImageBuildReclaim(local); err != nil {
				return err
			}
		}
		if local.Started {
			pin, held, err := r.nodeRoots.RecordedPin(u.Scope.Root, buildArtifactConsumer(u.Scope))
			if err != nil {
				return err
			}
			if held {
				if pin.Lease != local.Lease {
					return imagebuild.ErrStorage
				}
				if err := r.nodeRoots.Return(pin); err != nil {
					return err
				}
			}
		}
		local.Returned = true
		if err := r.saveImageBuildReclaim(local); err != nil {
			return err
		}
	}
	if local.Receipt == nil {
		evidence, _ := json.Marshal(struct {
			Native  [32]byte
			Lease   reconcile.Lease
			Started bool
		}{local.Native, local.Lease, local.Started})
		fact := imagebuild.ReclaimReceipt{Schema: 1, Scope: u.Scope.Hash(), Version: local.Version, Native: sha256.Sum256(append([]byte("sfc-imagebuild-closure-1\x00"), evidence...)), At: uint64(time.Now().Unix())}
		fact.Signature = ed25519.Sign(r.Identity.Private, imagebuild.ReclaimReceiptBytes(fact))
		local.Receipt = &fact
		if err := r.saveImageBuildReclaim(local); err != nil {
			return err
		}
	}
	if !local.Receipt.Valid(u.Scope, local.Version) {
		return imagebuild.ErrStorage
	}
	latest, err := r.imageBuildArtifactWork(ctx, u)
	if err != nil {
		return err
	}
	if latest.Upload.Reclaimed != nil {
		if string(imagebuild.ReclaimReceiptBytes(*latest.Upload.Reclaimed)) != string(imagebuild.ReclaimReceiptBytes(*local.Receipt)) {
			return imagebuild.ErrStorage
		}
		return nil
	}
	if !latest.Reclaim {
		return imagebuild.ErrUsed
	}
	return r.publishImageBuildOwner(ctx, latest, control.ImageBuildOwnerReport{Action: "reclaimed", Reclaimed: local.Receipt})
}
func (r *Runtime) reconcileImageBuildArtifacts(ctx context.Context, view cluster.View) error {
	b, err := r.controlPolicy.ImageBuilds(view.State)
	if err != nil {
		return err
	}
	var failed error
	processed := 0
	for _, u := range b.Uploads {
		if u.Scope.Root.Key != r.Identity.Public || u.Reclaimed != nil {
			continue
		}
		if !u.Closed {
			if uint64(time.Now().Unix()) < u.Scope.ExpiresAt {
				continue
			}
			work, err := r.imageBuildArtifactWork(ctx, u)
			if err != nil {
				failed = errors.Join(failed, err)
				continue
			}
			if work.Upload.Closed {
				continue
			}
			fact := imagebuild.ExpiryReceipt{Schema: 1, Scope: u.Scope.Hash(), At: uint64(time.Now().Unix())}
			fact.Signature = ed25519.Sign(r.Identity.Private, imagebuild.ExpiryReceiptBytes(fact))
			failed = errors.Join(failed, r.publishImageBuildOwner(ctx, work, control.ImageBuildOwnerReport{Action: "expired", Expiry: &fact}))
		} else if !b.ArtifactReferenced(u) {
			failed = errors.Join(failed, r.reclaimImageBuild(ctx, u))
		} else {
			continue
		}
		processed++
		if processed >= 4 {
			break
		}
	}
	return failed
}
