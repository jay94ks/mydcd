// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

type registryMaintenanceReceipt struct {
	Schema                 uint8
	Cluster, Owner, Target [32]byte
	Operation              string
	Sent                   bool
	Result                 *control.RegistryMaintenanceResult `json:",omitempty"`
	Prune                  *registryPruneProgress             `json:",omitempty"`
}

func registryMaintenanceReceiptKey(id string) string {
	hash := sha256.Sum256([]byte(id))
	return "maintenance/registry/" + hex.EncodeToString(hash[:])
}
func (r *Runtime) saveRegistryMaintenance(row registryMaintenanceReceipt) error {
	raw, err := json.Marshal(row)
	if err != nil || len(raw) > 16<<10 {
		return registry.ErrStorage
	}
	return r.reports.Write(map[string][]byte{registryMaintenanceReceiptKey(row.Operation): raw})
}
func (r *Runtime) loadRegistryMaintenance(work control.RegistryMaintenanceWork) (registryMaintenanceReceipt, error) {
	row := registryMaintenanceReceipt{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Target: work.Change.DigestValue(), Operation: work.Operation}
	raw, err := r.reports.GetBounded(registryMaintenanceReceiptKey(row.Operation), 16<<10)
	if errors.Is(err, storage.ErrMissing) {
		return row, nil
	}
	if err != nil {
		return row, err
	}
	stored, err := schema.Decode[registryMaintenanceReceipt](raw)
	if err != nil || stored.Schema != row.Schema || stored.Cluster != row.Cluster || stored.Owner != row.Owner || stored.Target != row.Target || stored.Operation != row.Operation || stored.Result != nil && !stored.Result.Valid() {
		return row, registry.ErrStorage
	}
	if stored.Result != nil && r.reports.Sync() != nil {
		return row, registry.ErrStorage
	}
	if stored.Prune != nil && !stored.Prune.valid(work.Change) {
		return row, registry.ErrStorage
	}
	return stored, nil
}
func (r *Runtime) registryMaintenanceWork(ctx context.Context, id string, images []string) (control.RegistryMaintenanceWork, error) {
	raw, _ := json.Marshal(control.RegistryMaintenanceWorkRequest{Operation: id, At: time.Now().Unix(), Images: images})
	reply, err := r.appCall(ctx, "registry-maintenance-work", raw)
	if err != nil {
		return control.RegistryMaintenanceWork{}, err
	}
	work, err := schema.Decode[control.RegistryMaintenanceWork](reply.Data)
	if err != nil || reply.Local || work.Schema != 1 || work.Cluster != r.controlPolicy.Cluster || work.Owner != r.Identity.Public || work.Change.OwnerKey() != r.Identity.Public || work.Operation != id || work.Revision == 0 || work.Index == 0 || work.Epoch == 0 || !work.Change.Valid(work.Cluster, work.Action) {
		return work, mydcp.ErrAdmission
	}
	if _, err = r.Engine().ReadAtLeast(ctx, work.Index); err != nil {
		return work, err
	}
	return work, nil
}
func (r *Runtime) registryMaintenanceReport(ctx context.Context, work control.RegistryMaintenanceWork, action string, result *control.RegistryMaintenanceResult) error {
	report := control.RegistryMaintenanceReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Operation: work.Operation, Action: action, Expected: work.Revision, RootRevision: work.RootRevision, Epoch: work.Epoch, At: uint64(time.Now().Unix()), Result: result}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.RegistryMaintenanceReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "registry-maintenance-report", raw)
	if err == nil && (reply.Committed == nil || reply.Committed.Result.Code != state.Applied) {
		return errTunnelProgress
	}
	return err
}
func sameMaintenanceRun(a, b control.RegistryRunRef) bool {
	a.Ready = nil
	b.Ready = nil
	a.Draining = false
	b.Draining = false
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
func (r *Runtime) maintenanceStore(run control.RegistryRunRef) (*registry.Store, error) {
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	row, ok := r.registryRecords[run.Spec.Key()]
	live := r.registrySessions[run.Spec.Key()]
	if !ok || row.Run == nil || !sameMaintenanceRun(*row.Run, run) || row.IOClosed || row.PinReturned {
		return nil, registry.ErrUnavailable
	}
	if live != nil && live.store != nil {
		return live.store, nil
	}
	// Cleanup borrows the exact retained native pin; it creates neither a new
	// writer/run nor a serving listener/current user grant. Known data may never
	// be initialized empty to settle an original maintenance operation.
	if !row.KnownData || row.Pin == nil || r.nativeVolumes == nil {
		return nil, registry.ErrUnavailable
	}
	directory, err := r.nativeVolumes.OpenDataDirectory(r.ctx, *row.Pin)
	if err != nil {
		return nil, err
	}
	if _, err = directory.Root.Lstat("registry/registry.db"); err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err = directory.Check(); err != nil {
		_ = directory.Close()
		return nil, err
	}
	store, err := registry.OpenStore(r.ctx, filepath.Join(directory.Path(), "registry"), registry.Scope{Schema: 1, Cluster: row.Cluster, Node: row.DataOwner, Tenant: row.Spec.Tenant, Registry: row.Spec.ID}, row.Spec.Metadata, row.Spec.Blobs)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err = directory.Check(); err != nil {
		_ = store.Close()
		_ = directory.Close()
		return nil, err
	}
	if live == nil {
		live = &registrySession{}
		r.registrySessions[run.Spec.Key()] = live
	}
	if live.directory != nil {
		_ = live.directory.Close()
	}
	live.directory = directory
	live.store = store
	return store, nil
}

func (r *Runtime) reopenMaintenanceStore(ctx context.Context, run control.RegistryRunRef) {
	r.registryMu.Lock()
	defer r.registryMu.Unlock()
	row, ok := r.registryRecords[run.Spec.Key()]
	if !ok || row.Run == nil || !sameMaintenanceRun(*row.Run, run) || row.IOClosed {
		return
	}
	// Existing quiesce retains the same native/shared pin and run. The normal
	// owner loop reopens that original DB; it does not create a new operation.
	_, _ = r.quiesceRegistry(ctx, row)
}
func nativeMaintenanceResult(code string, at uint64, native any, bytes int64) control.RegistryMaintenanceResult {
	raw, _ := json.Marshal(native)
	return control.RegistryMaintenanceResult{Code: code, At: at, Native: sha256.Sum256(raw), ReclaimedBytes: bytes}
}
func (r *Runtime) finishRegistryMaintenance(ctx context.Context, work control.RegistryMaintenanceWork, local registryMaintenanceReceipt) {
	if local.Result == nil || !local.Result.Valid() || r.saveRegistryMaintenance(local) != nil {
		return
	}
	fresh, err := r.registryMaintenanceWork(ctx, work.Operation, nil)
	if err != nil || fresh.State != "running" || fresh.Change.DigestValue() != local.Target {
		return
	}
	_ = r.registryMaintenanceReport(ctx, fresh, "complete", local.Result)
}

func (r *Runtime) runRegistryMaintenance(id string) {
	defer r.wg.Done()
	defer func() { r.mu.Lock(); r.registryMaintenanceBusy = false; r.mu.Unlock() }()
	ctx := r.ctx
	work, err := r.registryMaintenanceWork(ctx, id, nil)
	if err != nil {
		return
	}
	if work.State == "queued" {
		if r.registryMaintenanceReport(ctx, work, "begin", nil) != nil {
			return
		}
		work, err = r.registryMaintenanceWork(ctx, id, nil)
		if err != nil {
			return
		}
	}
	if work.State != "running" {
		return
	}
	local, err := r.loadRegistryMaintenance(work)
	if err != nil {
		return
	}
	if work.Change.Prune != nil {
		r.runRegistryPrune(ctx, work, local)
		return
	}
	if work.Change.External != nil {
		r.runExternalRegistryMaintenance(ctx, work, local)
		return
	}
	if local.Result == nil && !work.Allowed && !local.Sent {
		local.Result = &control.RegistryMaintenanceResult{Code: "DENIED", At: uint64(time.Now().UnixMilli())}
	}
	if local.Result == nil && !local.Sent && work.Action == "delete-registry-image" && work.InUse {
		local.Result = &control.RegistryMaintenanceResult{Code: "IMAGE_IN_USE", At: uint64(time.Now().UnixMilli())}
	}
	var store *registry.Store
	if local.Result == nil {
		store, err = r.maintenanceStore(work.Change.Run)
		if err != nil {
			return
		}
		change := work.Change
		deletion := registry.ImageDelete{Operation: id, Authority: change.Run.Spec.Authority, Repository: change.Repository, Reference: change.Reference, ExpectedDigest: change.Digest}
		gc := registry.GCRequest{Operation: id, Authority: change.Run.Spec.Authority}
		pendingGC := false
		if work.Action == "delete-registry-image" {
			original, found, e := store.DeleteReceipt(ctx, deletion)
			if e != nil {
				r.reopenMaintenanceStore(ctx, change.Run)
				return
			}
			if found {
				code := original.Code
				if original.State == "already-absent" {
					code = "ALREADY_ABSENT"
				}
				result := nativeMaintenanceResult(code, original.At, original, 0)
				local.Result = &result
			}
		} else {
			original, found, e := store.GCReceipt(ctx, gc)
			if e != nil {
				r.reopenMaintenanceStore(ctx, change.Run)
				return
			}
			pendingGC = found && original.State == "deleting"
			if found && original.State == "done" {
				result := nativeMaintenanceResult("OK", original.CompletedAt, original, original.ReclaimedBytes)
				local.Result = &result
			}
		}
		if local.Result == nil && !work.Allowed && !pendingGC {
			local.Result = &control.RegistryMaintenanceResult{Code: "DENIED", At: uint64(time.Now().UnixMilli())}
		}
		if local.Result == nil {
			if !local.Sent {
				local.Sent = true
				if r.saveRegistryMaintenance(local) != nil {
					return
				}
			}
			until, e := store.BeginWriteFence(ctx, id, time.Now().Unix())
			if e != nil {
				if errors.Is(e, registry.ErrBudget) && store.EndWriteFence(ctx, id) == nil {
					local.Result = &control.RegistryMaintenanceResult{Code: "REGISTRY_BUDGET", At: uint64(time.Now().UnixMilli())}
					r.finishRegistryMaintenance(ctx, work, local)
				}
				return
			}
			if until > time.Now().Unix() && !pendingGC {
				return
			}
			guard := func(call context.Context, images []string) error {
				for offset := 0; offset < len(images) || offset == 0; offset += 32 {
					selected := images[offset:min(offset+32, len(images))]
					fresh, e := r.registryMaintenanceWork(call, id, selected)
					if e != nil {
						return e
					}
					if fresh.State != "running" || fresh.Change.DigestValue() != change.DigestValue() {
						return mydcp.ErrAdmission
					}
					if !fresh.Allowed {
						return registry.ErrForbidden
					}
					if fresh.InUse {
						return registry.ErrImageInUse
					}
					if len(images) == 0 {
						break
					}
				}
				return nil
			}
			if work.Action == "delete-registry-image" {
				original, e := store.DeleteImage(ctx, deletion, guard)
				if e == nil {
					code := original.Code
					if original.State == "already-absent" {
						code = "ALREADY_ABSENT"
					}
					result := nativeMaintenanceResult(code, original.At, original, 0)
					local.Result = &result
				} else {
					err = e
				}
			} else {
				original, e := store.GarbageCollect(ctx, gc, guard)
				if e == nil {
					result := nativeMaintenanceResult("OK", original.CompletedAt, original, original.ReclaimedBytes)
					local.Result = &result
				} else {
					err = e
				}
			}
			if err != nil {
				code := ""
				switch {
				case errors.Is(err, registry.ErrImageInUse):
					code = "IMAGE_IN_USE"
				case errors.Is(err, registry.ErrForbidden):
					code = "DENIED"
				case errors.Is(err, registry.ErrUploadsInProgress), errors.Is(err, registry.ErrReaders):
					code = "UPLOADS_IN_PROGRESS"
				case errors.Is(err, registry.ErrPushLeaseActive):
					return
				case errors.Is(err, registry.ErrBudget):
					code = "REGISTRY_BUDGET"
				}
				if code == "" {
					if errors.Is(err, registry.ErrStorage) {
						r.reopenMaintenanceStore(ctx, change.Run)
					}
					return
				}
				local.Result = &control.RegistryMaintenanceResult{Code: code, At: uint64(time.Now().UnixMilli())}
			}
		}
		if local.Result != nil && store.EndWriteFence(ctx, id) != nil {
			return
		}
	}
	r.finishRegistryMaintenance(ctx, work, local)
}
func (r *Runtime) advanceRegistryMaintenance(ctx context.Context) {
	if r.reports == nil || ctx.Err() != nil {
		return
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return
	}
	jobs, err := r.controlPolicy.RegistryMaintenanceJobs(view.State)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.registryMaintenanceBusy {
		return
	}
	for n := 0; n < len(jobs.Records); n++ {
		index := (r.registryMaintenanceCursor + n) % len(jobs.Records)
		row := jobs.Records[index]
		if row.Change.OwnerKey() == r.Identity.Public && row.Pending() && row.State != "unknown" {
			r.registryMaintenanceCursor = (index + 1) % len(jobs.Records)
			r.registryMaintenanceBusy = true
			r.wg.Add(1)
			go r.runRegistryMaintenance(row.Change.Operation)
			return
		}
	}
}
