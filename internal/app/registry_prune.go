// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

type registryPruneProgress struct {
	Preview        string
	Next           uint32
	Sent           bool
	Summary        control.RegistryPruneSummary
	ReclaimedBytes int64
}

func (p registryPruneProgress) valid(change control.RegistryMaintenanceChange) bool {
	if change.Prune == nil || p.Preview != registryPrunePreviewKey(change.Prune.Fact.Target, change.Prune.Fact.Preview) || p.Next > change.Prune.Fact.Items || p.Next != p.Summary.Processed || !p.Summary.Valid() || p.ReclaimedBytes < 0 {
		return false
	}
	if p.Sent && p.Next == change.Prune.Fact.Items || p.Summary.GCCode != "" && (!change.Prune.Conditions.GC || p.Next != change.Prune.Fact.Items) {
		return false
	}
	return true
}
func registryPruneItemPrefix(operation string) string {
	h := sha256.Sum256([]byte(operation))
	return "maintenance/registry-prune/" + hex.EncodeToString(h[:]) + "/item/"
}
func registryPruneItemKey(operation string, index uint32) string {
	return registryPruneItemPrefix(operation) + fmt.Sprintf("%08d", index)
}

// One bbolt commit advances the ordinal and stores the original item result.
// The large frozen preview is never rewritten for progress or placed in Raft.
func (r *Runtime) saveRegistryPruneItem(local *registryMaintenanceReceipt, item registryclient.PruneItem, result control.RegistryMaintenanceResult) error {
	if local.Prune == nil || !result.Valid() || result.Prune != nil {
		return registry.ErrStorage
	}
	row := control.PrunePublicItem(item)
	row.Code, row.At, row.Native = result.Code, result.At, result.Native
	if !row.Valid(true) {
		return registry.ErrStorage
	}
	key := registryPruneItemKey(local.Operation, local.Prune.Next)
	if _, err := r.reports.GetBounded(key, 16<<10); !errors.Is(err, storage.ErrMissing) {
		return registry.ErrStorage
	}
	next := *local
	p := *local.Prune
	p.Next++
	p.Sent = false
	p.Summary.Processed++
	if control.PruneResultSuccess(row.Code) {
		p.Summary.Deleted++
	} else if control.PruneResultSkipped(row.Code) {
		p.Summary.Skipped++
	} else {
		p.Summary.Failed++
	}
	next.Prune = &p
	raw, err := json.Marshal(row)
	if err != nil || len(raw) > 16<<10 {
		return registry.ErrStorage
	}
	progress, err := json.Marshal(next)
	if err != nil || len(progress) > 16<<10 {
		return registry.ErrStorage
	}
	if err = r.reports.Write(map[string][]byte{key: raw, registryMaintenanceReceiptKey(local.Operation): progress}); err != nil {
		return err
	}
	*local = next
	return nil
}
func (r *Runtime) registryPruneResultsOwner(ctx context.Context, read control.RegistryPruneRead) (control.RegistryPruneView, error) {
	change := read.Base.Change
	local, err := r.loadRegistryMaintenance(control.RegistryMaintenanceWork{Operation: change.Operation, Change: change})
	if err != nil {
		return control.RegistryPruneView{}, err
	}
	var total uint32
	if local.Prune != nil {
		total = local.Prune.Next
	}
	root := control.RegistryPruneResultRoot(local.Target, total, local.Result)
	start, end, next, err := registryclient.PruneResultRange(root, total, read.After)
	if err != nil {
		return control.RegistryPruneView{}, err
	}
	out := control.RegistryPruneView{Schema: 1, Tenant: read.Tenant, Plan: read.Base, Page: control.RegistryPrunePage{Schema: 1, Root: root, Part: "items", Total: total, Processed: total, Next: next}}
	for index := start; index < end; index++ {
		raw, err := r.reports.GetBounded(registryPruneItemKey(change.Operation, index), 16<<10)
		if err != nil {
			return out, err
		}
		row, err := schema.Decode[control.RegistryPruneRow](raw)
		if err != nil || !row.Valid(true) {
			return out, registry.ErrStorage
		}
		out.Page.Rows = append(out.Page.Rows, row)
	}
	latest, err := r.currentView(ctx)
	if err != nil || latest.Local {
		return out, mydcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentRegistryPruneRead(latest.State, read, time.Now().Unix(), true)
	if err != nil || !out.Valid(current, true) {
		return control.RegistryPruneView{}, mydcp.ErrAdmission
	}
	return out, nil
}

func pruneItemReferences(authority string, item registryclient.PruneItem) []string {
	refs := []string{authority + "/" + item.Image.Repository + "@" + item.Image.Digest}
	if !strings.HasPrefix(item.Image.Reference, "sha256:") {
		refs = append(refs, authority+"/"+item.Image.Repository+":"+item.Image.Reference)
	}
	return refs
}
func registryPruneRefusal(err error) string {
	switch {
	case errors.Is(err, registry.ErrImageInUse):
		return "IMAGE_IN_USE"
	case errors.Is(err, registry.ErrForbidden):
		return "DENIED"
	case errors.Is(err, registry.ErrUploadsInProgress), errors.Is(err, registry.ErrReaders):
		return "UPLOADS_IN_PROGRESS"
	case errors.Is(err, registry.ErrBudget):
		return "REGISTRY_BUDGET"
	}
	return ""
}
func (r *Runtime) registryPruneGuard(local registryMaintenanceReceipt) func(context.Context, []string) error {
	return func(ctx context.Context, images []string) error {
		for offset := 0; offset < len(images) || offset == 0; offset += 32 {
			fresh, err := r.registryMaintenanceWork(ctx, local.Operation, images[offset:min(offset+32, len(images))])
			if err != nil {
				return err
			}
			if fresh.State != "running" || fresh.Change.DigestValue() != local.Target {
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
}
func (r *Runtime) runRegistryPrune(ctx context.Context, work control.RegistryMaintenanceWork, local registryMaintenanceReceipt) {
	if local.Result != nil {
		r.finishRegistryMaintenance(ctx, work, local)
		return
	}
	change := work.Change
	if change.Prune == nil {
		return
	}
	r.registryPruneMu.Lock()
	preview, err := r.loadRegistryPrunePreview(change)
	if err == nil && local.Prune == nil {
		local.Prune = &registryPruneProgress{Preview: registryPrunePreviewKey(change.Prune.Fact.Target, change.Prune.Fact.Preview)}
		err = r.saveRegistryMaintenance(local)
	}
	r.registryPruneMu.Unlock()
	if err != nil {
		if errors.Is(err, storage.ErrMissing) && local.Prune == nil && !local.Sent {
			local.Result = &control.RegistryMaintenanceResult{Code: "PREVIEW_UNAVAILABLE", At: uint64(time.Now().UnixMilli()), Prune: &control.RegistryPruneSummary{}}
			r.finishRegistryMaintenance(ctx, work, local)
		}
		return
	}
	if !local.Prune.valid(change) {
		return
	}
	if change.External != nil {
		r.runExternalRegistryPrune(ctx, work, local, preview)
		return
	}
	store, err := r.maintenanceStore(change.Run)
	if err != nil {
		return
	}
	guard := r.registryPruneGuard(local)
	// Native receipts are read before current permission checks: an old effect
	// is settled from its original transaction, never repeated as new work.
	end := min(local.Prune.Next+16, uint32(len(preview.Items)))
	for local.Prune.Next < end {
		item := preview.Items[local.Prune.Next]
		deletion, cause := registry.PruneImageDelete(local.Operation, change.Authority(), item)
		if cause != nil {
			return
		}
		original, found, cause := store.DeleteReceipt(ctx, deletion)
		if cause != nil {
			r.reopenMaintenanceStore(ctx, change.Run)
			return
		}
		var result control.RegistryMaintenanceResult
		if !found {
			cause = guard(ctx, pruneItemReferences(change.Authority(), item))
			if cause == nil {
				local.Sent = true
				local.Prune.Sent = true
				if r.saveRegistryMaintenance(local) != nil {
					return
				}
				until, e := store.BeginWriteFence(ctx, local.Operation, time.Now().Unix())
				if e != nil {
					cause = e
				} else if until > time.Now().Unix() {
					return
				}
				if cause == nil {
					original, cause = store.DeleteImage(ctx, deletion, guard)
					found = cause == nil
				}
			}
			if cause != nil {
				code := registryPruneRefusal(cause)
				if code == "" {
					if errors.Is(cause, registry.ErrStorage) {
						r.reopenMaintenanceStore(ctx, change.Run)
					}
					return
				}
				result = control.RegistryMaintenanceResult{Code: code, At: uint64(time.Now().UnixMilli())}
			}
		}
		if found {
			code := original.Code
			if original.State == "already-absent" {
				code = "ALREADY_ABSENT"
			}
			result = nativeMaintenanceResult(code, original.At, original, 0)
		}
		if r.saveRegistryPruneItem(&local, item, result) != nil {
			return
		}
	}
	if local.Prune.Next < uint32(len(preview.Items)) {
		return
	}
	if change.Prune.Conditions.GC && local.Prune.Summary.GCCode == "" {
		request := registry.GCRequest{Operation: local.Operation, Authority: change.Authority()}
		original, found, cause := store.GCReceipt(ctx, request)
		if cause != nil {
			r.reopenMaintenanceStore(ctx, change.Run)
			return
		}
		pending := found && original.State == "deleting"
		if !found || original.State != "done" {
			if !pending {
				cause = guard(ctx, nil)
			}
			if cause == nil {
				local.Sent = true
				if r.saveRegistryMaintenance(local) != nil {
					return
				}
				until, e := store.BeginWriteFence(ctx, local.Operation, time.Now().Unix())
				if e != nil {
					cause = e
				} else if until > time.Now().Unix() && !pending {
					return
				}
				if cause == nil {
					original, cause = store.GarbageCollect(ctx, request, guard)
				}
			}
		}
		if cause != nil {
			code := registryPruneRefusal(cause)
			if code == "" || pending {
				if errors.Is(cause, registry.ErrStorage) {
					r.reopenMaintenanceStore(ctx, change.Run)
				}
				return
			}
			local.Prune.Summary.GCCode = code
		} else {
			if original.State != "done" {
				return
			}
			local.Prune.Summary.GCCode = "OK"
			local.Prune.Summary.GCAt = original.CompletedAt
			local.Prune.ReclaimedBytes = original.ReclaimedBytes
		}
		if r.saveRegistryMaintenance(local) != nil {
			return
		}
	}
	if err := store.EndWriteFence(ctx, local.Operation); err != nil {
		if errors.Is(err, registry.ErrStorage) {
			r.reopenMaintenanceStore(ctx, change.Run)
		}
		return
	}
	r.finishRegistryPrune(ctx, work, local)
}

func (r *Runtime) finishRegistryPrune(ctx context.Context, work control.RegistryMaintenanceWork, local registryMaintenanceReceipt) {
	if local.Prune == nil || !local.Prune.valid(work.Change) || local.Prune.Sent || local.Prune.Next != work.Change.Prune.Fact.Items {
		return
	}
	summary := local.Prune.Summary
	if work.Change.Prune.Conditions.GC && summary.GCCode == "" {
		return
	}
	h := sha256.New()
	_, _ = h.Write([]byte("mydc-registry-prune-result-1\x00"))
	raw, _ := json.Marshal(struct {
		Target         [32]byte
		Summary        control.RegistryPruneSummary
		ReclaimedBytes int64
	}{local.Target, summary, local.Prune.ReclaimedBytes})
	_, _ = h.Write(raw)
	for index := uint32(0); index < local.Prune.Next; index++ {
		raw, err := r.reports.GetBounded(registryPruneItemKey(local.Operation, index), 16<<10)
		if err != nil {
			return
		}
		row, err := schema.Decode[control.RegistryPruneRow](raw)
		if err != nil || !row.Valid(true) {
			return
		}
		_, _ = h.Write(raw)
	}
	code := "OK"
	if summary.Failed > 0 || summary.GCCode != "" && summary.GCCode != "OK" {
		code = "PARTIAL"
	}
	result := control.RegistryMaintenanceResult{Code: code, At: uint64(time.Now().UnixMilli()), ReclaimedBytes: local.Prune.ReclaimedBytes, Prune: &summary}
	copy(result.Native[:], h.Sum(nil))
	local.Result = &result
	r.finishRegistryMaintenance(ctx, work, local)
}

func (r *Runtime) runExternalRegistryPrune(ctx context.Context, work control.RegistryMaintenanceWork, local registryMaintenanceReceipt, preview registryclient.PrunePreview) {
	if local.Prune.Sent {
		_ = r.registryMaintenanceReport(ctx, work, "uncertain", nil)
		return
	}
	var client *registryclient.Access
	if work.Allowed {
		target := work.Change.External
		source, err := r.externalRegistryWork(ctx, target.Selection)
		if err != nil || source.Inputs.ReadSet != target.ReadSet {
			return
		}
		release, err := r.acquireExternalReader(source)
		if err != nil {
			return
		}
		defer release()
		client, err = r.sourceRegistryClient(ctx, source)
		if err != nil {
			return
		}
		defer client.Close()
	}
	guard := r.registryPruneGuard(local)
	end := min(local.Prune.Next+16, uint32(len(preview.Items)))
	for local.Prune.Next < end {
		item := preview.Items[local.Prune.Next]
		code := ""
		if !work.Allowed {
			code = "DENIED"
		} else if !strings.HasPrefix(item.Image.Reference, "sha256:") {
			code = "UNSUPPORTED"
		}
		var result control.RegistryMaintenanceResult
		if code == "" {
			beforeCode := ""
			outcome := client.DeleteManifest(ctx, work.Change.Authority()+"/"+item.Image.Repository+"@"+item.Image.Digest, func(call context.Context) error {
				unchanged, cause := client.CheckPruneAliases(call, item)
				if cause != nil {
					return cause
				}
				if !unchanged {
					beforeCode = "REFERENCE_CHANGED"
					return registry.ErrForbidden
				}
				if err := guard(call, pruneItemReferences(work.Change.Authority(), item)); err != nil {
					beforeCode = registryPruneRefusal(err)
					return err
				}
				local.Sent = true
				local.Prune.Sent = true
				return r.saveRegistryMaintenance(local)
			})
			if !outcome.Valid() {
				return
			}
			if outcome.Code == "UNKNOWN" {
				_ = r.registryMaintenanceReport(ctx, work, "uncertain", nil)
				return
			}
			if outcome.Attempted {
				result = nativeMaintenanceResult(outcome.Code, outcome.At, struct {
					Target          [32]byte
					Operation, Item string
					Outcome         registryclient.DeleteOutcome
				}{local.Target, local.Operation, item.ItemID(), outcome}, 0)
			} else {
				code = outcome.Code
				if beforeCode != "" {
					code = beforeCode
				}
			}
		}
		if code != "" {
			result = control.RegistryMaintenanceResult{Code: code, At: uint64(time.Now().UnixMilli())}
		}
		if r.saveRegistryPruneItem(&local, item, result) != nil {
			return
		}
	}
	if local.Prune.Next == uint32(len(preview.Items)) {
		r.finishRegistryPrune(ctx, work, local)
	}
}
