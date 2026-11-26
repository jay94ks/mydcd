// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagecache"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"

	cerrdefs "github.com/containerd/errdefs"
)

type cacheItemReceipt struct {
	ID     string
	Sent   bool
	Result *imagecache.Part `json:",omitempty"`
}
type cacheReceipt struct {
	Schema                 uint8
	Cluster, Owner, Target [32]byte
	Operation              string
	Items                  []cacheItemReceipt
}

func cacheReceiptKey(operation string) string {
	hash := sha256.Sum256([]byte(operation))
	return "maintenance/image-cache/" + hex.EncodeToString(hash[:])
}
func (r *Runtime) saveCacheReceipt(receipt cacheReceipt) error {
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > 32<<10 {
		return imagecache.ErrPlan
	}
	return r.reports.Write(map[string][]byte{cacheReceiptKey(receipt.Operation): raw})
}
func (r *Runtime) loadCacheReceipt(work control.ImageCacheWork) (cacheReceipt, error) {
	out := cacheReceipt{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Target: work.Plan.Digest(), Operation: work.Operation}
	for _, image := range work.Plan.Images {
		out.Items = append(out.Items, cacheItemReceipt{ID: image.ID})
	}
	raw, err := r.reports.GetBounded(cacheReceiptKey(work.Operation), 32<<10)
	if errors.Is(err, storage.ErrMissing) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	stored, err := schema.Decode[cacheReceipt](raw)
	if err != nil || stored.Schema != 1 || stored.Cluster != out.Cluster || stored.Owner != out.Owner || stored.Target != out.Target || stored.Operation != out.Operation || len(stored.Items) != len(out.Items) {
		return out, imagecache.ErrPlan
	}
	for i, item := range stored.Items {
		if item.ID != out.Items[i].ID || item.Result != nil && (!item.Result.Valid() || item.Result.ID != item.ID) {
			return out, imagecache.ErrPlan
		}
	}
	return stored, nil
}
func (r *Runtime) cacheWork(ctx context.Context, operation string) (control.ImageCacheWork, error) {
	raw, _ := json.Marshal(control.ImageCacheWorkRequest{Operation: operation})
	reply, err := r.appCall(ctx, "image-cache-work", raw)
	if err != nil {
		return control.ImageCacheWork{}, err
	}
	work, err := schema.Decode[control.ImageCacheWork](reply.Data)
	if err != nil || work.Schema != 1 || work.Cluster != r.controlPolicy.Cluster || work.Owner != r.Identity.Public || work.Operation != operation || !work.Plan.DeleteReady() || work.Plan.Owner != work.Owner || work.Index == 0 || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex < work.Index || len(work.References) != len(work.Plan.Images) || len(work.Parts) > len(work.Plan.Images) {
		return work, mydcp.ErrAdmission
	}
	if _, err = r.Engine().ReadAtLeast(ctx, work.Index); err != nil {
		return work, err
	}
	return work, nil
}
func (r *Runtime) cacheReport(ctx context.Context, work control.ImageCacheWork, action string, part *imagecache.Part) error {
	report := control.ImageCacheReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Operation: work.Operation, Action: action, Expected: work.Revision, RootRevision: work.RootRevision, Epoch: work.Epoch, At: uint64(time.Now().Unix()), Part: part}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.ImageCacheReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "image-cache-report", raw)
	if err == nil && (reply.Committed == nil || reply.Committed.Result.Code != state.Applied) {
		return errTunnelProgress
	}
	return err
}
func (r *Runtime) runImageCache(operation string) {
	defer r.wg.Done()
	defer func() { r.mu.Lock(); r.imageCacheBusy = false; r.mu.Unlock() }()
	r.imageUseMu.Lock()
	defer r.imageUseMu.Unlock()
	ctx := r.ctx
	work, err := r.cacheWork(ctx, operation)
	if err != nil {
		return
	}
	if work.State == "queued" {
		if r.cacheReport(ctx, work, "begin", nil) != nil {
			return
		}
	}
	work, err = r.cacheWork(ctx, operation)
	if err != nil || work.State != "running" {
		return
	}
	receipt, err := r.loadCacheReceipt(work)
	if err != nil {
		log.Printf("image cache original receipt unavailable: operation=%s cause=%v", operation, err)
		return
	}
	for work.State == "running" && len(work.Parts) < len(work.Plan.Images) {
		i := len(work.Parts)
		item := &receipt.Items[i]
		if item.Result == nil {
			r.life.RLock()
			if r.closed || r.docker == nil {
				r.life.RUnlock()
				return
			}
			_, inspectErr := r.docker.API.ImageInspect(ctx, item.ID)
			if cerrdefs.IsNotFound(inspectErr) {
				item.Result = &imagecache.Part{ID: item.ID, State: "already-absent", At: uint64(time.Now().UnixMilli())}
			}
			if item.Result == nil && !work.Allowed {
				if item.Sent {
					r.life.RUnlock()
					return
				}
				item.Result = &imagecache.Part{ID: item.ID, State: "failed", Code: "authority-revoked", At: uint64(time.Now().UnixMilli())}
			}
			if item.Result == nil {
				wasSent := item.Sent
				call, cancel := context.WithTimeout(ctx, 30*time.Second)
				part, known, callErr := r.docker.RemoveCachedImage(call, work.Plan.Images[i], func(call context.Context, current imagecache.Image) (uint64, error) {
					fresh, e := r.cacheWork(call, operation)
					if e != nil {
						return 0, e
					}
					if !fresh.Allowed || fresh.State != "running" || len(fresh.Parts) != i || fresh.Plan.Digest() != work.Plan.Digest() {
						return 0, mydcp.ErrAdmission
					}
					private, err := r.privateImageReferences(current.ID)
					if err != nil {
						return 0, err
					}
					return fresh.References[i] + private, nil
				}, func() error { item.Sent = true; return r.saveCacheReceipt(receipt) })
				cancel()
				if known {
					// A new conflict/skip does not settle an earlier request whose
					// reply was lost. That original may still delete later. Only
					// positive absence can release its original admission fence.
					if wasSent && part.State != "removed" && part.State != "already-absent" {
						r.life.RUnlock()
						return
					}
					item.Result = &part
				} else if callErr != nil {
					r.life.RUnlock()
					return
				}
			}
			r.life.RUnlock()
		}
		if item.Result == nil || !item.Result.Valid() || r.saveCacheReceipt(receipt) != nil || ctx.Err() != nil {
			return
		}
		work, err = r.cacheWork(ctx, operation)
		if err != nil || work.State != "running" || len(work.Parts) != i {
			return
		}
		if r.cacheReport(ctx, work, "item", item.Result) != nil {
			return
		}
		work, err = r.cacheWork(ctx, operation)
		if err != nil {
			return
		}
	}
}
func (r *Runtime) advanceImageCache(ctx context.Context) {
	if r.reports == nil || ctx.Err() != nil {
		return
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return
	}
	jobs, err := r.controlPolicy.ImageCacheJobs(v.State)
	if err != nil {
		return
	}
	for _, row := range jobs.Records {
		if row.Plan.Owner != r.Identity.Public || row.State != "queued" && row.State != "running" {
			continue
		}
		r.mu.Lock()
		if !r.imageCacheBusy && ctx.Err() == nil {
			r.imageCacheBusy = true
			r.wg.Add(1)
			go r.runImageCache(row.Operation)
		}
		r.mu.Unlock()
		return
	}
}
