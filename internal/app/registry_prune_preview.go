// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/schema"
)

const registryPrunePreviewPrefix = "registry/prune-preview/"
const registryPruneCacheBytes = 32 << 20

type registryPrunePreviewRecord struct {
	Schema                 uint8
	Cluster, Owner, Target [32]byte
	At                     uint64
	Preview                registryclient.PrunePreview
	Digest, Public         [32]byte
}

func registryPrunePreviewKey(target, preview [32]byte) string {
	raw := append(append([]byte{}, target[:]...), preview[:]...)
	h := sha256.Sum256(raw)
	return registryPrunePreviewPrefix + hex.EncodeToString(h[:])
}
func (r *Runtime) decodeRegistryPrunePreview(key string, raw []byte) (registryPrunePreviewRecord, error) {
	row, err := schema.Decode[registryPrunePreviewRecord](raw)
	if err != nil || row.Schema != 1 || row.Cluster != r.controlPolicy.Cluster || row.Owner != r.Identity.Public || row.Target == ([32]byte{}) || row.At == 0 || !row.Preview.Valid() || row.Digest != row.Preview.Digest() || row.Public != control.RegistryPrunePreviewPublicDigest(row.Preview) || registryPrunePreviewKey(row.Target, row.Digest) != key {
		return row, registry.ErrStorage
	}
	return row, nil
}
func (r *Runtime) loadRegistryPrunePreview(change control.RegistryMaintenanceChange) (registryclient.PrunePreview, error) {
	if change.Prune == nil {
		return registryclient.PrunePreview{}, registry.ErrStorage
	}
	key := registryPrunePreviewKey(change.Prune.Fact.Target, change.Prune.Fact.Preview)
	row, ok := r.registryPruneLoaded[key]
	if !ok {
		raw, err := r.reports.GetBounded(key, registryclient.MaxPrunePreviewBytes+4096)
		if err != nil {
			return registryclient.PrunePreview{}, err
		}
		row, err = r.decodeRegistryPrunePreview(key, raw)
		if err != nil {
			return registryclient.PrunePreview{}, err
		}
		if r.registryPruneLoaded == nil {
			r.registryPruneLoaded = map[string]registryPrunePreviewRecord{}
		}
		r.registryPruneLoaded[key] = row
	}
	if row.Target != change.PruneBase().DigestValue() || control.PruneConditionsDigest(row.Preview.Conditions) != change.Prune.Fact.Conditions || row.Preview.Authority != change.Authority() || uint32(len(row.Preview.Items)) != change.Prune.Fact.Items || uint32(len(row.Preview.Retained)) != change.Prune.Fact.Retained || row.Preview.ImageBytes != change.Prune.Fact.ImageBytes || row.Preview.EstimatedReclaimedBytes != change.Prune.Fact.EstimatedReclaimedBytes || row.Preview.EstimateKnown != change.Prune.Fact.EstimateKnown || row.Preview.Live != change.Prune.Fact.Live || row.Public != change.Prune.Fact.Public || row.Digest != change.Prune.Fact.Preview {
		return registryclient.PrunePreview{}, registry.ErrStorage
	}
	return row.Preview, nil
}

// Caller and the owner worker serialize staging/start with registryPruneMu.
// Unstarted expired previews may disappear; a native-started/uncertain parent
// always retains its original artifact. Immutable result rows live separately.
func (r *Runtime) stageRegistryPrunePreview(s state.State, base control.RegistryMaintenanceChange, preview registryclient.PrunePreview, at uint64) error {
	if !preview.Valid() || at == 0 {
		return registry.ErrStorage
	}
	key := registryPrunePreviewKey(base.PruneBase().DigestValue(), preview.Digest())
	protected := map[string]bool{}
	jobs, err := r.controlPolicy.RegistryMaintenanceJobs(s)
	if err != nil {
		return err
	}
	for _, job := range jobs.Records {
		if job.Pending() && job.Change.Prune != nil {
			f := job.Change.Prune.Fact
			protected[registryPrunePreviewKey(f.Target, f.Preview)] = true
		}
	}
	locals, err := r.reports.ScanBounded("maintenance/registry/", 128, 4<<20)
	if err != nil {
		return err
	}
	for _, raw := range locals {
		row, err := schema.Decode[registryMaintenanceReceipt](raw)
		if err != nil || row.Schema != 1 || row.Cluster != r.controlPolicy.Cluster || row.Owner != r.Identity.Public {
			return registry.ErrStorage
		}
		if row.Prune != nil && row.Result == nil {
			protected[row.Prune.Preview] = true
		}
	}
	rows, err := r.reports.ScanBounded(registryPrunePreviewPrefix, 64, registryPruneCacheBytes)
	if err != nil {
		return err
	}
	changes := map[string][]byte{}
	total, count := 0, 0
	for k, raw := range rows {
		row, err := r.decodeRegistryPrunePreview(k, raw)
		if err != nil {
			return err
		}
		if k == key {
			continue
		}
		if !protected[k] && at > row.At && at-row.At > control.RegistryPrunePreviewSeconds {
			changes[k] = nil
			continue
		}
		total += len(k) + len(raw)
		count++
	}
	row := registryPrunePreviewRecord{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Target: base.PruneBase().DigestValue(), At: at, Preview: preview, Digest: preview.Digest(), Public: control.RegistryPrunePreviewPublicDigest(preview)}
	raw, err := json.Marshal(row)
	if err != nil || len(raw) > registryclient.MaxPrunePreviewBytes+4096 || count >= 64 || len(key)+len(raw) > registryPruneCacheBytes-total {
		return &registryclient.Error{Code: "METADATA_BUDGET"}
	}
	changes[key] = raw
	if err = r.reports.Write(changes); err != nil {
		return err
	}
	if r.registryPruneLoaded == nil {
		r.registryPruneLoaded = map[string]registryPrunePreviewRecord{}
	}
	for k, value := range changes {
		if value == nil {
			delete(r.registryPruneLoaded, k)
		}
	}
	var owned registryPrunePreviewRecord
	_ = json.Unmarshal(raw, &owned)
	r.registryPruneLoaded[key] = owned
	return nil
}

func registryPruneProtection(authority string, refs []control.ImageReference) func(registryclient.ImageMetadata) string {
	return func(image registryclient.ImageMetadata) string {
		ref := authority + "/" + image.Repository + "@" + image.Digest
		for _, row := range refs {
			if row.Unknown || row.MatchImage(ref) != "" {
				return "IMAGE_IN_USE"
			}
		}
		return ""
	}
}
func (r *Runtime) registryPruneOwner(ctx context.Context, read control.RegistryPruneRead, results bool) (control.RegistryPruneView, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.RegistryPruneView{}, mydcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentRegistryPruneRead(view.State, read, time.Now().Unix(), results)
	if err != nil || current.Base.Change.OwnerKey() != r.Identity.Public {
		return control.RegistryPruneView{}, mydcp.ErrAdmission
	}
	if results {
		return r.registryPruneResultsOwner(ctx, current)
	}
	base := current.Base
	var preview registryclient.PrunePreview
	if current.Query.Fact != nil {
		base.Change.Prune = &control.RegistryPruneTarget{Conditions: *current.Query.Conditions, Fact: *current.Query.Fact}
		r.registryPruneMu.Lock()
		preview, err = r.loadRegistryPrunePreview(base.Change)
		r.registryPruneMu.Unlock()
	} else {
		refs, cause := r.controlPolicy.ImageReferences(view.State, current.Tenant, "")
		if cause != nil {
			return control.RegistryPruneView{}, cause
		}
		protect := registryPruneProtection(base.Change.Authority(), refs)
		if base.Change.External == nil {
			if _, _, err = r.registryCurrent(ctx, base.Change.Run); err != nil {
				return control.RegistryPruneView{}, err
			}
			var store *registry.Store
			store, err = r.maintenanceStore(base.Change.Run)
			if err == nil {
				preview, err = store.PrunePreviewProtected(ctx, base.Change.Authority(), *current.Query.Conditions, protect)
			}
		} else {
			target := base.Change.External
			work, cause := r.externalRegistryWork(ctx, target.Selection)
			if cause != nil || work.Inputs.ReadSet != target.ReadSet {
				return control.RegistryPruneView{}, mydcp.ErrAdmission
			}
			release, cause := r.acquireExternalReader(work)
			if cause != nil {
				return control.RegistryPruneView{}, cause
			}
			defer release()
			client, cause := r.sourceRegistryClient(ctx, work)
			if cause != nil {
				return control.RegistryPruneView{}, cause
			}
			defer client.Close()
			var in registryclient.PruneInventory
			in, err = client.PruneInventory(ctx, *current.Query.Conditions, func(repo string) bool {
				selected, cause := r.controlPolicy.ExternalRegistryForImage(view.State, current.Tenant, access.Image{Registry: base.Change.Authority(), Repository: repo})
				return cause == nil && selected != nil && selected.ID == base.Change.RegistryID()
			}, protect)
			if err == nil {
				preview, err = registryclient.BuildPrunePreview(in, *current.Query.Conditions)
			}
		}
		if err != nil {
			return control.RegistryPruneView{}, err
		}
		latest, cause := r.currentView(ctx)
		if cause != nil || latest.Local {
			return control.RegistryPruneView{}, mydcp.ErrAdmission
		}
		current, cause = r.controlPolicy.CurrentRegistryPruneRead(latest.State, read, time.Now().Unix(), false)
		if cause != nil {
			return control.RegistryPruneView{}, cause
		}
		base = current.Base
		at := uint64(time.Now().Unix())
		r.registryPruneMu.Lock()
		err = r.stageRegistryPrunePreview(latest.State, base.Change, preview, at)
		r.registryPruneMu.Unlock()
		if err != nil {
			return control.RegistryPruneView{}, err
		}
		fact := control.RegistryPruneFact{Schema: 1, Cluster: base.Cluster, Owner: r.Identity.Public, Target: base.Change.PruneBase().DigestValue(), Conditions: control.PruneConditionsDigest(preview.Conditions), Preview: preview.Digest(), Tenant: current.Tenant, Registry: base.Change.RegistryID(), External: base.Change.External != nil, Items: uint32(len(preview.Items)), Retained: uint32(len(preview.Retained)), ImageBytes: preview.ImageBytes, EstimatedReclaimedBytes: preview.EstimatedReclaimedBytes, EstimateKnown: preview.EstimateKnown, Live: preview.Live, At: at}
		fact.Public = control.RegistryPrunePreviewPublicDigest(preview)
		fact.Signature = ed25519.Sign(r.commandIdentity().Private, control.RegistryPruneFactBytes(fact))
		base.Change.Prune = &control.RegistryPruneTarget{Conditions: preview.Conditions, Fact: fact}
	}
	if err != nil {
		return control.RegistryPruneView{}, err
	}
	count := len(preview.Items)
	if current.Query.Part == "retained" {
		count = len(preview.Retained)
	}
	root := base.Change.Prune.Fact.Preview
	start, end, next, err := registryclient.PrunePageRange(current.Query.Part, root, uint32(count), current.After)
	if err != nil {
		return control.RegistryPruneView{}, err
	}
	out := control.RegistryPruneView{Schema: 1, Tenant: current.Tenant, Plan: base, Page: control.RegistryPrunePage{Schema: 1, Root: root, Part: current.Query.Part, Total: uint32(count), Next: next}}
	if current.Query.Part == "items" {
		for _, item := range preview.Items[start:end] {
			out.Page.Rows = append(out.Page.Rows, control.PrunePublicItem(item))
		}
	} else {
		out.Page.Retained = append([]registryclient.PruneRetained{}, preview.Retained[start:end]...)
	}
	latest, cause := r.currentView(ctx)
	if cause != nil || latest.Local {
		return out, mydcp.ErrAdmission
	}
	current, cause = r.controlPolicy.CurrentRegistryPruneRead(latest.State, read, time.Now().Unix(), false)
	if cause != nil || !out.Valid(current, false) {
		return control.RegistryPruneView{}, mydcp.ErrAdmission
	}
	return out, nil
}

type registryPruneOwnerRequest struct {
	Read    control.RegistryPruneRead
	Results bool
}

func (r *Runtime) registryPrune(ctx context.Context, read control.RegistryPruneRead, results bool) (control.RegistryPruneView, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.RegistryPruneView{}, mydcp.ErrAdmission
	}
	current, err := r.controlPolicy.CurrentRegistryPruneRead(view.State, read, time.Now().Unix(), results)
	if err != nil {
		return control.RegistryPruneView{}, err
	}
	if current.Base.Change.OwnerKey() == r.Identity.Public {
		return r.registryPruneOwner(ctx, current, results)
	}
	peer, ok := r.Mesh.Peer(mydcp.Identity(current.Base.Change.OwnerKey()))
	if !ok || !peer.Member {
		return control.RegistryPruneView{}, mydcp.ErrAdmission
	}
	raw, _ := json.Marshal(registryPruneOwnerRequest{current, results})
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "registry-prune-owner", Input: raw})
	if err != nil || reply.Code != "ok" {
		return control.RegistryPruneView{}, mydcp.ErrAdmission
	}
	out, err := schema.Decode[control.RegistryPruneView](reply.Data)
	if err != nil || !out.Valid(current, results) {
		return control.RegistryPruneView{}, mydcp.ErrAdmission
	}
	return out, nil
}
