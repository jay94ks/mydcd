// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/moby/moby/client"
)

// Existing manager journals and SDK identities remain the native authority.
// The frozen exact-key set also covers legacy/managed keys outside app prefixes.
func tenantResourceKey(key, tenant string, original map[string]bool) bool {
	if original[key] {
		return true
	}
	for _, prefix := range []string{"network/bridge/", "network/reference/", "network/tun/", "network/dns/", "network/route/", "workload/volume/", "workload/vault/", "workload/inputs/", "workload/task/", "workload/registry/", "workload/cd/", "ingress/app/", "volume/", "fixed-volume/", "image-build/", "image-build-cache-prune/"} {
		if strings.HasPrefix(key, prefix+tenant+"/") {
			return true
		}
	}
	return false
}

func (r *Runtime) tenantLocalActivity(ctx context.Context, tenant string, retirement access.TenantRetirement) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	original := map[string]bool{}
	for _, target := range retirement.Targets {
		if target.Owner == r.Identity.Public && target.Key != "" {
			original[target.Key] = true
		}
	}
	// A missing manager/journal cannot stand in for original native closure.
	for _, target := range retirement.Targets {
		if target.Owner != r.Identity.Public {
			continue
		}
		var read func(string) (reconcile.Record, error)
		switch target.Kind {
		case "task":
			if r.workload == nil {
				return activity, control.ErrCatalog
			}
			read = r.workload.View
		case "bridge":
			if r.network == nil {
				return activity, control.ErrCatalog
			}
			read = r.network.View
		case "tunnel":
			if r.tunnel == nil {
				return activity, control.ErrCatalog
			}
			read = r.tunnel.manager.View
		case "volume", "volume-create":
			if strings.HasPrefix(target.Key, "volume/") || strings.HasPrefix(target.Key, "fixed-volume/") {
				if r.nativeVolumes == nil {
					return activity, control.ErrCatalog
				}
				read = r.nativeVolumes.View
			}
		case "ingress":
			if r.ingress == nil {
				return activity, control.ErrCatalog
			}
		case "dns":
			if r.dnsOwner() == nil {
				return activity, control.ErrCatalog
			}
		}
		if read != nil {
			record, err := read(target.Key)
			if err != nil {
				return activity, err
			}
			if record.State.Pending != nil || record.State.Applied.Present || len(record.Consumers) > 0 {
				activity.Resources++
			}
		}
	}
	journal := func(keys []string, read func(string) (reconcile.Record, error)) error {
		for _, key := range keys {
			if !tenantResourceKey(key, tenant, original) {
				continue
			}
			record, err := read(key)
			if err != nil {
				return err
			}
			if record.State.Pending != nil || record.State.Applied.Present {
				activity.Resources++
			}
			activity.Leases += uint32(len(record.Consumers))
		}
		return nil
	}
	add := func(next lifecycle.Activity, err error) error {
		if err != nil {
			return err
		}
		activity, err = activity.Add(next)
		return err
	}
	if r.network != nil {
		if err := journal(r.network.Keys(), r.network.View); err != nil {
			return activity, err
		}
	}
	if r.workload != nil {
		if err := journal(r.workload.Keys(), r.workload.View); err != nil {
			return activity, err
		}
	}
	if r.nativeVolumes != nil {
		if err := journal(r.nativeVolumes.Keys(), r.nativeVolumes.View); err != nil {
			return activity, err
		}
	}
	if r.activations != nil {
		if err := add(r.activations.TenantActivity(tenant)); err != nil {
			return activity, err
		}
	}
	if r.projections != nil {
		if err := add(r.projections.TenantActivity(tenant)); err != nil {
			return activity, err
		}
	}
	if owner := r.dnsOwner(); owner != nil {
		if err := add(owner.TenantActivity(tenant)); err != nil {
			return activity, err
		}
	}
	if r.ingress != nil {
		for _, key := range r.ingress.Keys() {
			if !tenantResourceKey(key, tenant, original) {
				continue
			}
			observed, err := r.ingress.Observe(key)
			if err != nil {
				return activity, err
			}
			if !observed.Gone {
				activity.Resources++
			}
			activity.Flows += uint32(observed.Requests)
		}
	}
	if r.tunnel != nil {
		if err := journal(r.tunnel.manager.Keys(), r.tunnel.manager.View); err != nil {
			return activity, err
		}
	}
	// These counters cover finite in-flight artifact IO, not other tenants'
	// running services or retained immutable cache bytes.
	if r.checkerSources != nil {
		if err := add(r.checkerSources.TenantActivity(tenant)); err != nil {
			return activity, err
		}
	}
	if r.checkerCompiler != nil {
		if err := add(r.checkerCompiler.TenantActivity(tenant)); err != nil {
			return activity, err
		}
	}
	if r.imageBuildNative != nil {
		if err := add(r.imageBuildNative.TenantActivity(tenant)); err != nil {
			return activity, err
		}
	} else if r.reports != nil {
		if err := add(imagebuild.StoredTenantActivity(r.reports, engine.Owner(r.controlPolicy.Cluster, r.Identity.Public), tenant)); err != nil {
			return activity, err
		}
	}
	if err := add(r.tenantImageBuildInputActivity(tenant)); err != nil {
		return activity, err
	}
	if r.vaultApprovals != nil {
		count, err := tenantPendingJournal(r.vaultApprovals.Keys(), r.vaultApprovals.Read, func(raw string) (bool, error) {
			command, err := state.DecodeCommand([]byte(raw))
			if err != nil {
				return false, err
			}
			report, err := schema.Decode[control.VaultApprovalReport]([]byte(command.Value))
			return report.Approval.Payload.Target.Tenant == tenant || report.Approval.Payload.Target.Realm == tenant, err
		})
		if err := add(count, err); err != nil {
			return activity, err
		}
	}
	if r.volumeRestores != nil {
		count, err := tenantPendingJournal(r.volumeRestores.Keys(), r.volumeRestores.Read, func(raw string) (bool, error) {
			binding, err := schema.Decode[control.VolumeRestoreBinding]([]byte(raw))
			return binding.Target.Scope.Tenant == tenant, err
		})
		if err := add(count, err); err != nil {
			return activity, err
		}
	}
	if r.backupArtifacts != nil {
		owner := r.backupArtifacts
		if !owner.mu.TryLock() {
			activity.Resources++
		} else {
			if owner.closed {
				owner.mu.Unlock()
				return activity, control.ErrCatalog
			}
			count, err := tenantPendingJournal(owner.journal.Keys(), owner.journal.Read, func(raw string) (bool, error) {
				// Each producer's stored intent is canonical and validated when
				// its existing owner opens. Scope is read from that exact intent.
				var binding struct {
					Scope struct{ Tenant string }
					Job   control.VolumeMove
				}
				if err := json.Unmarshal([]byte(raw), &binding); err != nil {
					return false, err
				}
				scope := binding.Scope.Tenant
				if scope == "" {
					scope = binding.Job.Binding.Scope.Tenant
				}
				if scope == "" {
					return false, control.ErrCatalog
				}
				return scope == tenant, nil
			})
			owner.mu.Unlock()
			if err := add(count, err); err != nil {
				return activity, err
			}
		}
	}
	if !r.registryMu.TryLock() {
		activity.Resources++
	} else {
		if r.registryFailed.Load() {
			r.registryMu.Unlock()
			return activity, errors.New("registry owner requires recovery")
		}
		for _, row := range r.registryRecords {
			if row.Spec.Tenant == tenant && row.Run != nil && (row.Phase != "closed" || !row.IOClosed || !row.PinReturned) {
				activity.Writers++
			}
		}
		r.registryMu.Unlock()
	}
	// Inventory SDK objects even when a local journal is already terminal.
	// List errors are Unknown; objects from another tenant are left untouched.
	if r.docker != nil {
		filters := client.Filters{}.Add("label", "org.mydc.owner="+r.docker.Owner)
		containers, err := r.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
		if err != nil {
			return activity, err
		}
		for _, container := range containers.Items {
			if tenantResourceKey(container.Labels["org.mydc.key"], tenant, original) {
				activity.Resources++
			}
		}
		networks, err := r.docker.API.NetworkList(ctx, client.NetworkListOptions{Filters: filters})
		if err != nil {
			return activity, err
		}
		for _, network := range networks.Items {
			if tenantResourceKey(network.Labels["org.mydc.key"], tenant, original) {
				activity.Resources++
			}
		}
	}
	return activity, nil
}

// Unfinished owner evidence needs periodic observation even without native
// modules or a new FSM index (for example after a temporary IO barrier).
func (r *Runtime) tenantRetirementPending(s state.State) bool {
	users, err := r.controlPolicy.Catalog(s)
	if err != nil {
		return false
	}
	for _, tenant := range users.Tenants() {
		if tenant.Phase != access.TenantRetiring || tenant.Retirement == nil {
			continue
		}
		for _, owner := range tenant.Retirement.Owners {
			if owner.Key == r.Identity.Public && (owner.Report == nil || !owner.Report.Complete()) {
				return true
			}
		}
	}
	return false
}

// This is the existing module pass's final observation, not a delete worker or
// another queue. Explicit app/network/registry/data operations own their effects.
func (r *Runtime) reconcileTenantRetirements(ctx context.Context, local cluster.View) error {
	users, err := r.controlPolicy.Catalog(local.State)
	if err != nil {
		return err
	}
	var failed error
	for _, tenant := range users.Tenants() {
		if tenant.Phase != access.TenantRetiring || tenant.Retirement == nil {
			continue
		}
		own := false
		for _, owner := range tenant.Retirement.Owners {
			own = own || owner.Key == r.Identity.Public && (owner.Report == nil || !owner.Report.Complete())
		}
		if !own {
			continue
		}
		if err := r.observeTenantRetirement(ctx, tenant.ID); err != nil {
			failed = errors.Join(failed, err)
		}
	}
	return failed
}
func (r *Runtime) observeTenantRetirement(ctx context.Context, tenant string) error {
	if !r.inputLife.TryLock() {
		return nil
	}
	defer r.inputLife.Unlock()
	if !r.vaultApprovalLife.TryLock() {
		return nil
	}
	defer r.vaultApprovalLife.Unlock()
	if !r.life.TryLock() {
		return nil
	}
	defer r.life.Unlock()
	if r.closed || ctx.Err() != nil {
		return ctx.Err()
	}
	raw, _ := json.Marshal(control.TenantID{ID: tenant})
	reply, err := r.appCall(ctx, "tenant-retirement-work", raw)
	if err != nil {
		return err
	}
	work, err := schema.Decode[control.TenantRetirementWork](reply.Data)
	if err != nil || work.Schema != 1 || work.Cluster != r.controlPolicy.Cluster || work.Owner != r.Identity.Public || work.Tenant != tenant || work.Index != reply.CommandIndex {
		return control.ErrCatalog
	}
	if work.Complete || work.Remaining != 0 {
		return nil
	}
	view, err := r.Engine().ReadAtLeast(ctx, work.Index)
	if err != nil {
		return err
	}
	users, err := r.controlPolicy.Catalog(view.State)
	if err != nil {
		return err
	}
	current, ok := users.Tenant(tenant)
	if !ok || current.Phase != access.TenantRetiring || current.Retirement == nil || view.State.Object(control.CatalogKey).Revision != work.RootRevision || view.State.ModuleEpoch() != work.Epoch {
		return control.ErrCatalog
	}
	original := current.Retirement
	if original.Operation != work.Operation || original.StartedRevision != work.StartedRevision || original.InventoryHash != work.InventoryHash || original.OwnersHash != work.OwnersHash {
		return control.ErrCatalog
	}
	before, err := r.tenantLocalActivity(ctx, tenant, *original)
	if err != nil {
		return err
	}
	if before.Resources != 0 || before.Flows != 0 || before.Writers != 0 || before.CDJobs != 0 {
		return nil // includes actual Docker objects, not just terminal journals
	}
	if err := r.collectTenantImageBuildCaches(ctx, view.State, tenant); err != nil {
		return err
	}
	activity, err := r.tenantLocalActivity(ctx, tenant, *original)
	if err != nil || !activity.Empty() {
		return err
	}
	node := ""
	for _, owner := range original.Owners {
		if owner.Key == r.Identity.Public {
			node = owner.Node
		}
	}
	proof := access.TenantReport{Cluster: work.Cluster, Tenant: tenant, Operation: work.Operation, Node: node, Owner: r.Identity.Public, StartedRevision: work.StartedRevision, Sequence: work.Sequence, InventoryHash: work.InventoryHash, OwnersHash: work.OwnersHash, Quiesced: true}
	proof.Signature = ed25519.Sign(r.Identity.Private, access.TenantReportBytes(proof))
	report := control.TenantRetirementReport{Schema: 1, Epoch: work.Epoch, RootRevision: work.RootRevision, Proof: proof}
	raw, err = json.Marshal(report)
	if err != nil {
		return err
	}
	answer, err := r.appCall(ctx, "tenant-retirement-report", raw)
	if err != nil {
		return err
	}
	if answer.Committed == nil || answer.Committed.Result.Code != state.Applied {
		return errors.New("tenant retirement report was not committed")
	}
	return nil
}

// Count only unresolved native IO/reference journals. Immutable data-only
// artifacts remain governed by the shared explicit retention/delete contract.
func tenantPendingJournal(keys []string, read func(string) (reconcile.Record, error), belongs func(string) (bool, error)) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	for _, key := range keys {
		record, err := read(key)
		if err != nil {
			return activity, err
		}
		if record.State.Pending == nil && len(record.Consumers) == 0 {
			continue
		}
		spec := record.State.Applied.Spec
		if spec == "" {
			spec = record.State.Desired.Spec
		}
		if record.State.Pending != nil && record.State.Pending.Target.Spec != "" {
			spec = record.State.Pending.Target.Spec
		}
		if spec == "" && record.Checkpoint != nil {
			spec = record.Checkpoint.Target.Spec
		}
		if spec == "" {
			return activity, control.ErrCatalog
		}
		selected, err := belongs(spec)
		if err != nil {
			return activity, err
		}
		if !selected {
			continue
		}
		if record.State.Pending != nil {
			activity.Resources++
		}
		activity.Leases += uint32(len(record.Consumers))
	}
	return activity, nil
}
