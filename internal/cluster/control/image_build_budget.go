// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
)

// The accepted begin is the budget reservation. Cancel/uncertain retain it;
// only the accepted terminal owner closure returns it. This view is shared by
// app admission, quota changes and registry starts, never persisted separately.
func (p Policy) imageBuildReservations(s state.State) ([]tenancy.Reservation, error) {
	b, err := p.ImageBuilds(s)
	if err != nil {
		return nil, err
	}
	var out []tenancy.Reservation
	for _, row := range b.Jobs {
		run := row.Run
		if run.Phase == "queued" || run.Terminal() {
			continue
		}
		spec := run.Spec
		out = append(out, tenancy.Reservation{
			Key:    "workload/imagebuild/" + spec.Tenant + "/" + spec.ID + "/builder",
			Tenant: spec.Tenant, Node: spec.Scope.Root.Node, Owner: spec.Scope.Root.Key,
			Generation: 1, Revision: run.Revision, Draining: run.Cancel,
			Need: workload.Resources{CPU: uint64(spec.Policy.CPUMillis) * 1_000_000, Memory: uint64(spec.Policy.MemoryBytes)},
		})
	}
	for _, row := range b.CachePrunes {
		if !row.Pending() || row.State == "queued" {
			continue
		}
		q, err := row.Change()
		if err != nil {
			return nil, err
		}
		source, found := b.Job(q.Tenant, row.Source)
		if !found {
			return nil, ErrCatalog
		}
		spec := source.Run.Spec
		limits, err := row.Limits(spec)
		if err != nil {
			return nil, err
		}
		out = append(out, tenancy.Reservation{Key: "workload/imagebuild-cache-prune/" + q.Tenant + "/" + q.ID + "/builder", Tenant: q.Tenant, Node: q.Node, Owner: spec.Scope.Root.Key, Generation: 1, Revision: row.Revision, Need: workload.Resources{CPU: uint64(limits.CPUMillis) * 1_000_000, Memory: uint64(limits.MemoryBytes)}})
	}
	return out, nil
}

func (p Policy) imageBuildBudgetAvailable(s state.State, work ImageBuildJobWork) bool {
	if work.Run.Phase != "queued" {
		return true // already reserved, including unknown/cancelled originals
	}
	spec := work.Run.Spec
	return p.imageBuildNeedAvailable(s, spec.Tenant, spec.Scope.Root.Node, spec.Scope.Root.Key, spec.Policy.CPUMillis, spec.Policy.MemoryBytes)
}

func (p Policy) imageBuildNeedAvailable(s state.State, tenantID, node string, owner [32]byte, cpu uint64, memory int64) bool {
	projection, err := p.ProjectResources(s)
	if err != nil {
		return false
	}
	need := workload.Resources{CPU: cpu * 1_000_000, Memory: uint64(memory)}
	for _, tenant := range []string{"", tenantID} {
		limit, ok := projection.Resources.Quotas.Limit(tenant, node)
		used, err := projection.Resources.Quotas.Usage(tenant, node)
		if !ok || limit.Owner != owner || err != nil || used.CPU > limit.Capacity.CPU || used.Memory > limit.Capacity.Memory || need.CPU > limit.Capacity.CPU-used.CPU || need.Memory > limit.Capacity.Memory-used.Memory {
			return false
		}
	}
	return true
}
