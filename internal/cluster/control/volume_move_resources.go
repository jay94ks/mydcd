// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
)

func addDemand(a, b workload.Resources) (workload.Resources, error) {
	if b.CPU > ^uint64(0)-a.CPU || b.Memory > ^uint64(0)-a.Memory {
		return a, ErrCatalog
	}
	return workload.Resources{CPU: a.CPU + b.CPU, Memory: a.Memory + b.Memory}, nil
}

// moveUsage is derived from accepted intents. It never creates a fake native
// object/generation or removes source budget before its real Goal is settled.
func (r ResourceProjection) moveUsage(tenant, node string) (workload.Resources, error) {
	var total workload.Resources
	for _, held := range r.MoveHolds {
		if held.Demand.Node != node || tenant != "" && held.Scope.Tenant != tenant {
			continue
		}
		var err error
		total, err = addDemand(total, held.Demand.Need)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (p Policy) projectMoveResources(s state.State, apps Apps, v Volumes, out *ResourceProjection) error {
	seenDrainGroups := map[string]bool{}
	for _, job := range v.Moves() {
		_, move, ok := v.Move(job.Selection())
		if !ok {
			return ErrCatalog
		}
		if !movePending(move) || job.App == nil || job.App.Target == nil {
			continue
		}
		if job.Origin.Change.Action == "drain-node" {
			key := job.Origin.RequestID + "/" + job.Binding.Scope.Tenant + "/" + job.Binding.Scope.App
			if seenDrainGroups[key] {
				continue
			}
			seenDrainGroups[key] = true
		}
		var q VolumeMoveBegin
		if moveBeginForJob(job, &q) != nil {
			return ErrCatalog
		}
		b, err := p.frozenMoveBlueprint(apps, job.Origin, q)
		if err != nil {
			return err
		}
		demands, err := b.ResourceDemands()
		if err != nil {
			return err
		}
		// Borrowed managed sources remain the exact accepted references;
		// retaining capacity must not allow their replacement underneath a move.
		ctx := deployment.PlanningContext{Cluster: p.Cluster, Networks: out.Resources.Networks, Current: s.Objects(""), Nodes: map[string]deployment.PlanningNode{}}
		for _, step := range b.Steps() {
			if step.Kind != "network-ref" {
				continue
			}
			var ref deployment.NetworkReference
			if canonical(step.Goal, &ref) != nil || ref.Tenant != b.Scope().Tenant || ref.Node != step.Node || ref.Owner != step.Owner {
				return ErrCatalog
			}
			ctx.Nodes[ref.Node] = deployment.PlanningNode{Key: ref.Owner}
			if ref.CheckRetained(ctx) != nil {
				return ErrCatalog
			}
		}
		consumers, err := b.NetworkConsumers()
		if err != nil {
			return err
		}
		out.MoveConsumers = append(out.MoveConsumers, consumers...)
		retiring := addressRetirement(s, apps, job)
		for _, demand := range demands {
			if err := admitMoveAddresses(*out, b.Scope(), demand, retiring); err != nil {
				return err
			}
			if current, exists := out.Goals[demand.Key]; exists && demand.Matches(current.Goal) && current.Goal.Tenant == b.Scope().Tenant && current.Goal.App == b.Scope().App && current.Goal.Deployment == b.Scope().Deployment {
				// CPU/network/address accounting remains with the existing Goal
				// until deletion. Ingress releases ports at signed Gone, so its
				// accepted future demand must take over at that boundary.
				if demand.Ingress == nil || current.Goal.Lifecycle == nil || !current.Goal.Lifecycle.Released() {
					continue
				}
			}
			held := deployment.PlannedResource{Origin: job.Digest(), Scope: b.Scope(), Demand: demand}
			if n := demand.Network; n != nil {
				for _, current := range out.Resources.Networks.AllNetworks() {
					if networksOverlap(*n, current) {
						return ErrCatalog
					}
				}
				for _, prior := range out.MoveHolds {
					if prior.Demand.Network != nil && networksOverlap(*n, *prior.Demand.Network) {
						return ErrCatalog
					}
				}
			}
			out.MoveHolds = append(out.MoveHolds, held)
		}
	}
	for _, limit := range out.Resources.Quotas.Limits() {
		used, err := out.Resources.Quotas.Usage(limit.Tenant, limit.Node)
		if err != nil {
			return err
		}
		held, err := out.moveUsage(limit.Tenant, limit.Node)
		if err != nil {
			return err
		}
		total, err := addDemand(used, held)
		if err != nil || total.CPU > limit.Capacity.CPU || total.Memory > limit.Capacity.Memory {
			return ErrCatalog
		}
		count := out.Resources.Networks.ReservedCount(limit.Tenant, limit.Node)
		for _, hold := range out.MoveHolds {
			if hold.Demand.Network != nil && hold.Demand.Node == limit.Node && (limit.Tenant == "" || limit.Tenant == hold.Scope.Tenant) {
				count++
			}
		}
		if count > limit.Networks {
			return ErrCatalog
		}
	}
	// Every held node needs both explicit limits, even for zero CPU network holds.
	for _, held := range out.MoveHolds {
		for _, tenant := range []string{"", held.Scope.Tenant} {
			limit, ok := out.Resources.Quotas.Limit(tenant, held.Demand.Node)
			if !ok || !out.Resources.Quotas.SameOwner(held.Demand.Node, limit.Owner, held.Demand.Owner) {
				return ErrCatalog
			}
		}
	}
	return nil
}

func networksOverlap(a, b tenancy.Network) bool {
	return slices.ContainsFunc(a.Pools, func(left tenancy.Subnet) bool {
		return slices.ContainsFunc(b.Pools, func(right tenancy.Subnet) bool { return left.Prefix.Overlaps(right.Prefix) })
	})
}

// Admit against the one real Book and all earlier accepted desired demands.
// A future revision may retain its own old attachment through cold retirement,
// Its signed, positively stopped retirement can retain the future reservation
// after Goal deletion. This never returns or grants the original Book slot.
func admitMoveAddresses(out ResourceProjection, scope deployment.AppScope, demand deployment.ResourceDemand, retiring *moveAddressRetirement) error {
	for _, address := range demand.Addresses {
		if actual, found := out.Addresses.AllocationAt(address.Address); found {
			source, current := out.AddressSources[address.Address.String()]
			goal, exists := out.Goals[source.Key]
			pool, known := out.Addresses.Pool(actual.Pool)
			sameCurrent := current && exists && source.Generation != 0 && source.Revision >= source.Generation && source.Key == demand.Key && source.Generation == actual.Generation && goal.Goal.Tenant == scope.Tenant && goal.Goal.App == scope.App && goal.Goal.Deployment == scope.Deployment && goal.Goal.Node == demand.Node && out.Resources.Quotas.SameOwner(demand.Node, goal.Goal.Owner, demand.Owner)
			rawOwner, ownerErr := hex.DecodeString(actual.Owner)
			var packetOwner [32]byte
			if ownerErr == nil && len(rawOwner) == 32 {
				copy(packetOwner[:], rawOwner)
			}
			if !known || ownerErr != nil || len(rawOwner) != 32 || actual.Endpoint != address.Endpoint || !out.Resources.Quotas.SameOwner(demand.Node, packetOwner, demand.Owner) || pool.Network != address.Network || !sameCurrent && !retiring.holds(scope, demand, address, actual) {
				return ErrCatalog
			}
		}
		for _, prior := range out.MoveHolds {
			if slices.ContainsFunc(prior.Demand.Addresses, func(a deployment.StaticAddressDemand) bool { return a.Address == address.Address }) {
				return ErrCatalog
			}
		}
	}
	return nil
}
