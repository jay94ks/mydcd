// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"strconv"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/schema"
)

// This is a read-only view of the ONE accepted move's existing retirement.
// It is not an allocation, replacement Goal, or permission to activate a Task.
type moveAddressRetirement struct {
	state state.State
	view  deployment.RetirementView
}

func addressRetirement(s state.State, apps Apps, job VolumeMove) *moveAddressRetirement {
	entry, ok := apps.entries[appKey(job.Binding.Scope.Tenant, job.Binding.Scope.App)]
	if !ok || entry.Down == nil || !bytes.Equal(OperationBytes(*entry.Down), OperationBytes(job.Origin)) || !bytes.Equal(entry.Down.Signature, job.Origin.Signature) {
		return nil
	}
	want, _, err := moveAppRetirement(job.Origin, moveScope(job))
	retiring, ok := entry.Inventory.Retirement()
	id := want.Operation
	if entry.Delivery != nil {
		transition, pending := entry.Delivery.Transition()
		if !pending || transition.Mode != deployment.DeliveryDown || transition.Selection.Operation != want.Operation {
			return nil
		}
		id = transition.Retirement
	}
	if err != nil || !ok || !retiring.Down || retiring.ID != id {
		return nil
	}
	return &moveAddressRetirement{state: s, view: retiring}
}

func (r *moveAddressRetirement) holds(scope deployment.AppScope, demand deployment.ResourceDemand, address deployment.StaticAddressDemand, actual network.Allocation) bool {
	if r == nil || demand.Kind != "task" {
		return false
	}
	o := r.state.Object(demand.Key)
	if o.Present || o.Generation != actual.Generation {
		return false
	}
	for _, target := range r.view.Targets {
		c := target.Original
		if c.Step.Key != demand.Key || c.Step.Kind != "task" || c.Step.Node != demand.Node || c.Step.Owner != demand.Owner || c.Result.Code != state.Applied || c.Result.Generation != actual.Generation || c.Result.Revision < c.Result.Generation || target.Drain == nil || target.Drain.Result == nil || target.Drain.Result.Code != state.Applied || target.Proof == nil || target.Proof.Result == nil || target.Proof.Result.Code != state.Applied || target.Proof.Result.Generation != actual.Generation || o.Revision <= target.Proof.Result.Revision {
			continue
		}
		if schema.VerifyGone(c.Step.Owner, scope.Cluster, c.Step.Key, c.Result.Generation, []byte(target.Drain.Command.Value), target.Gone) != nil {
			continue
		}
		var goal deployment.GoalCommand
		var service deployment.ComposeService
		if canonical([]byte(c.Command.Value), &goal) != nil || goal.Schema != 1 || goal.Cluster != scope.Cluster || goal.Kind != "task" || goal.Tenant != scope.Tenant || goal.App != scope.App || goal.Deployment != scope.Deployment || goal.Node != demand.Node || goal.Owner != demand.Owner || canonical(goal.Config, &service) != nil {
			continue
		}
		for alias, attachment := range service.Networks {
			for family, ip := range []string{attachment.IPv4, attachment.IPv6} {
				if ip != "" && ip == address.Address.String() && c.Step.Key+"/"+alias+"/"+strconv.Itoa(family) == address.Endpoint {
					return true
				}
			}
		}
	}
	return false
}
