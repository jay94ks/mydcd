// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// Only the intended field's authority/goal/lifetime belongs to this CAS. Fresh
// health reports, source-read bookkeeping and unrelated apps are not edits to
// that intent. The reducer still checks current permissions and idle state.
func appFieldTarget(s state.State, apps Apps, entry appEntry, path []string) [32]byte {
	if entry.Delivery == nil || !deployment.AllowedAppOverride(path) {
		return [32]byte{}
	}
	d := *entry.Delivery
	scope := entry.Inventory.Scope()
	var target struct {
		Origin                           UserOperation
		Sync                             *AppDeliverySync
		Down                             *UserOperation
		Path                             []string
		Policy                           deployment.DeliveryDeclaration
		PolicyRevision, OverrideRevision uint64
		Paused, Quiescent                bool
		Candidate, Running               *deployment.DeliverySelection
		Transition                       *deployment.DeliveryTransition
		Operation, Status                string
		Plan                             [32]byte
		Task                             state.Object
		Claim                            *struct {
			Result                  state.Result
			Command, Binding, Owner [32]byte
			Node                    string
			Removed, Retained       bool
		}
		Replicas []appFieldReplica `json:",omitempty"`
	}
	target.Origin, target.Sync, target.Down, target.Path = entry.Origin, entry.Sync, entry.Down, path
	target.Policy, target.PolicyRevision, target.OverrideRevision = d.Policy(), d.PolicyRevision(), d.OverrideRevision()
	target.Paused, target.Quiescent = d.Paused(), entry.Inventory.Quiescent()
	if v, ok := d.CandidateSelection(); ok {
		target.Candidate = &v
	}
	if v, ok := d.Selection(); ok {
		target.Running = &v
	}
	if v, ok := d.Transition(); ok {
		target.Transition = &v
	}
	if e, ok := entry.Inventory.Execution(); ok {
		target.Operation, target.Status, target.Plan = e.ActiveOperation(), e.Status(), e.Blueprint().Digest()
	}
	if blueprint, ok := d.CandidateBlueprint(); ok {
		instances, err := blueprint.ServiceInstances(path[1])
		if err != nil {
			return [32]byte{}
		}
		if len(instances) > 1 || len(instances) == 1 && instances[0].Ordinal != 0 {
			for _, instance := range instances {
				key := deployment.ResourceKey("task", scope.Tenant, scope.App, instance.ResourceID())
				row := appFieldReplica{Key: key, Task: s.Object(key)}
				for _, claim := range entry.Inventory.Claims() {
					if claim.Step.Key != key {
						continue
					}
					row.Result, row.Command, row.Owner, row.Node, row.Removed, row.Retained = claim.Result, state.Digest(claim.Command), claim.Step.Owner, claim.Step.Node, claim.Removed, claim.Retained
					if binding, ok := apps.Binding(deployment.ObjectRef{Key: key, Generation: claim.Result.Generation, Revision: claim.Result.Revision}); ok {
						row.Binding = binding.Digest()
					}
					break
				}
				target.Replicas = append(target.Replicas, row)
			}
			slices.SortFunc(target.Replicas, func(a, b appFieldReplica) int { return strings.Compare(a.Key, b.Key) })
		}
	}
	key := deployment.ResourceKey("task", scope.Tenant, scope.App, path[1])
	target.Task = s.Object(key)
	for _, claim := range entry.Inventory.Claims() {
		if claim.Step.Key != key {
			continue
		}
		target.Claim = &struct {
			Result                  state.Result
			Command, Binding, Owner [32]byte
			Node                    string
			Removed, Retained       bool
		}{Result: claim.Result, Command: state.Digest(claim.Command), Owner: claim.Step.Owner, Node: claim.Step.Node, Removed: claim.Removed, Retained: claim.Retained}
		ref := deployment.ObjectRef{Key: key, Generation: claim.Result.Generation, Revision: claim.Result.Revision}
		if binding, ok := apps.Binding(ref); ok {
			target.Claim.Binding = binding.Digest()
		}
		break
	}
	raw, err := json.Marshal(target)
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(append([]byte("mydc-app-field-target-1\x00"), raw...))
}

type appFieldReplica struct {
	Key                     string
	Task                    state.Object
	Result                  state.Result
	Command, Binding, Owner [32]byte
	Node                    string
	Removed, Retained       bool
}
