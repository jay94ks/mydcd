// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
)

type DeliveryStatus struct {
	Rejection                                               *CDRejection `json:",omitempty"`
	Rejected                                                bool         `json:",omitempty"`
	ApprovalActor, ApprovalReason                           string       `json:",omitempty"`
	Transition, TransitionPhase                             string       `json:",omitempty"`
	OverridePaths                                           [][]string   `json:",omitempty"`
	Source, Sync, EffectiveSync, Operation, Health          string
	Candidate, Artifact, Plan                               [32]byte
	Commit, LastSuccessCommit, ActiveOperation, SourceError string
	Changes                                                 []Change
}

// Status compares committed Desired separately from inventory ownership and
// current owner observations. Source/cache failure never turns into a deletion.
func (d Delivery) Status(c access.Catalog, ctx PlanningContext, now uint64) (DeliveryStatus, error) {
	out := DeliveryStatus{Rejected: d.Rejected(), Source: "Ready", Sync: "Unknown", Operation: "Planned", Health: "Unknown", SourceError: d.d.SourceError}
	if d.Rejected() {
		key := rejectionSource(d.d.Candidate.Artifact)
		for _, row := range d.d.Rejections {
			if row.Source == key {
				own := row
				out.Rejection = &own
				break
			}
		}
	}
	if d.d.Approval != nil {
		out.ApprovalActor = d.d.Approval.Actor
		out.ApprovalReason = d.d.Approval.Reason
	}
	if !d.scope(c, ctx) {
		return out, ErrInputs
	}
	a := d.Inventory()
	if e, ok := a.Execution(); ok {
		out.Operation = e.Status()
		out.Health = e.Health(now)
		out.ActiveOperation = e.d.Operation
		for _, stage := range e.d.Stages {
			if stage.Result != nil {
				current := ctx.Current[stage.Key]
				if !current.Present || current.Revision != stage.Result.Revision || current.Generation != stage.Result.Generation {
					out.Health = "Unknown"
					break
				}
			}
		}
	}
	if d.d.LastSuccess != nil {
		out.LastSuccessCommit = d.d.LastSuccess.Candidate.Artifact.Commit
	}
	if d.d.Paused {
		out.Operation = "Paused"
	}
	if d.d.Candidate != nil {
		candidate := d.d.Candidate
		b := Blueprint{candidate.Plan}
		out.Candidate = candidate.ID
		out.Artifact = candidate.Artifact.Digest
		out.Plan = b.Digest()
		out.Commit = candidate.Artifact.Commit
		changes, err := a.Changes(b, d.d.Policy.Sync.Prune)
		if err != nil {
			return out, err
		}
		out.Changes = changes
		out.Sync = "InSync"
		for _, step := range b.Steps() {
			if !deliveryDesiredMatches(step, b, ctx) {
				out.Sync = "OutOfSync"
				break
			}
		}
		for _, change := range changes {
			if change.Action == "Remove" {
				out.Sync = "OutOfSync"
			}
		}
		if out.Sync != "InSync" {
			out.Source = "ChangeAvailable"
		}
		if d.d.Policy.Sync.Mode == "manual" && !d.ApprovalReady(c) && (a.d.Active == nil || a.d.Active.CompletedAt != 0) && out.Sync != "InSync" && !d.d.Paused {
			out.Operation = "AwaitingApproval"
		}
	}
	if out.Rejected {
		out.Operation = "Rejected"
	}
	if d.d.SourceError != "" {
		out.Source = "SourceError"
	}
	if d.d.Candidate != nil && (d.d.Candidate.PolicyRevision != d.d.PolicyRevision || d.d.Candidate.OverrideRevision != d.d.OverrideRevision) {
		// This is the last valid input, not a result of the new registration.
		out.Sync = "Unknown"
	}
	// UI divergence from Git is different from whether the operator's
	// effective goals have already been applied. Never schedule a new rollout
	// solely to remove this intentional OutOfSync indication.
	out.EffectiveSync = out.Sync
	for _, o := range d.d.Overrides {
		out.OverridePaths = append(out.OverridePaths, append([]string(nil), o.Path...))
		out.Sync = "OutOfSync"
	}
	if t := d.d.Transition; t != nil {
		out.Transition = t.Selection.Operation
		out.TransitionPhase = t.Phase
		out.Operation = "Stopping"
		if t.Phase == "ready" {
			out.Operation = "Planned"
		}
		out.Health = "Unknown"
	}
	return out, nil
}

func deliveryDesiredMatches(step Step, b Blueprint, ctx PlanningContext) bool {
	current := ctx.Current[step.Key]
	var g GoalCommand
	if !current.Present || json.Unmarshal([]byte(current.Value), &g) != nil || g.Lifecycle != nil || g.Cluster != b.d.Cluster || g.Tenant != b.d.Tenant || g.App != b.d.App || g.Deployment != b.d.Deployment || g.Kind != step.Kind || g.Owner != step.Owner || g.Node != step.Node || !bytes.Equal(g.Config, step.Goal) || !bytes.Equal(goal(g.Activation), goal(step.Activation)) || len(g.Dependencies) != len(step.Dependencies) {
		return false
	}
	for i, dep := range step.Dependencies {
		source := ctx.Current[dep.Key]
		ref := ObjectRef{dep.Key, source.Revision, source.Generation}
		for _, stable := range step.StableDNS {
			if stable.Key == dep.Key && stable.Generation == source.Generation {
				ref = stable
			}
		}
		if !source.Present || g.Dependencies[i] != ref {
			return false
		}
	}
	return true
}
