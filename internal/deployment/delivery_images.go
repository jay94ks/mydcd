// SPDX-License-Identifier: Apache-2.0

package deployment

// DeliveryImagePlan is an immutable view of a retained plan, not a new grant
// or execution. Steps() returns owned values as in ordinary Inventory reads.
type DeliveryImagePlan struct {
	Kind, Operation, Commit string
	Plan                    Blueprint
}

// ImagePlans includes the source candidate and positively retained continuity
// plans. A paused/failed request does not by itself release those references.
func (d Delivery) ImagePlans() []DeliveryImagePlan {
	var result []DeliveryImagePlan
	add := func(kind string, selection *deliverySelection) {
		if selection != nil {
			result = append(result, DeliveryImagePlan{Kind: kind, Operation: selection.Operation, Commit: selection.Candidate.Artifact.Commit, Plan: Blueprint{selection.Candidate.Plan}})
		}
	}
	if d.d.Candidate != nil {
		result = append(result, DeliveryImagePlan{Kind: "cd-candidate", Commit: d.d.Candidate.Artifact.Commit, Plan: Blueprint{d.d.Candidate.Plan}})
	}
	add("cd-running", d.d.Running)
	add("cd-last-success", d.d.LastSuccess)
	add("cd-last-failure", d.d.LastFailure)
	if plan, ok := d.TransitionPlan(); ok {
		result = append(result, DeliveryImagePlan{Kind: "cd-transition", Operation: d.d.Transition.Selection.Operation, Plan: plan})
	}
	return result
}
