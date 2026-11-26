// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/sha256"
	"github.com/jay94ks/mydcd/internal/access"
)

// StartRelocated keeps the same CD principal, source policy, field ownership
// and original Inventory. The explicit drain chooses only the frozen placement
// candidate; ordinary replacement still waits for each original closure.
func (d Delivery) StartRelocated(expected uint64, c access.Catalog, ctx PlanningContext, b Blueprint, actor, id, submitter string, epoch uint64) (Delivery, error) {
	if expected != d.Revision() || !d.scope(c, ctx) || !d.overrideIdle() || !d.movePolicy(b.d.Input) || b.d.Actor != d.Principal() || b.CheckAppInput() != nil || !d.transitionAccess(c, actor) || d.usedTransitionID(id) {
		return d, ErrInputs
	}
	if err := checkOverrideOwners(b, d.d.Overrides); err != nil {
		return d, err
	}
	inventory, err := d.Inventory().Begin(d.Inventory().Revision(), c, ctx, b, id, submitter, epoch, false)
	if err != nil {
		return d, err
	}
	body, err := marshalApp(b.d.Input)
	if err != nil {
		return d, err
	}
	candidate := deliveryCandidate{Overrides: ownDeliveryOverrides(d.d.Overrides), OverrideRevision: d.d.OverrideRevision, Artifact: deliveryArtifact{Kind: "file", Digest: sha256.Sum256(body), Body: body}, Plan: b.d, PolicyRevision: d.d.PolicyRevision, InventoryRevision: d.Inventory().Revision(), LocalServices: ownLocalServices(d.d.LocalServices), LocalRevision: d.d.LocalRevision}
	candidate.ID = candidateID(candidate)
	next, err := d.clone()
	if err != nil {
		return d, err
	}
	next.d.Inventory = inventory.d
	next.d.Running = &deliverySelection{Candidate: candidate, Operation: id, Submitter: submitter, Epoch: epoch}
	next.d.Approval = nil
	next.floors(c, ctx)
	if next.validate() != nil {
		return d, ErrInputs
	}
	return next, nil
}
