// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// AppInputDigest binds an explicit move's public input separately from the CAS
// bases that must change after positive source retirement/owner publication.
func (b Blueprint) AppInputDigest() [32]byte {
	if b.CheckAppInput() != nil {
		return [32]byte{}
	}
	raw, err := marshalApp(b.d.Input)
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(raw)
}

func (d Delivery) movePolicy(input Compose) bool {
	return input.Sfc.Delivery != nil && bytes.Equal(goal(*input.Sfc.Delivery), goal(d.d.Policy))
}

// PlanMoved retains the registered principal/source policy while using the
// ordinary explicit Volume preview compiler. Moving an overridden service to
// another owner requires returning that field first, not expanding its grant.
func (d Delivery) PlanMoved(input Compose, c access.Catalog, ctx PlanningContext, move VolumeMovePlacement) (Blueprint, error) {
	if !d.scope(c, ctx) || d.d.Paused || !d.overrideIdle() || !d.movePolicy(input) {
		return Blueprint{}, ErrInputs
	}
	input, err := mergeLocalServices(input, d.d.LocalServices, AppScope{Tenant: ctx.Tenant, App: ctx.Project, Deployment: ctx.Deployment})
	if err != nil {
		return Blueprint{}, err
	}
	input, err = applyDeliveryOverrides(input, d.d.Overrides)
	if err != nil {
		return Blueprint{}, err
	}
	b, err := CompileAppVolumeMove(input, c, ctx, move)
	if err != nil {
		return b, err
	}
	if err := checkOverrideOwners(b, d.d.Overrides); err != nil {
		return Blueprint{}, err
	}
	return b, nil
}

// StartMoved is the same retained-volume handoff consumed by ordinary app
// moves. The control transaction also verifies the signed move and publishes
// the real owner/Arm. This method never manufactures that Volume state.
func (d Delivery) StartMoved(expected uint64, c access.Catalog, ctx PlanningContext, b Blueprint, binding volumes.Binding, actor, id, submitter string, epoch uint64) (Delivery, error) {
	return d.StartMovedGroup(expected, c, ctx, b, []volumes.Binding{binding}, actor, id, submitter, epoch)
}
func (d Delivery) StartMovedGroup(expected uint64, c access.Catalog, ctx PlanningContext, b Blueprint, bindings []volumes.Binding, actor, id, submitter string, epoch uint64) (Delivery, error) {
	if expected != d.Revision() || !d.scope(c, ctx) || !d.movePolicy(b.d.Input) || b.d.Actor != d.Principal() || b.CheckAppInput() != nil || !d.transitionAccess(c, actor) {
		return d, ErrInputs
	}
	n := d
	var err error
	if t, pending := d.Transition(); pending {
		if t.Mode != DeliveryDown || t.Phase != "ready" {
			return d, ErrInputs
		}
		n, err = d.ContinueTransition(d.Revision(), c, ctx, actor)
		if err != nil {
			return d, err
		}
	}
	if !n.d.Paused || !n.Inventory().Quiescent() || n.usedTransitionID(id) {
		return d, ErrInputs
	}
	if err := checkOverrideOwners(b, n.d.Overrides); err != nil {
		return d, err
	}
	a := n.Inventory()
	updated, err := a.BeginMovedGroup(a.Revision(), c, ctx, b, bindings, id, submitter, epoch)
	if err != nil {
		return d, err
	}
	body, err := marshalApp(b.d.Input)
	if source := b.OriginalDocument(); source != nil {
		body = source.Body
	}
	if err != nil {
		return d, err
	}
	candidate := deliveryCandidate{Overrides: ownDeliveryOverrides(n.d.Overrides), OverrideRevision: n.d.OverrideRevision, Artifact: deliveryArtifact{Original: b.d.Document != nil, Kind: "file", Digest: sha256.Sum256(body), Body: body}, Plan: b.d, PolicyRevision: n.d.PolicyRevision, InventoryRevision: a.Revision()}
	candidate.LocalServices, candidate.LocalRevision = ownLocalServices(n.d.LocalServices), n.d.LocalRevision
	candidate.ID = candidateID(candidate)
	n, err = n.clone()
	if err != nil {
		return d, err
	}
	n.d.Inventory, n.d.Running = updated.d, &deliverySelection{Candidate: candidate, Operation: id, Submitter: submitter, Epoch: epoch}
	n.d.Paused, n.d.Approval = false, nil
	n.floors(c, ctx)
	if n.validate() != nil {
		return d, ErrInputs
	}
	return n, nil
}
