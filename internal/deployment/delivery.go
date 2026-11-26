// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

type deliveryCandidate struct {
	LocalServices                     *LocalServicesDocument `json:",omitempty"`
	LocalRevision                     uint64                 `json:",omitempty"`
	Overrides                         []DeliveryOverride     `json:",omitempty"`
	OverrideRevision                  uint64                 `json:",omitempty"`
	Artifact                          deliveryArtifact
	Plan                              blueprintRecord
	PolicyRevision, InventoryRevision uint64
	ID                                [32]byte
}
type deliveryApproval struct {
	Reason          string `json:",omitempty"`
	Explicit        bool   `json:",omitempty"`
	Candidate       [32]byte
	Actor           string
	CatalogRevision uint64
}
type deliverySelection struct {
	Candidate            deliveryCandidate
	Operation, Submitter string
	Epoch                uint64
}
type deliveryRecord struct {
	LocalServices                           *LocalServicesDocument      `json:",omitempty"`
	LocalRevision                           uint64                      `json:",omitempty"`
	Rejections                              []CDRejection               `json:",omitempty"`
	Approvers                               []string                    `json:",omitempty"`
	CompactedSuccess                        *OperationSummary           `json:",omitempty"`
	CompactedFailure                        *OperationSummary           `json:",omitempty"`
	Transition                              *deliveryTransition         `json:",omitempty"`
	Transitions                             []deliveryTransitionSummary `json:",omitempty"`
	Overrides                               []DeliveryOverride          `json:",omitempty"`
	OverrideRevision                        uint64                      `json:",omitempty"`
	Schema                                  uint8
	Revision, PolicyRevision, FetchSequence uint64
	CatalogFloor, NetworkFloor              uint64
	Principal                               string
	Policy                                  DeliveryDeclaration
	Inventory                               inventoryRecord
	Fetch                                   *DeliveryFetch
	Candidate                               *deliveryCandidate
	Approval                                *deliveryApproval
	Running, LastSuccess, LastFailure       *deliverySelection
	SourceError                             string
	Paused                                  bool
}

// Delivery selects immutable inputs for the SAME app Inventory/Execution.
// This shared metadata candidate must commit atomically with inventory changes.
// It performs no polling, I/O, native operation or quorum emulation.
type Delivery struct{ d deliveryRecord }

func NewDelivery(c access.Catalog, ctx PlanningContext, raw []byte) (Delivery, error) {
	if ctx.Networks.Cluster() != ctx.Cluster {
		return Delivery{}, ErrInputs
	}
	b, err := CompileAppDocument(raw, c, ctx)
	if err != nil || c.Authorize(ctx.Actor, b.d.Tenant, access.ManageCD, "") != nil {
		return Delivery{}, ErrInputs
	}
	// Reuse Compose's own defaulting instead of creating CD-specific defaults.
	normalized := b.d.Input
	if normalized.MyDC.Delivery == nil {
		normalized.MyDC.Delivery = &DeliveryDeclaration{}
		if normalized.normalize() != nil {
			return Delivery{}, ErrInputs
		}
	}
	a, err := NewInventory(ctx.Cluster, b.d.Tenant, b.d.App, b.d.Deployment)
	if err != nil {
		return Delivery{}, err
	}
	d := Delivery{deliveryRecord{Schema: 1, Revision: 1, PolicyRevision: 1, Principal: ctx.Actor, Policy: *normalized.MyDC.Delivery, Inventory: a.d, CatalogFloor: c.Revision(), NetworkFloor: ctx.Networks.Revision()}}
	candidate := deliveryCandidate{Artifact: deliveryArtifact{Original: true, Kind: "file", Digest: sha256.Sum256(raw), Body: bytes.Clone(raw)}, Plan: b.d, PolicyRevision: 1, InventoryRevision: a.Revision()}
	candidate.ID = candidateID(candidate)
	d.d.Candidate = &candidate
	return d, nil
}
func candidateID(c deliveryCandidate) [32]byte {
	c.ID = [32]byte{}
	return sha256.Sum256(append([]byte("mydc-delivery-candidate-1\x00"), goal(c)...))
}
func (d Delivery) Revision() uint64 { return d.d.Revision }

// Quiescent keeps source/transition receipts alive even when the Inventory has
// no pending native command. Idle candidates and historical selections do not
// themselves pin the request ledger.
func (d Delivery) Quiescent() bool {
	return d.d.Fetch == nil && d.d.Transition == nil && (Inventory{d.d.Inventory}).Quiescent()
}

func (d Delivery) Candidate() ([32]byte, bool) {
	if d.d.Candidate == nil {
		return [32]byte{}, false
	}
	return d.d.Candidate.ID, true
}
func (d Delivery) Inventory() Inventory {
	raw, _ := json.Marshal(d.d.Inventory)
	var i inventoryRecord
	_ = json.Unmarshal(raw, &i)
	return Inventory{i}
}
func (d Delivery) clone() (Delivery, error) {
	if d.d.Schema != 1 || d.d.Revision == ^uint64(0) {
		return d, ErrInputs
	}
	raw, err := json.Marshal(d.d)
	if err != nil {
		return d, err
	}
	var n deliveryRecord
	if json.Unmarshal(raw, &n) != nil {
		return d, ErrInputs
	}
	n.Revision++
	return Delivery{n}, nil
}
func (d Delivery) scope(c access.Catalog, ctx PlanningContext) bool {
	return d.baseScope(c, ctx) && c.Authorize(ctx.Actor, d.d.Inventory.Tenant, access.ManageCD, "") == nil
}
func (d Delivery) baseScope(c access.Catalog, ctx PlanningContext) bool {
	a := d.d.Inventory
	return ctx.Cluster == a.Cluster && ctx.Networks.Cluster() == a.Cluster && ctx.Actor == d.d.Principal && ctx.Tenant == a.Tenant && ctx.Project == a.App && ctx.Deployment == a.Deployment && c.Revision() >= d.d.CatalogFloor && ctx.Networks.Revision() >= d.d.NetworkFloor
}

// Configure is an authenticated management change, never a Git-supplied grant.
// Accepted original work and the last valid artifact survive a source change;
// only a fresh result from the new registration can start a new operation.
func (d Delivery) Configure(expected, policyRevision uint64, c access.Catalog, ctx PlanningContext, actor string, policy DeliveryDeclaration) (Delivery, error) {
	if expected != d.Revision() || policyRevision != d.d.PolicyRevision || d.d.PolicyRevision == ^uint64(0) || !d.scope(c, ctx) || c.Authorize(actor, d.d.Inventory.Tenant, access.ManageCD, "") != nil {
		return d, ErrInputs
	}
	var artifact deliveryArtifact
	if d.d.Candidate != nil {
		artifact = d.d.Candidate.Artifact
	} else if d.d.Running != nil {
		artifact = d.d.Running.Candidate.Artifact
	} else {
		return d, ErrInputs
	}
	model, err := artifactCompose(artifact)
	if err != nil {
		return d, err
	}
	model.MyDC.Delivery = &policy
	if model.normalize() != nil {
		return d, ErrInputs
	}
	if bytes.Equal(goal(d.d.Policy), goal(policy)) {
		return d, nil
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Policy = policy
	n.d.PolicyRevision++
	n.d.Fetch = nil
	n.d.Approval = nil
	n.d.SourceError = ""
	return n, nil
}
func (d *Delivery) floors(c access.Catalog, ctx PlanningContext) {
	d.d.CatalogFloor = c.Revision()
	d.d.NetworkFloor = ctx.Networks.Revision()
}
func (d Delivery) Fetch(expected uint64, c access.Catalog, ctx PlanningContext) (Delivery, DeliveryFetch, error) {
	if expected != d.Revision() || !d.scope(c, ctx) || !d.d.Policy.Enabled || d.d.Paused || d.d.Fetch != nil || d.d.FetchSequence == ^uint64(0) {
		return d, DeliveryFetch{}, ErrInputs
	}
	n, err := d.clone()
	if err != nil {
		return d, DeliveryFetch{}, err
	}
	n.floors(c, ctx)
	n.d.FetchSequence++
	f := DeliveryFetch{n.d.FetchSequence, n.d.PolicyRevision, deliverySourceID(n.d.Policy)}
	n.d.Fetch = &f
	return n, f, nil
}
func (d Delivery) fetchMatches(f DeliveryFetch) bool {
	return d.d.Fetch != nil && *d.d.Fetch == f && f.PolicyRevision == d.d.PolicyRevision && f.Source == deliverySourceID(d.d.Policy)
}
func (d Delivery) SourceFailed(expected uint64, f DeliveryFetch, code string) (Delivery, error) {
	if expected != d.Revision() || !d.fetchMatches(f) {
		return d, ErrInputs
	}
	// Transport/private exception text never becomes replicated source status.
	switch code {
	case "fetch", "missing", "invalid", "scope", "policy", "name-conflict", "alias-conflict":
	default:
		return d, ErrInputs
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.d.Fetch = nil
	n.d.SourceError = code
	return n, nil
}
func (d Delivery) Received(expected uint64, c access.Catalog, ctx PlanningContext, input DeliveryInput) (Delivery, error) {
	if expected != d.Revision() || !d.scope(c, ctx) || !d.fetchMatches(input.fetch) || input.artifact.Kind != "git" || input.artifact.Path != d.d.Policy.Source.Path || uint64(len(input.artifact.Body)) > d.d.Policy.Limits.Bytes {
		return d, ErrSource
	}
	if d.d.Candidate != nil && d.d.Candidate.PolicyRevision == d.d.PolicyRevision && d.d.Candidate.OverrideRevision == d.d.OverrideRevision && d.d.Candidate.LocalRevision == d.d.LocalRevision && bytes.Equal(goal(d.d.Candidate.Artifact), goal(input.artifact)) {
		// An unchanged authenticated observation is not a new plan selection.
		// Preserve a manual approval and all original execution bytes. Current
		// catalog/plan checks still apply when approving/starting/replanning.
		n, err := d.clone()
		if err != nil {
			return d, err
		}
		n.floors(c, ctx)
		n.d.Fetch, n.d.SourceError = nil, ""
		return n, nil
	}
	candidate, err := d.compile(c, ctx, input.artifact)
	if err != nil {
		var conflict *InputError
		if errors.As(err, &conflict) {
			switch conflict.Code {
			case "CD_LOCAL_SERVICE_NAME_CONFLICT":
				return d.SourceFailed(expected, input.fetch, "name-conflict")
			case "CD_LOCAL_ALIAS_CONFLICT":
				return d.SourceFailed(expected, input.fetch, "alias-conflict")
			}
		}
		return d, err
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Fetch = nil
	n.d.SourceError = ""
	n.d.Candidate = &candidate
	n.d.Approval = nil
	return n, nil
}

// SubmitFile selects a new single-file input for an app without Git polling.
// A Git-managed app must resolve explicit runtime overrides/source ownership;
// a local upload never silently replaces its registered source.
func (d Delivery) SubmitFile(expected uint64, c access.Catalog, ctx PlanningContext, actor string, raw []byte) (Delivery, error) {
	if expected != d.Revision() || !d.scope(c, ctx) || c.Authorize(actor, d.d.Inventory.Tenant, access.ManageCD, "") != nil {
		return d, ErrInputs
	}
	if d.d.Policy.Enabled {
		return d, inputError("CD_SOURCE_CONFLICT", "source")
	}
	candidate, err := d.compile(c, ctx, deliveryArtifact{Original: true, Kind: "file", Digest: sha256.Sum256(raw), Body: bytes.Clone(raw)})
	if err != nil {
		return d, err
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Candidate = &candidate
	n.d.Approval = nil
	n.d.SourceError = ""
	return n, nil
}
func (d Delivery) compile(c access.Catalog, ctx PlanningContext, a deliveryArtifact) (deliveryCandidate, error) {
	input, err := artifactComposeKind(a, "app")
	if err != nil {
		return deliveryCandidate{}, err
	}
	// A source update cannot reauthorize its own registration or policy.
	// The policy lives on the server ('cd set'); a source without it follows
	// that policy. A source that still names one must name the same.
	if registered := input.MyDC.Delivery; registered != nil && !bytes.Equal(goal(registered), goal(d.d.Policy)) {
		return deliveryCandidate{}, inputError("CD_POLICY_APPROVAL_REQUIRED", "x-mydc.delivery")
	}
	var b Blueprint
	if a.Kind == "git" || a.Original {
		b, err = compileAppDocument(a.Body, d.d.Overrides, c, ctx, nil, d.d.LocalServices)
	} else {
		// Old file artifacts may have been generated from a normalized model.
		// They remain valid execution sources, not proof of original bytes.
		input, err = mergeLocalServices(input, d.d.LocalServices, AppScope{Tenant: ctx.Tenant, App: ctx.Project, Deployment: ctx.Deployment})
		if err == nil {
			input, err = applyDeliveryOverrides(input, d.d.Overrides)
		}
		if err == nil {
			b, err = CompileApp(input, c, ctx)
		}
	}
	if err != nil {
		return deliveryCandidate{}, errors.Join(ErrInputs, err)
	}
	if !(Inventory{d.d.Inventory}).scope(b) {
		return deliveryCandidate{}, ErrInputs
	}
	out := deliveryCandidate{Artifact: a, Plan: b.d, PolicyRevision: d.d.PolicyRevision, InventoryRevision: d.d.Inventory.Revision}
	out.Overrides = ownDeliveryOverrides(d.d.Overrides)
	out.OverrideRevision = d.d.OverrideRevision
	out.LocalServices, out.LocalRevision = ownLocalServices(d.d.LocalServices), d.d.LocalRevision
	if err = checkOverrideOwners(b, out.Overrides); err != nil {
		return deliveryCandidate{}, err
	}
	if err = d.checkOverrideInventory(b, out.Overrides, ctx); err != nil {
		return deliveryCandidate{}, err
	}
	out.ID = candidateID(out)
	return out, nil
}

// Replan retains the same artifact, invalidates an old plan approval, and uses
// the current exact committed inputs. It never rewrites Running's selection.
func (d Delivery) Replan(expected uint64, c access.Catalog, ctx PlanningContext) (Delivery, error) {
	if expected != d.Revision() || !d.scope(c, ctx) || d.d.Candidate == nil {
		return d, ErrInputs
	}
	candidate, err := d.compile(c, ctx, d.d.Candidate.Artifact)
	if err != nil {
		return d, err
	}
	if candidate.ID == d.d.Candidate.ID {
		return d, nil
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Candidate = &candidate
	n.d.Approval = nil
	return n, nil
}

// RebaseCandidate refreshes only incidental CAS/readiness/accounting bases.
// The registered source and effective intent stay fixed; callers retain the
// original signed choice and bind the accepted current plan in the same FSM
// transaction. A real input/owner/policy change still requires a new selection.
func (d Delivery) RebaseCandidate(expected uint64, c access.Catalog, ctx PlanningContext) (Delivery, error) {
	if d.d.Candidate == nil {
		return d, ErrInputs
	}
	original := *d.d.Candidate
	next, err := d.Replan(expected, c, ctx)
	if err != nil {
		return d, err
	}
	if next.d.Candidate == nil || original.PolicyRevision != next.d.Candidate.PolicyRevision || original.OverrideRevision != next.d.Candidate.OverrideRevision || original.LocalRevision != next.d.Candidate.LocalRevision || original.Artifact.Digest != next.d.Candidate.Artifact.Digest || !sameDeliveryIntent(Blueprint{original.Plan}, Blueprint{next.d.Candidate.Plan}) {
		return d, inputError("CD_TARGET_REPLAN_REQUIRED", "candidate")
	}
	if d.ExplicitApprovalReady(c) {
		a := *d.d.Approval
		a.Candidate = next.d.Candidate.ID
		next.d.Approval = &a
	}
	return next, nil
}

func (d Delivery) Approve(expected uint64, c access.Catalog, ctx PlanningContext, actor string, id [32]byte, reasons ...string) (Delivery, error) {
	reason := ""
	if len(reasons) > 1 {
		return d, ErrInputs
	}
	if len(reasons) == 1 {
		reason = reasons[0]
	}
	if !ValidCDReason(reason) {
		return d, ErrInputs
	}
	if d.Rejected() {
		return d, inputError("CD_CANDIDATE_REJECTED", "candidate")
	}
	if expected != d.Revision() || !d.scope(c, ctx) || d.d.Candidate == nil || d.d.Candidate.ID != id || d.d.Candidate.PolicyRevision != d.d.PolicyRevision || d.d.Candidate.OverrideRevision != d.d.OverrideRevision || d.d.Candidate.LocalRevision != d.d.LocalRevision || !d.mayDecide(c, actor) || (Blueprint{d.d.Candidate.Plan}).ValidateCurrent(c, ctx) != nil || d.d.Candidate.InventoryRevision != d.d.Inventory.Revision {
		return d, ErrInputs
	}
	if err := (Blueprint{d.d.Candidate.Plan}).CheckAppInput(); err != nil {
		return d, err
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Approval = &deliveryApproval{Candidate: id, Actor: actor, CatalogRevision: c.Revision(), Reason: reason}
	return n, nil
}
func (d Delivery) Start(expected uint64, c access.Catalog, ctx PlanningContext, id, submitter string, epoch uint64) (Delivery, error) {
	if d.localConflict() {
		return d, inputError("CD_LOCAL_SOURCE_CONFLICT", "source")
	}
	if expected != d.Revision() || !d.scope(c, ctx) || d.d.Paused || d.d.Transition != nil || d.usedTransitionID(id) || d.d.Candidate == nil || d.d.Candidate.PolicyRevision != d.d.PolicyRevision || d.d.Candidate.InventoryRevision != d.d.Inventory.Revision || d.d.Candidate.OverrideRevision != d.d.OverrideRevision || d.d.Candidate.LocalRevision != d.d.LocalRevision {
		return d, ErrInputs
	}
	candidate := *d.d.Candidate
	if d.Rejected() {
		return d, inputError("CD_CANDIDATE_REJECTED", "candidate")
	}
	if err := (Blueprint{candidate.Plan}).CheckAppInput(); err != nil {
		return d, err
	}
	approved := d.ApprovalReady(c)
	if d.d.Policy.Sync.Mode != "automatic" && !approved {
		return d, inputError("CD_APPROVAL_REQUIRED", "candidate")
	}
	if d.d.LastFailure != nil && bytes.Equal(goal(d.d.LastFailure.Candidate.Plan.Input), goal(candidate.Plan.Input)) {
		return d, inputError("CD_FAILED_REVISION", "candidate")
	}
	a := d.Inventory()
	b := Blueprint{candidate.Plan}
	replacement, err := a.ReplacementPlan(b, d.d.Policy.Sync.Prune)
	if err != nil {
		return d, err
	}
	if d.d.LastSuccess != nil && bytes.Equal(goal(d.d.LastSuccess.Candidate.Plan.Input), goal(candidate.Plan.Input)) {
		for _, step := range b.Steps() {
			if !deliveryDesiredMatches(step, b, ctx) && d.d.Policy.Sync.Drift != "reconcile" && !approved {
				return d, inputError("CD_DRIFT_REPORT_ONLY", step.Key)
			}
		}
	}
	// Missing Desired metadata is not evidence that an original native object
	// ended. Even drift=reconcile cannot silently issue another generation.
	for _, claim := range a.Claims() {
		if !claim.Removed && !claim.Retained {
			current := ctx.Current[claim.Step.Key]
			if !current.Present || current.Generation != claim.Result.Generation {
				return d, inputError("ORIGINAL_GENERATION_NOT_RELEASED", claim.Step.Key)
			}
		}
	}
	for _, step := range b.Steps() {
		if index := a.claim(step.Key); replacement == nil && index >= 0 && !a.d.Claims[index].Removed && !deliveryDesiredMatches(step, b, ctx) {
			if IngressRuntimeUpdate(a.d.Claims[index], step) {
				continue
			}
			switch step.Kind {
			case "dns", "namespace", "delivery", "volume":
			default:
				return d, inputError("TRANSITION_REQUIRED", step.Key)
			}
		}
	}
	next, err := a.Begin(a.Revision(), c, ctx, b, id, submitter, epoch, d.d.Policy.Sync.Prune)
	if err != nil {
		return d, err
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Inventory = next.d
	n.d.Running = &deliverySelection{candidate, id, submitter, epoch}
	n.d.Approval = nil
	return n, nil
}

// AdvanceExecution delegates original command/result/native-observation checks
// to Inventory.Advance. It does not use the newest source as a recovery recipe.
func (d Delivery) AdvanceExecution(expected uint64, next Execution, shared state.State) (Delivery, error) {
	if expected != d.Revision() || d.d.Running == nil || next.d.Operation != d.d.Running.Operation || next.d.Submitter != d.d.Running.Submitter || next.d.Epoch != d.d.Running.Epoch || (Blueprint{next.d.Plan}).Digest() != (Blueprint{d.d.Running.Candidate.Plan}).Digest() {
		return d, ErrInputs
	}
	a := d.Inventory()
	updated, err := a.Advance(a.Revision(), next, shared)
	if err != nil {
		return d, err
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.d.Inventory = updated.d
	n.recordExecutionOutcome(next)
	return n, nil
}

// Both the direct core adapter and the app checkpoint bridge publish the same
// verified execution outcome. Neither path may retain a superseded failure.
func (n *Delivery) recordExecutionOutcome(next Execution) {
	if next.Status() == "Succeeded" {
		n.d.LastSuccess = n.d.Running
		n.d.CompactedSuccess = nil
		if n.d.LastFailure != nil && bytes.Equal(goal(n.d.LastFailure.Candidate.Plan.Input), goal(n.d.Running.Candidate.Plan.Input)) {
			n.d.LastFailure = nil
			n.d.CompactedFailure = nil
		}
	}
	if next.Status() == "Failed" {
		n.d.LastFailure = n.d.Running
		n.d.CompactedFailure = nil
	}
}
func (d Delivery) Pause(expected uint64, c access.Catalog, actor string, paused bool, shared state.State) (Delivery, error) {
	if expected != d.Revision() || c.Revision() < d.d.CatalogFloor || c.Authorize(actor, d.d.Inventory.Tenant, access.ManageCD, "") != nil {
		return d, ErrInputs
	}
	a := d.Inventory()
	if e, ok := a.Execution(); ok && e.Status() != "Succeeded" && e.Status() != "Closed" {
		next, err := e.Pause(c, actor, e.Revision(), paused)
		if err != nil {
			return d, err
		}
		a, err = a.Advance(a.Revision(), next, shared)
		if err != nil {
			return d, err
		}
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.d.Paused = paused
	n.d.CatalogFloor = c.Revision()
	n.d.Inventory = a.d
	return n, nil
}
