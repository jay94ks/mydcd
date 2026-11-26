// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"gopkg.in/yaml.v3"
)

// DeliverySelection describes a frozen choice, not an execution/health receipt.
type DeliverySelection struct {
	Candidate, Artifact, Plan, Intent [32]byte
	Commit, Operation, Submitter      string
	Epoch                             uint64
}
type DeliveryTransition struct {
	Mode              DeliveryTransitionMode
	Phase, Retirement string
	Selection         DeliverySelection
}

func selectionView(c deliveryCandidate) DeliverySelection {
	b := Blueprint{c.Plan}
	return DeliverySelection{Candidate: c.ID, Artifact: c.Artifact.Digest, Plan: b.Digest(), Intent: b.IntentDigest(), Commit: c.Artifact.Commit}
}
func (d Delivery) Selection() (DeliverySelection, bool) {
	if d.d.Running == nil {
		return DeliverySelection{}, false
	}
	v := selectionView(d.d.Running.Candidate)
	v.Operation, v.Submitter, v.Epoch = d.d.Running.Operation, d.d.Running.Submitter, d.d.Running.Epoch
	return v, true
}
func (d Delivery) CandidateSelection() (DeliverySelection, bool) {
	if d.d.Candidate == nil {
		return DeliverySelection{}, false
	}
	return selectionView(*d.d.Candidate), true
}

// CandidateApplied compares the selected immutable source and effective
// intent, excluding incidental CAS/readiness/usage bases. It is not a native
// completion or health result; those remain owned by the current Execution.
func (d Delivery) CandidateApplied() bool {
	if d.d.Candidate == nil || d.d.Running == nil {
		return false
	}
	a, b := d.d.Running.Candidate, *d.d.Candidate
	return a.Artifact.Digest == b.Artifact.Digest && a.Artifact.Commit == b.Artifact.Commit && a.PolicyRevision == b.PolicyRevision && a.OverrideRevision == b.OverrideRevision && (Blueprint{a.Plan}).IntentDigest() == (Blueprint{b.Plan}).IntentDigest()
}
func (d Delivery) Transition() (DeliveryTransition, bool) {
	if d.d.Transition == nil {
		return DeliveryTransition{}, false
	}
	t := d.d.Transition
	v := selectionView(t.Selection.Candidate)
	v.Operation, v.Submitter, v.Epoch = t.Selection.Operation, t.Selection.Submitter, t.Selection.Epoch
	return DeliveryTransition{t.Mode, t.Phase, t.Retirement, v}, true
}
func (d Delivery) SourceError() string      { return d.d.SourceError }
func (d Delivery) OverrideRevision() uint64 { return d.d.OverrideRevision }
func (d Delivery) PolicyRevision() uint64   { return d.d.PolicyRevision }

// IntentDigest uses the SAME semantic boundary as transition rebasing: actual
// input/goals/owners/nodes remain fixed; released CAS/readiness bases and node
// Used accounting do not turn the original choice into another application.
func (b Blueprint) IntentDigest() [32]byte {
	if _, err := b.Encode(); err != nil {
		return [32]byte{}
	}
	steps := slices.Clone(b.d.Steps)
	for i := range steps {
		steps[i].Base, steps[i].BasePresent, steps[i].StableDNS = ObjectRef{}, false, nil
	}
	nodes := make(map[string]PlanningNode, len(b.d.Nodes))
	for id, n := range b.d.Nodes {
		n.Used.CPU, n.Used.Memory = 0, 0
		nodes[id] = n
	}
	raw, _ := json.Marshal(struct {
		InputKind                      string
		Cluster                        [32]byte
		Actor, Tenant, App, Deployment string
		Input                          Compose
		Steps                          []Step
		Nodes                          map[string]PlanningNode
	}{b.d.InputKind, b.d.Cluster, b.d.Actor, b.d.Tenant, b.d.App, b.d.Deployment, b.d.Input, steps, nodes})
	return sha256.Sum256(raw)
}

// Sync uses the ordinary Start or positive-retirement transition. Manual sync
// is an explicit approval of this exact candidate. Automatic callers must first
// check registered automatic policy/current scope/health; they cannot recover
// a failed revision or silently move an owned Volume through this method.
func (d Delivery) Sync(expected uint64, c access.Catalog, ctx PlanningContext, actor, operation, submitter string, epoch uint64, recover bool) (Delivery, error) {
	return d.sync(expected, c, ctx, actor, operation, submitter, epoch, true, recover)
}

// SyncAutomatic retains Start's report-only drift gate. Creating a manual
// approval before that gate would silently turn polling into an override.
// Current health/quorum/member delegation are checked by the control caller.
func (d Delivery) SyncAutomatic(expected uint64, c access.Catalog, ctx PlanningContext, operation, submitter string, epoch uint64) (Delivery, error) {
	if d.Policy().Sync.Mode != "automatic" && !d.ExplicitApprovalReady(c) {
		return d, ErrInputs
	}
	return d.sync(expected, c, ctx, d.Principal(), operation, submitter, epoch, false, false)
}

func (d Delivery) sync(expected uint64, c access.Catalog, ctx PlanningContext, actor, operation, submitter string, epoch uint64, explicit, recover bool) (Delivery, error) {
	if expected != d.Revision() || d.d.Candidate == nil {
		return d, ErrInputs
	}
	approved := d
	var err error
	if explicit {
		approved, err = d.Approve(expected, c, ctx, actor, d.d.Candidate.ID)
		if err != nil {
			return d, err
		}
	}
	if recover {
		return approved.BeginTransition(approved.Revision(), c, ctx, d.Principal(), operation, submitter, epoch, DeliveryRecover)
	}
	n, err := approved.Start(approved.Revision(), c, ctx, operation, submitter, epoch)
	if err == nil {
		return n, nil
	}
	var reason *InputError
	if !errors.As(err, &reason) || reason.Code != "TRANSITION_REQUIRED" {
		return d, err
	}
	if !explicit && !d.ExplicitApprovalReady(c) {
		approved, err = d.Approve(d.Revision(), c, ctx, actor, d.d.Candidate.ID)
		if err != nil {
			return d, err
		}
	}
	return approved.BeginTransition(approved.Revision(), c, ctx, d.Principal(), operation, submitter, epoch, DeliveryUpdate)
}

// NewAcceptedDelivery attaches source selection to the already accepted app
// Inventory. It does not begin another execution or adopt native observations.
// The caller has validated this Blueprint and its original signed delegation
// in the same management transaction that accepted the Inventory.
func NewAcceptedDelivery(b Blueprint, i Inventory, catalog access.Catalog) (Delivery, error) {
	policy := b.d.Input.MyDC.Delivery
	if policy == nil {
		return Delivery{}, ErrInputs
	}
	return newDelivery(b, i, catalog, b.d.Actor, *policy)
}

// AttachDelivery turns CD on for an app deployed without it ('cd set'). The
// running execution becomes the first candidate; the policy lives only on
// the server, so the app's own file never carries it.
func AttachDelivery(i Inventory, catalog access.Catalog, actor string, policy DeliveryDeclaration) (Delivery, error) {
	e, active := i.Execution()
	if !active {
		return Delivery{}, ErrInputs
	}
	b := e.Blueprint()
	if b.d.Input.MyDC.Delivery != nil {
		return Delivery{}, ErrInputs
	}
	model := b.d.Input
	model.MyDC.Delivery = &policy
	if model.normalize() != nil || !bytes.Equal(goal(*model.MyDC.Delivery), goal(policy)) {
		return Delivery{}, ErrInputs
	}
	return newDelivery(b, i, catalog, actor, policy)
}

func newDelivery(b Blueprint, i Inventory, catalog access.Catalog, principal string, p DeliveryDeclaration) (Delivery, error) {
	e, active := i.Execution()
	policy := &p
	if b.CheckAppInput() != nil || !i.scope(b) || !active || e.Blueprint().Digest() != b.Digest() || !policy.Enabled || catalog.Authorize(principal, b.d.Tenant, access.ManageCD, "") != nil {
		return Delivery{}, ErrInputs
	}
	raw, err := marshalApp(b.d.Input)
	if source := b.OriginalDocument(); source != nil {
		raw = source.Body
	}
	if err != nil {
		return Delivery{}, err
	}
	d := Delivery{deliveryRecord{Schema: 1, Revision: 1, PolicyRevision: 1, Principal: principal, Policy: *policy, Inventory: i.d, CatalogFloor: b.d.CatalogRevision, NetworkFloor: b.d.NetworkRevision}}
	candidate := deliveryCandidate{Artifact: deliveryArtifact{Original: b.d.Document != nil, Kind: "file", Digest: sha256.Sum256(raw), Body: raw}, Plan: b.d, PolicyRevision: 1, InventoryRevision: i.Revision()}
	if doc := b.OriginalDocument(); doc != nil && doc.LocalServices != nil {
		d.d.LocalServices, d.d.LocalRevision = ownLocalServices(doc.LocalServices), doc.LocalServices.Revision
		candidate.LocalServices, candidate.LocalRevision = ownLocalServices(doc.LocalServices), doc.LocalServices.Revision
	}
	candidate.ID = candidateID(candidate)
	d.d.Candidate = &candidate
	d.d.Running = &deliverySelection{candidate, e.d.Operation, e.d.Submitter, e.d.Epoch}
	if e.Status() == "Succeeded" {
		d.d.LastSuccess = d.d.Running
	}
	if d.validate() != nil {
		return Delivery{}, ErrInputs
	}
	return d, nil
}

// FollowInventory persists an Inventory value produced by the ordinary app
// reducer. It is not an untrusted mutation API: the control FSM first validates
// the exact A1 result/owner observation/removal, then calls this storage bridge.
// Only Delivery.Start/ContinueTransition may select a different execution.
func (d Delivery) FollowInventory(expected uint64, i Inventory) (Delivery, error) {
	if expected != d.Revision() || i.Scope() != (Inventory{d.d.Inventory}).Scope() || i.Revision() < d.d.Inventory.Revision || i.validate() != nil {
		return d, ErrInputs
	}
	if bytes.Equal(goal(i.d), goal(d.d.Inventory)) {
		return d, nil
	}
	if e, active := i.Execution(); active && (d.d.Running == nil || e.d.Operation != d.d.Running.Operation || e.d.Submitter != d.d.Running.Submitter || e.d.Epoch != d.d.Running.Epoch || e.Blueprint().Digest() != (Blueprint{d.d.Running.Candidate.Plan}).Digest()) {
		return d, ErrInputs
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	// Own the same record, not a second independently mutable Inventory.
	raw, _ := i.Encode()
	i, err = DecodeInventory(raw)
	if err != nil {
		return d, err
	}
	n.d.Inventory = i.d
	if e, active := i.Execution(); active {
		n.recordExecutionOutcome(e)
	} else {
		n.d.Running = nil
	}
	if n.validate() != nil {
		return d, ErrInputs
	}
	// The checkpoint encoder/decoder consume these same canonical bytes next.
	// Remember only this fully checked value; no current authority or mutable
	// record is retained by the existing bounded validation cache.
	if raw, err := json.Marshal(n.d); err == nil {
		validatedDeliveryBytes.remember(raw)
	}
	return n, nil
}

func (d Delivery) Principal() string      { return d.d.Principal }
func (b Blueprint) CDDefaultNode() string { return b.d.DefaultNode }

// AcceptedPlan preserves the recipe owner across positive retirement, when
// Execution is absent but the original update/recovery has yet to be applied.
// An unaccepted queued candidate is never a continuity source.
func (d Delivery) AcceptedPlan() (Blueprint, bool) {
	if transition, ok := d.Transition(); ok && transition.Mode != DeliveryDown {
		return d.TransitionPlan()
	}
	if execution, ok := d.Inventory().Execution(); ok {
		return execution.Blueprint(), true
	}
	return Blueprint{}, false
}
func (d Delivery) Paused() bool { return d.d.Paused }
func (b Blueprint) DeliveryPolicy() (DeliveryDeclaration, bool) {
	if b.d.Input.MyDC.Delivery == nil || !b.d.Input.MyDC.Delivery.Enabled {
		return DeliveryDeclaration{}, false
	}
	raw, _ := json.Marshal(b.d.Input.MyDC.Delivery)
	var policy DeliveryDeclaration
	_ = json.Unmarshal(raw, &policy)
	return policy, true
}
func (d Delivery) Policy() DeliveryDeclaration {
	raw, _ := json.Marshal(d.d.Policy)
	var p DeliveryDeclaration
	_ = json.Unmarshal(raw, &p)
	return p
}
func (d Delivery) FetchTicket() (DeliveryFetch, bool) {
	if d.d.Fetch == nil {
		return DeliveryFetch{}, false
	}
	return *d.d.Fetch, true
}
func (d Delivery) CandidateBlueprint() (Blueprint, bool) {
	if d.d.Candidate == nil {
		return Blueprint{}, false
	}
	raw, err := (Blueprint{d.d.Candidate.Plan}).Encode()
	if err != nil {
		return Blueprint{}, false
	}
	b, err := DecodeBlueprint(raw)
	return b, err == nil
}

func marshalApp(input Compose) ([]byte, error) {
	raw, err := yaml.Marshal(input)
	if err != nil {
		return nil, err
	}
	var tree yaml.Node
	if yaml.Unmarshal(raw, &tree) != nil || len(tree.Content) != 1 {
		return nil, ErrInputs
	}
	// An explicit empty resolver list disables default projection and must not
	// disappear merely because the accepted input is now stored as an artifact.
	for name, service := range input.Services {
		for _, field := range []struct {
			name   string
			values []string
		}{{"dns", service.DNS}, {"dns_search", service.DNSSearch}} {
			if field.values != nil && len(field.values) == 0 {
				if yamlSet(tree.Content[0], []string{"services", name, field.name}, &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}) != nil {
					return nil, ErrInputs
				}
			}
		}
	}
	return yaml.Marshal(&tree)
}
