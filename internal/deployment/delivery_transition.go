// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

type DeliveryTransitionMode string

const (
	DeliveryUpdate   DeliveryTransitionMode = "update"
	DeliveryRecover  DeliveryTransitionMode = "recover"
	DeliveryDown     DeliveryTransitionMode = "down"
	DeliveryRecreate DeliveryTransitionMode = "recreate"
)

type deliveryTransition struct {
	Mode       DeliveryTransitionMode
	Phase      string
	Selection  deliverySelection
	Retirement string
	Receipt    *retirementRecord
	Required   []ObjectRef
}
type deliveryTransitionSummary struct {
	ID                      string
	Mode                    DeliveryTransitionMode
	Outcome                 string
	Artifact, Plan, Closure [32]byte
	Submitter               string
	Epoch                   uint64
}

func transitionRetirementID(id string) string {
	sum := sha256.Sum256([]byte("sfc-delivery-retire-1\x00" + id))
	return "cd-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))
}

// The same opaque retirement identity is used for plain and CD recreation.
// It is derived from the accepted user operation, never a new retry identity.
func RecreationRetirementID(id string) string {
	sum := sha256.Sum256([]byte("sfc-container-recreate-1\x00" + id))
	return "recreate-" + hex.EncodeToString(sum[:24])
}
func (d Delivery) usedTransitionID(id string) bool {
	if d.d.Transition != nil && d.d.Transition.Selection.Operation == id {
		return true
	}
	return slices.ContainsFunc(d.d.Transitions, func(s deliveryTransitionSummary) bool { return s.ID == id })
}
func (d Delivery) transitionAccess(c access.Catalog, actor string) bool {
	if d.d.Transition != nil && d.d.Transition.Mode == DeliveryRecreate {
		return c.Revision() >= d.d.CatalogFloor && c.AuthorizeCleanup(actor, d.d.Inventory.Tenant, access.Deploy) == nil
	}
	return c.Revision() >= d.d.CatalogFloor && c.AuthorizeCleanup(actor, d.d.Inventory.Tenant, access.ManageCD) == nil && c.AuthorizeCleanup(actor, d.d.Inventory.Tenant, access.Deploy) == nil
}

// BeginRecreation freezes the RUNNING declaration, not a newly fetched Git
// candidate. Explicit user approval is checked by control before calling this
// core. Plain apps use Inventory.Retire directly; no fake CD is attached.
func (d Delivery) BeginRecreation(expected uint64, c access.Catalog, actor, id, submitter string, epoch uint64, keys []string) (Delivery, error) {
	if expected != d.Revision() || d.d.Transition != nil || d.d.Running == nil || d.usedTransitionID(id) || len(d.d.Transitions) >= 128 || c.AuthorizeCleanup(actor, d.d.Inventory.Tenant, access.Deploy) != nil {
		return d, ErrInputs
	}
	a := d.Inventory()
	if _, err := a.PreviewRetirement(keys, false); err != nil {
		return d, err
	}
	retirement := RecreationRetirementID(id)
	updated, err := a.Retire(a.Revision(), c, actor, retirement, submitter, epoch, keys, false)
	if err != nil {
		return d, err
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	selected := *n.d.Running
	selected.Operation, selected.Submitter, selected.Epoch = id, submitter, epoch
	n.d.Inventory = updated.d
	n.d.Transition = &deliveryTransition{Mode: DeliveryRecreate, Phase: "retiring", Selection: selected, Retirement: retirement}
	return n, nil
}

// BeginTransition freezes an explicitly approved update/recovery target. Down
// is itself an explicit management command; it stops polling/new dispatch while
// preserving the original execution and every unknown accepted request.
func (d Delivery) BeginTransition(expected uint64, c access.Catalog, ctx PlanningContext, actor, id, submitter string, epoch uint64, mode DeliveryTransitionMode) (Delivery, error) {
	if expected != d.Revision() || !d.baseScope(c, ctx) || !d.transitionAccess(c, actor) || d.d.Transition != nil || d.d.Candidate == nil || !identifier(id) || submitter == "" || len(submitter) > 256 || epoch == 0 || len(d.d.Transitions) >= 128 || d.usedTransitionID(id) || len(d.d.Inventory.History) >= 127 || epoch < d.d.Inventory.MinEpoch[submitter] {
		return d, ErrInputs
	}
	a := d.Inventory()
	if e, ok := a.Execution(); ok && e.d.Operation == id {
		return d, ErrInputs
	}
	if slices.ContainsFunc(a.d.History, func(h OperationSummary) bool { return h.ID == id }) {
		return d, ErrInputs
	}
	candidate := *d.d.Candidate
	var keys []string
	down := mode == DeliveryDown || mode == DeliveryRecover
	switch mode {
	case DeliveryUpdate, DeliveryRecover:
		if d.localConflict() {
			return d, inputError("CD_LOCAL_SOURCE_CONFLICT", "source")
		}
		if d.Rejected() {
			return d, inputError("CD_CANDIDATE_REJECTED", "candidate")
		}
		if err := (Blueprint{candidate.Plan}).CheckAppInput(); err != nil {
			return d, err
		}
		if !d.scope(c, ctx) || d.d.Paused || candidate.PolicyRevision != d.d.PolicyRevision || candidate.OverrideRevision != d.d.OverrideRevision || candidate.LocalRevision != d.d.LocalRevision || candidate.InventoryRevision != a.Revision() || (Blueprint{candidate.Plan}).ValidateCurrent(c, ctx) != nil {
			return d, ErrInputs
		}
		approval := d.d.Approval
		if approval == nil || approval.Candidate != candidate.ID || approval.CatalogRevision != c.Revision() || !d.mayDecide(c, approval.Actor) {
			return d, inputError("CD_TRANSITION_APPROVAL_REQUIRED", "candidate")
		}
		if mode == DeliveryRecover && d.d.LastFailure == nil {
			return d, ErrInputs
		}
		changes, err := a.Changes(Blueprint{candidate.Plan}, d.d.Policy.Sync.Prune)
		if err != nil {
			return d, err
		}
		for _, change := range changes {
			if change.Action == "MoveRequired" {
				return d, inputError("EXPLICIT_VOLUME_MOVE_REQUIRED", change.Key)
			}
			if change.Action == "Remove" || change.Action == "Replace" {
				keys = append(keys, change.Key)
			}
		}
		// Drift correction may require native replacement even when the last
		// inventory declaration still equals Git. It is never an absence guess.
		for _, step := range candidate.Plan.Steps {
			at := a.claim(step.Key)
			if at < 0 || a.d.Claims[at].Removed || deliveryDesiredMatches(step, Blueprint{candidate.Plan}, ctx) {
				continue
			}
			if IngressRuntimeUpdate(a.d.Claims[at], step) {
				continue
			}
			switch step.Kind {
			case "dns", "namespace", "delivery", "volume":
			default:
				keys = append(keys, step.Key)
			}
		}
		if !down && len(keys) == 0 {
			return d, inputError("NO_NATIVE_TRANSITION", "candidate")
		}
	case DeliveryDown:
	default:
		return d, ErrInputs
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	retirement := transitionRetirementID(id)
	updated, err := a.Retire(a.Revision(), c, actor, retirement, submitter, epoch, keys, down)
	if err != nil {
		return d, err
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Inventory = updated.d
	n.d.Transition = &deliveryTransition{Mode: mode, Phase: "retiring", Selection: deliverySelection{Candidate: candidate, Operation: id, Submitter: submitter, Epoch: epoch}, Retirement: retirement}
	n.d.Approval = nil
	if mode == DeliveryDown {
		n.d.Paused = true
		n.d.Fetch = nil
	}
	return n, nil
}
func (d Delivery) retirementMatches() bool {
	t := d.d.Transition
	return t != nil && t.Phase == "retiring" && d.d.Inventory.Retirement != nil && d.d.Inventory.Retirement.ID == t.Retirement
}
func (d Delivery) keepRetirement(expected uint64, a Inventory, err error) (Delivery, error) {
	if err != nil {
		return d, err
	}
	if expected != d.Revision() || !d.retirementMatches() {
		return d, ErrInputs
	}
	if a.Revision() == d.d.Inventory.Revision {
		return d, nil
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.d.Inventory = a.d
	return n, nil
}
func (d Delivery) SendRemoval(expected uint64, c access.Catalog, actor, key, phase string) (Delivery, error) {
	if !d.transitionAccess(c, actor) || !d.retirementMatches() {
		return d, ErrInputs
	}
	a := d.Inventory()
	updated, err := a.SendRemoval(a.Revision(), c, actor, key, phase)
	return d.keepRetirement(expected, updated, err)
}
func (d Delivery) UnknownRemoval(expected uint64, key, phase string) (Delivery, error) {
	if !d.retirementMatches() {
		return d, ErrInputs
	}
	a := d.Inventory()
	updated, err := a.UnknownRemoval(a.Revision(), key, phase)
	return d.keepRetirement(expected, updated, err)
}
func (d Delivery) SettleRemoval(expected uint64, key, phase string, shared state.State) (Delivery, error) {
	if !d.retirementMatches() {
		return d, ErrInputs
	}
	a := d.Inventory()
	updated, err := a.SettleRemoval(a.Revision(), key, phase, shared)
	return d.keepRetirement(expected, updated, err)
}
func (d Delivery) Gone(expected uint64, key string, signature []byte) (Delivery, error) {
	if !d.retirementMatches() {
		return d, ErrInputs
	}
	a := d.Inventory()
	updated, err := a.Gone(a.Revision(), key, signature)
	return d.keepRetirement(expected, updated, err)
}
func (d Delivery) Retained(expected uint64, key string, receipt *RetainReceipt) (Delivery, error) {
	if !d.retirementMatches() {
		return d, ErrInputs
	}
	a := d.Inventory()
	updated, err := a.Retained(a.Revision(), key, receipt)
	return d.keepRetirement(expected, updated, err)
}

// FinishRetirement publishes positive original closure independently from a
// later Apply. A changed policy may block Apply without discarding this receipt.
func (d Delivery) FinishRetirement(expected uint64, c access.Catalog, actor string) (Delivery, error) {
	if expected != d.Revision() || !d.retirementMatches() || !d.transitionAccess(c, actor) {
		return d, ErrInputs
	}
	a := d.Inventory()
	updated, err := a.FinishRetirement(a.Revision())
	if err != nil {
		return d, err
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.d.Transition.Phase = "ready"
	n.d.Transition.Receipt = n.d.Inventory.Retirement
	for _, target := range n.d.Transition.Receipt.Targets {
		n.d.Transition.Required = append(n.d.Transition.Required, ObjectRef{target.Original.Step.Key, target.Original.Result.Revision, target.Original.Result.Generation})
	}
	slices.SortFunc(n.d.Transition.Required, func(a, b ObjectRef) int { return strings.Compare(a.Key, b.Key) })
	n.d.Inventory = updated.d
	n.d.Running = nil
	n.d.CatalogFloor = c.Revision()
	return n, nil
}
func sameDeliveryIntent(a, b Blueprint) bool {
	intent := a.IntentDigest()
	return intent != ([32]byte{}) && intent == b.IntentDigest()
}
func (d *Delivery) archiveTransition(outcome string) {
	t := d.d.Transition
	closure := sha256.Sum256(goal(struct {
		Receipt  *retirementRecord
		Required []ObjectRef
	}{t.Receipt, t.Required}))
	d.d.Transitions = append(d.d.Transitions, deliveryTransitionSummary{ID: t.Selection.Operation, Mode: t.Mode, Outcome: outcome, Artifact: t.Selection.Candidate.Artifact.Digest, Plan: (Blueprint{t.Selection.Candidate.Plan}).Digest(), Closure: closure, Submitter: t.Selection.Submitter, Epoch: t.Selection.Epoch})
	d.d.Transition = nil
}

// ContinueTransition uses the ORIGINAL accepted source, even if a newer commit
// is queued. Only CAS bases/readiness references may change after proven cleanup.
func (d Delivery) ContinueTransition(expected uint64, c access.Catalog, ctx PlanningContext, actor string) (Delivery, error) {
	t := d.d.Transition
	if expected != d.Revision() || t == nil || t.Phase != "ready" {
		return d, fmt.Errorf("continue CD revision/phase: %w", ErrInputs)
	}
	if !d.baseScope(c, ctx) {
		return d, fmt.Errorf("continue CD original scope/floors: %w", ErrInputs)
	}
	if !d.transitionAccess(c, actor) {
		return d, fmt.Errorf("continue CD current cleanup access: %w", ErrInputs)
	}
	if t.Mode == DeliveryDown {
		n, err := d.clone()
		if err != nil {
			return d, err
		}
		n.d.Paused = true
		n.d.Fetch = nil
		n.floors(c, ctx)
		n.archiveTransition("stopped")
		return n, nil
	}
	if t.Mode == DeliveryRecreate {
		a := d.Inventory()
		b, err := (Blueprint{t.Selection.Candidate.Plan}).Rebase(c, ctx)
		if err != nil {
			return d, err
		}
		updated, err := a.Begin(a.Revision(), c, ctx, b, t.Selection.Operation, t.Selection.Submitter, t.Selection.Epoch, false)
		if err != nil {
			return d, err
		}
		n, err := d.clone()
		if err != nil {
			return d, err
		}
		candidate := t.Selection.Candidate
		candidate.Plan, candidate.InventoryRevision = b.d, a.Revision()
		candidate.ID = candidateID(candidate)
		n.d.Inventory = updated.d
		n.d.Running = &deliverySelection{Candidate: candidate, Operation: t.Selection.Operation, Submitter: t.Selection.Submitter, Epoch: t.Selection.Epoch}
		n.floors(c, ctx)
		n.archiveTransition("applying")
		return n, nil
	}
	if !d.scope(c, ctx) || d.d.Paused || t.Selection.Candidate.PolicyRevision != d.d.PolicyRevision || t.Selection.Candidate.OverrideRevision != d.d.OverrideRevision {
		return d, inputError("CD_TARGET_POLICY_CHANGED", "transition")
	}
	frozen := d
	frozen.d.Overrides = ownDeliveryOverrides(t.Selection.Candidate.Overrides)
	candidate, err := frozen.compile(c, ctx, t.Selection.Candidate.Artifact)
	if err != nil {
		return d, fmt.Errorf("continue CD original artifact compile: %w", err)
	}
	if !sameDeliveryIntent(Blueprint{t.Selection.Candidate.Plan}, Blueprint{candidate.Plan}) {
		return d, inputError("CD_TARGET_REPLAN_REQUIRED", "transition")
	}
	a := d.Inventory()
	updated, err := a.Begin(a.Revision(), c, ctx, Blueprint{candidate.Plan}, t.Selection.Operation, t.Selection.Submitter, t.Selection.Epoch, d.d.Policy.Sync.Prune)
	if err != nil {
		return d, fmt.Errorf("continue CD original inventory: %w", err)
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	if n.d.Candidate != nil && n.d.Candidate.ID == t.Selection.Candidate.ID {
		n.d.Candidate = &candidate
	}
	n.d.Inventory = updated.d
	n.d.Running = &deliverySelection{Candidate: candidate, Operation: t.Selection.Operation, Submitter: t.Selection.Submitter, Epoch: t.Selection.Epoch}
	n.floors(c, ctx)
	n.archiveTransition("applying")
	return n, nil
}

// AbandonTransition is possible only after positive closure. It keeps the
// original identity tombstone and never reopens an old native generation.
func (d Delivery) AbandonTransition(expected uint64, c access.Catalog, actor string) (Delivery, error) {
	if expected != d.Revision() || d.d.Transition == nil || d.d.Transition.Phase != "ready" || !d.transitionAccess(c, actor) {
		return d, ErrInputs
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.d.CatalogFloor = c.Revision()
	n.archiveTransition("abandoned")
	return n, nil
}

func (d Delivery) validateTransitions() error {
	seen := map[string]bool{}
	if len(d.d.Transitions) > 128 {
		return ErrInputs
	}
	for _, s := range d.d.Transitions {
		if !identifier(s.ID) || seen[s.ID] || s.Mode != DeliveryUpdate && s.Mode != DeliveryRecover && s.Mode != DeliveryDown && s.Mode != DeliveryRecreate || s.Outcome != "applying" && s.Outcome != "stopped" && s.Outcome != "abandoned" || s.Artifact == ([32]byte{}) || s.Plan == ([32]byte{}) || s.Closure == ([32]byte{}) || s.Submitter == "" || s.Epoch == 0 {
			return ErrInputs
		}
		seen[s.ID] = true
	}
	t := d.d.Transition
	if d.d.Inventory.Retirement != nil && !d.d.Inventory.Retirement.KeepExecution && (t == nil || t.Phase != "retiring") {
		return ErrInputs
	}
	if t == nil {
		return nil
	}
	expectedRetirement := transitionRetirementID(t.Selection.Operation)
	if t.Mode == DeliveryRecreate {
		expectedRetirement = RecreationRetirementID(t.Selection.Operation)
	}
	if !identifier(t.Selection.Operation) || t.Selection.Submitter == "" || len(t.Selection.Submitter) > 256 || t.Selection.Epoch == 0 || !d.validCandidate(t.Selection.Candidate) || t.Mode != DeliveryUpdate && t.Mode != DeliveryRecover && t.Mode != DeliveryDown && t.Mode != DeliveryRecreate || t.Retirement != expectedRetirement || seen[t.Selection.Operation] {
		return ErrInputs
	}
	switch t.Phase {
	case "retiring":
		r := d.d.Inventory.Retirement
		if r == nil || r.ID != t.Retirement || r.Submitter != t.Selection.Submitter || r.Epoch != t.Selection.Epoch || r.Down != (t.Mode == DeliveryDown || t.Mode == DeliveryRecover) || t.Receipt != nil || len(t.Required) != 0 {
			return ErrInputs
		}
	case "ready":
		if t.Receipt == nil || d.d.Inventory.Retirement != nil || d.d.Inventory.Active != nil || d.d.Running != nil || t.Receipt.ID != t.Retirement || t.Receipt.Submitter != t.Selection.Submitter || t.Receipt.Epoch != t.Selection.Epoch || len(t.Required) != len(t.Receipt.Targets) || t.Receipt.Down != (t.Mode == DeliveryDown || t.Mode == DeliveryRecover) {
			return ErrInputs
		}
		// Read-only historical receipt validation reuses the original Inventory
		// checker. It is never published as a second operational inventory.
		historical := d.Inventory()
		historical.d.Active = nil
		historical.d.History = nil
		historical.d.MinEpoch = nil
		historical.d.Claims = nil
		historical.d.Stopping = true
		historical.d.Retirement = t.Receipt
		currentInventory := Inventory{d.d.Inventory}
		for _, target := range t.Receipt.Targets {
			if !target.Closed {
				return ErrInputs
			}
			old := target.Original
			required := ObjectRef{old.Step.Key, old.Result.Revision, old.Result.Generation}
			if !slices.Contains(t.Required, required) {
				return ErrInputs
			}
			at := currentInventory.claim(old.Step.Key)
			if at < 0 {
				return ErrInputs
			}
			current := d.d.Inventory.Claims[at]
			if current.Result != old.Result || current.Command != old.Command || old.Step.Retain && (!current.Retained || !bytes.Equal(goal(current.RetainProof), goal(target.Retained))) || !old.Step.Retain && (!current.Removed || !bytes.Equal(goal(current.Removal), goal(RemovalProof{t.Receipt.ID, t.Receipt.Revision, target.Drain, target.Proof, target.Delete, target.Gone}))) {
				return ErrInputs
			}
			historical.d.Claims = append(historical.d.Claims, current)
		}
		for i, ref := range t.Required {
			if i > 0 && t.Required[i-1].Key >= ref.Key {
				return ErrInputs
			}
		}
		slices.SortFunc(historical.d.Claims, func(a, b Claim) int { return strings.Compare(a.Step.Key, b.Step.Key) })
		if historical.validate() != nil {
			return ErrInputs
		}
	default:
		return ErrInputs
	}
	return nil
}

// TransitionPlan returns an independent copy of the frozen target recipe.
func (d Delivery) TransitionPlan() (Blueprint, bool) {
	if d.d.Transition == nil {
		return Blueprint{}, false
	}
	raw, _ := json.Marshal(d.d.Transition.Selection.Candidate.Plan)
	var p blueprintRecord
	_ = json.Unmarshal(raw, &p)
	return Blueprint{p}, true
}
