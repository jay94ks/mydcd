// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type Claim struct {
	Removal           *RemovalProof
	RetainProof       *RetainReceipt
	Step              Step
	Command           state.Command
	Result            state.Result
	Operation         string
	Plan              [32]byte
	Native            string
	Observation       *Observation
	Retained, Removed bool
}

// NeverObservedNative stands for the native ID of a Task whose container was
// never created or observed (for example its recipe was rejected). Closure
// and address-release proofs need a non-empty ID, and both sides use this one.
const NeverObservedNative = "never-observed"

// ClosedNative is the native ID that closure proofs carry for c.
func (c Claim) ClosedNative() string {
	if c.Native == "" {
		return NeverObservedNative
	}
	return c.Native
}

type OperationSummary struct {
	Failed      bool `json:",omitempty"`
	ID, Status  string
	Plan        [32]byte
	CompletedAt uint64
	Submitter   string
	Epoch       uint64
}
type inventoryRecord struct {
	Schema                  uint8
	Cluster                 [32]byte
	Tenant, App, Deployment string
	Revision                uint64
	Active                  *executionRecord
	History                 []OperationSummary
	MinEpoch                map[string]uint64
	Claims                  []Claim
	Stopping                bool
	Retirement              *retirementRecord
}

// Inventory is the one app's shared ownership/operation index. It belongs in
// the same FSM transaction as its commands/results; it is not a replication
// protocol or a copy of node-local journals/data. Old operations are summarized
// only after their exact commands/results have become durable owned claims.
type Inventory struct{ d inventoryRecord }

func NewInventory(cluster [32]byte, tenant, app, deployment string) (Inventory, error) {
	if cluster == ([32]byte{}) || !identifier(tenant) || !identifier(app) || !identifier(deployment) {
		return Inventory{}, ErrInputs
	}
	return Inventory{inventoryRecord{Schema: 1, Cluster: cluster, Tenant: tenant, App: app, Deployment: deployment, Revision: 1}}, nil
}
func (a Inventory) Revision() uint64 { return a.d.Revision }
func (a Inventory) clone() (Inventory, error) {
	if a.d.Schema != 1 || a.d.Revision == ^uint64(0) {
		return a, ErrInputs
	}
	raw, err := json.Marshal(a.d)
	if err != nil {
		return a, err
	}
	var d inventoryRecord
	if json.Unmarshal(raw, &d) != nil {
		return a, ErrInputs
	}
	d.Revision++
	return Inventory{d}, nil
}
func (a Inventory) Claims() []Claim {
	raw, _ := json.Marshal(a.d.Claims)
	var out []Claim
	_ = json.Unmarshal(raw, &out)
	return out
}
func (a Inventory) Execution() (Execution, bool) {
	if a.d.Active == nil {
		return Execution{}, false
	}
	// Execution's private record is immutable. Transitions clone before any
	// write, and public accessors copy mutable fields. Reading this view must
	// not serialize the whole plan on every policy/health query.
	return Execution{*a.d.Active}, true
}
func (a Inventory) claim(key string) int {
	return slices.IndexFunc(a.d.Claims, func(c Claim) bool { return c.Step.Key == key })
}
func (a Inventory) scope(b Blueprint) bool {
	return a.d.Cluster == b.d.Cluster && a.d.Tenant == b.d.Tenant && a.d.App == b.d.App && a.d.Deployment == b.d.Deployment
}

type Change struct {
	Key, Action, Reason string
	Current             ObjectRef
	Retain              bool
	// Interruption, for a replaced Task, says why its service stops while
	// it is replaced (InterruptionCodes); "" when other replicas serve.
	Interruption string `json:",omitempty"`
}

func sameConfig(claim Claim, step Step) bool {
	var g GoalCommand
	return json.Unmarshal([]byte(claim.Command.Value), &g) == nil && g.Kind == step.Kind && g.Node == step.Node && g.Owner == step.Owner && bytes.Equal(g.Config, step.Goal) && bytes.Equal(goal(claim.Step.Dependencies), goal(step.Dependencies)) && bytes.Equal(goal(claim.Step.Identity), goal(step.Identity)) && bytes.Equal(goal(g.Activation), goal(step.Activation))
}

// Changes distinguishes retained/orphaned inventory from a deletion request.
// A source fetch/parser error supplies no Blueprint and must never call this
// method with a synthetic empty application.
func (a Inventory) Changes(b Blueprint, prune bool) ([]Change, error) {
	if !a.scope(b) {
		return nil, ErrInputs
	}
	next := map[string]Step{}
	var out []Change
	for _, s := range b.d.Steps {
		next[s.Key] = s
		change := Change{Key: s.Key, Action: "Create", Retain: s.Retain}
		if i := a.claim(s.Key); i >= 0 {
			old := a.d.Claims[i]
			change.Current = ObjectRef{s.Key, old.Result.Revision, old.Result.Generation}
			if !old.Removed {
				if sameConfig(old, s) {
					change.Action = "Keep"
				} else {
					change.Action = "Replace"
					change.Reason = "original native closure and new generation required"
					if old.Step.Node == s.Node && old.Step.Owner == s.Owner {
						if IngressRuntimeUpdate(old, s) {
							change.Action = "RuntimeUpdate"
							change.Reason = "same listener and original ingress native identity"
						}
						switch s.Kind {
						case "dns", "namespace", "delivery", "volume":
							change.Action = "RuntimeUpdate"
							change.Reason = "same owner and current module policy required"
						}
					}
					if s.Kind == "volume" && (old.Step.Node != s.Node || old.Step.Owner != s.Owner) {
						change.Action = "MoveRequired"
						change.Reason = "D2 writer/fence/owner CAS required"
					}
				}
			}
		}
		out = append(out, change)
	}
	// A consumer's config alone is insufficient: its exact producer position
	// and any planned producer replacement/update affect its native binding.
	for changed := true; changed; {
		changed = false
		for i := range out {
			if out[i].Action != "Keep" && !(out[i].Action == "RuntimeUpdate" && next[out[i].Key].Kind == "ingress") {
				continue
			}
			step := next[out[i].Key]
			old := a.d.Claims[a.claim(step.Key)]
			var g GoalCommand
			_ = json.Unmarshal([]byte(old.Command.Value), &g)
			stale := false
			for _, ref := range g.Dependencies {
				if producer, ok := next[ref.Key]; !ok || producer.Base != ref || !producer.BasePresent {
					if !ok || !stableDNSReference(step, producer, ref) {
						stale = true
					}
				}
			}
			for _, dep := range append(slices.Clone(step.Dependencies), step.Activation...) {
				if ingressIdentity(step, dep.Key) {
					continue
				}
				for _, action := range out {
					if action.Key == dep.Key && action.Action != "Keep" {
						producer := next[dep.Key]
						at := slices.IndexFunc(step.StableDNS, func(ref ObjectRef) bool { return ref.Key == dep.Key })
						if action.Action != "RuntimeUpdate" || at < 0 || !stableDNSReference(step, producer, step.StableDNS[at]) {
							stale = true
						}
					}
				}
			}
			if stale {
				out[i].Action, out[i].Reason = "Replace", "dependency generation or desired binding changed"
				changed = true
			}
		}
	}
	for _, old := range a.d.Claims {
		if old.Removed {
			continue
		}
		if _, ok := next[old.Step.Key]; ok {
			continue
		}
		action := "KeepOrphan"
		if prune {
			action = "Remove"
		}
		if old.Step.Retain {
			action = "Retain"
		}
		out = append(out, Change{Key: old.Step.Key, Action: action, Current: ObjectRef{old.Step.Key, old.Result.Revision, old.Result.Generation}, Retain: old.Step.Retain})
	}
	annotateInterruptions(b.d.Steps, out)
	slices.SortFunc(out, func(x, y Change) int { return strings.Compare(x.Key, y.Key) })
	return out, nil
}

func (a Inventory) Begin(expected uint64, c access.Catalog, ctx PlanningContext, b Blueprint, id, submitter string, epoch uint64, prune bool) (Inventory, error) {
	return a.begin(expected, c, ctx, b, id, submitter, epoch, prune, nil, false)
}

// BeginDeploy is Begin for an explicit user deploy (begin-app). It also
// replaces an edited Task kept alone on its node (DeployReplacementPlan).
func (a Inventory) BeginDeploy(expected uint64, c access.Catalog, ctx PlanningContext, b Blueprint, id, submitter string, epoch uint64, prune bool) (Inventory, error) {
	return a.begin(expected, c, ctx, b, id, submitter, epoch, prune, nil, true)
}

func (a Inventory) begin(expected uint64, c access.Catalog, ctx PlanningContext, b Blueprint, id, submitter string, epoch uint64, prune bool, moved []volumes.Binding, edits bool) (Inventory, error) {
	if expected != a.d.Revision || !a.scope(b) || a.d.Stopping || a.d.Retirement != nil || len(a.d.History) >= 127 || epoch < a.d.MinEpoch[submitter] {
		return a, ErrInputs
	}
	if slices.ContainsFunc(a.d.History, func(o OperationSummary) bool { return o.ID == id }) {
		return a, ErrInputs
	}
	if old, ok := a.Execution(); ok {
		if old.d.Operation == id {
			if (Blueprint{old.d.Plan}).Digest() == b.Digest() && old.d.Submitter == submitter && old.d.Epoch == epoch {
				return a, nil
			}
			return a, ErrInputs
		}
		if old.Status() != "Succeeded" && old.Status() != "Closed" {
			return a, inputError("ORIGINAL_OPERATION_PENDING", old.d.Operation)
		}
	}
	changes, err := a.Changes(b, prune)
	if err != nil {
		return a, err
	}
	if moved == nil {
		for _, change := range changes {
			if change.Action == "MoveRequired" {
				return a, inputError("TRANSITION_REQUIRED", change.Key)
			}
		}
		plan, err := a.replacementPlan(b, prune, edits)
		if err != nil {
			return a, err
		}
		if plan != nil {
			return a.beginReplacement(c, ctx, b, id, submitter, epoch, *plan)
		}
	}
	for _, change := range changes {
		if change.Action == "MoveRequired" && moved != nil {
			old := a.d.Claims[a.claim(change.Key)]
			for _, step := range b.Steps() {
				accepted := false
				for _, binding := range moved {
					accepted = accepted || a.retainedVolumeHandoff(old, step, ctx.Volumes, binding)
				}
				if step.Key == change.Key && accepted {
					change.Action = "RuntimeUpdate"
					break
				}
			}
		}
		if change.Action == "Replace" || change.Action == "Remove" || change.Action == "MoveRequired" {
			return a, inputError("TRANSITION_REQUIRED", change.Key)
		}
	}
	e, err := NewExecution(b, c, ctx, id, submitter, epoch)
	if err != nil {
		return a, err
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	if n.d.Active != nil {
		old := Execution{*n.d.Active}
		n.d.History = append(n.d.History, summarize(old, old.Status()))
	}
	n.d.Active = &e.d
	return n, nil
}

func summarize(e Execution, status string) OperationSummary {
	return OperationSummary{ID: e.d.Operation, Status: status, Plan: (Blueprint{e.d.Plan}).Digest(), CompletedAt: e.d.CompletedAt, Submitter: e.d.Submitter, Epoch: e.d.Epoch, Failed: e.failed()}
}

// OperationExpired uses only this inventory's consumed committed ledger floor.
// It proves an old request window expired, never native non-execution.
func (a Inventory) OperationExpired(submitter string, epoch uint64) bool {
	return epoch != 0 && a.d.MinEpoch[submitter] > epoch
}

// RotateWindow compacts only settled history after the existing A1 ledger has
// durably moved every original submitter to a newer epoch. Claims, native IDs,
// pins and closure proofs survive. It never invents a new epoch or rotates an
// unsettled operation merely to create space for another request.
func (a Inventory) RotateWindow(expected uint64, c access.Catalog, actor string, shared state.State) (Inventory, error) {
	if expected != a.d.Revision || a.d.Stopping || a.d.Retirement != nil || c.AuthorizeCleanup(actor, a.d.Tenant, access.Deploy) != nil {
		return a, ErrInputs
	}
	summaries := slices.Clone(a.d.History)
	if e, ok := a.Execution(); ok {
		if e.Status() != "Succeeded" && e.Status() != "Closed" {
			return a, inputError("ORIGINAL_OPERATION_PENDING", e.d.Operation)
		}
		summaries = append(summaries, summarize(e, e.Status()))
	}
	if len(summaries) == 0 {
		return a, nil
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	if n.d.MinEpoch == nil {
		n.d.MinEpoch = map[string]uint64{}
	}
	for _, summary := range summaries {
		epoch, ok := shared.LedgerEpoch(summary.Submitter)
		if !ok || epoch <= summary.Epoch {
			return a, inputError("COMMITTED_EPOCH_REQUIRED", summary.Submitter)
		}
		if n.d.MinEpoch[summary.Submitter] < epoch {
			n.d.MinEpoch[summary.Submitter] = epoch
		}
	}
	n.d.History, n.d.Active = nil, nil
	return n, nil
}

// sameOrExpired reports whether next is prior, or prior newly marked Expired.
func sameOrExpired(prior, next Observation) bool {
	if bytes.Equal(goal(prior), goal(next)) {
		return true
	}
	if prior.Expired || !next.Expired {
		return false
	}
	next.Expired = false
	return bytes.Equal(goal(prior), goal(next))
}

func progress(old, next Execution) bool {
	if !bytes.Equal(goal(old.d.Replacement), goal(next.d.Replacement)) {
		return false
	}
	if next.d.Revision < old.d.Revision || next.d.Operation != old.d.Operation || next.d.Submitter != old.d.Submitter || next.d.Epoch != old.d.Epoch || (Blueprint{next.d.Plan}).Digest() != (Blueprint{old.d.Plan}).Digest() || old.d.Stopping && !next.d.Stopping || old.d.Closed && !next.d.Closed || old.d.CompletedAt != 0 && (old.d.CompletedAt != next.d.CompletedAt || !bytes.Equal(goal(old.d.CompletionWitness), goal(next.d.CompletionWitness))) {
		return false
	}
	for i, prior := range old.d.Stages {
		s := next.d.Stages[i]
		if !bytes.Equal(goal(prior.Previous), goal(s.Previous)) {
			return false
		}
		if prior.Command != nil && (s.Command == nil || *s.Command != *prior.Command) || prior.Result != nil && (s.Result == nil || *s.Result != *prior.Result) {
			return false
		}
		if prior.Replay != nil && (s.Replay == nil || s.Replay.Request == prior.Replay.Request && prior.Replay.Dispatched && !s.Replay.Dispatched || s.Replay.Request != prior.Replay.Request && !prior.Replay.Dispatched) {
			return false
		}
		// Only the dispatch of a new replay grant moves Unknown back to Dispatched.
		replayed := prior.Replay != nil && !prior.Replay.Dispatched && s.Replay != nil && s.Replay.Dispatched && s.Replay.Request == prior.Replay.Request
		if prior.Journal.Pending != nil && prior.Journal.Pending.Phase >= reconcile.Dispatched && s.Journal.Pending != nil && s.Journal.Pending.Phase < prior.Journal.Pending.Phase && !replayed {
			return false
		}
		if prior.Observation != nil && (s.Observation == nil || s.Observation.Sequence < prior.Observation.Sequence || s.Observation.Sequence == prior.Observation.Sequence && !sameOrExpired(*prior.Observation, *s.Observation)) {
			return false
		}
		if prior.Observation != nil && !s.Observation.Released && (!validInstanceTransition(*prior.Observation, *s.Observation) || !validExitTransition(*prior.Observation, *s.Observation)) {
			return false
		}
	}
	return true
}

// Advance consumes legitimate progress of the original execution. New commit
// results must be present in the authoritative A1 ledger (or an exact current
// object for a no-op). A missed/rotated lookup is not non-execution. Previously
// captured results need not be looked up again after their ledger window ends.
func (a Inventory) Advance(expected uint64, next Execution, shared state.State) (Inventory, error) {
	return a.advance(expected, next, shared, nil)
}

func (a Inventory) AdvanceWithVolumes(expected uint64, next Execution, shared state.State, current map[string]volumes.State) (Inventory, error) {
	return a.advance(expected, next, shared, current)
}

func (a Inventory) advance(expected uint64, next Execution, shared state.State, current map[string]volumes.State) (Inventory, error) {
	old, ok := a.Execution()
	switch {
	case !ok:
		return a, inputError("ADVANCE_NO_EXECUTION", "advance")
	case expected != a.d.Revision:
		return a, inputError("ADVANCE_REVISION", "advance")
	case next.validate() != nil:
		return a, inputError("ADVANCE_INVALID_EXECUTION", "advance")
	case !progress(old, next):
		return a, inputError("ADVANCE_NOT_PROGRESS", "advance")
	}
	if next.d.Revision == old.d.Revision {
		if bytes.Equal(goal(next.d), goal(old.d)) {
			return a, nil
		}
		return a, inputError("ADVANCE_GOAL_CHANGED", "advance")
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	for i, s := range next.d.Stages {
		if s.Result == nil {
			continue
		}
		if old.d.Stages[i].Result == nil {
			if s.Noop {
				o := shared.Object(s.Key)
				if !o.Present || o.Value != s.Command.Value || o.Revision != s.Result.Revision || o.Generation != s.Result.Generation {
					return a, inputError("ADVANCE_NOOP_RESULT", "advance")
				}
			} else {
				r, found := shared.LookupResult(*s.Command)
				if !found || r != *s.Result {
					return a, inputError("ADVANCE_RESULT_NOT_FOUND", "advance")
				}
			}
		}
		if s.Result.Code != state.Applied {
			continue
		}
		step := next.d.Plan.Steps[i]
		claim := Claim{Step: step, Command: *s.Command, Result: *s.Result, Operation: next.d.Operation, Plan: (Blueprint{next.d.Plan}).Digest(), Observation: s.Observation}
		j := n.claim(s.Key)
		if j >= 0 {
			prior := n.d.Claims[j]
			if s.Noop && !prior.Removed && !prior.Retained {
				// No native mutation occurred. Keep the actual effect's original
				// command/receipt and binding provenance; the current Execution
				// separately owns its new logical step and fresh observations.
				if prior.Result != *s.Result || prior.Command.Value != s.Command.Value || prior.Step.Owner != step.Owner || prior.Step.Node != step.Node {
					return a, inputError("ORIGINAL_NOOP_SOURCE_CHANGED", s.Key)
				}
				continue
			}
			if at := a.target(s.Key); s.Noop && at >= 0 && a.d.Retirement.Targets[at].Original.Command == prior.Command && prior.Result == *s.Result {
				// The running retirement removed or retained this same original
				// effect. A later report of the Noop stage changes nothing: the
				// claim keeps the command its retirement target recorded.
				continue
			}
			rebound := false
			if prior.Step.Kind == "volume" && (prior.Step.Owner != step.Owner || prior.Step.Node != step.Node) {
				volume := current[a.d.Tenant+"/"+a.d.App+"/"+step.Key[strings.LastIndexByte(step.Key, '/')+1:]]
				for _, move := range volume.Moves() {
					rebound = rebound || a.retainedVolumeHandoff(prior, step, current, move.Binding)
				}
			}
			if claim.Result.Generation < prior.Result.Generation || claim.Result.Generation == prior.Result.Generation && claim.Result.Revision < prior.Result.Revision {
				return a, inputError("ADVANCE_GENERATION_REGRESSED", "advance")
			}
			if claim.Result.Generation != prior.Result.Generation && !prior.Removed {
				return a, inputError("ORIGINAL_GENERATION_NOT_RELEASED", s.Key)
			}
			if !prior.Removed && !rebound && (prior.Step.Node != step.Node || prior.Step.Owner != step.Owner) {
				return a, inputError("ORIGINAL_OWNER_NOT_RELEASED", s.Key)
			}
			if claim.Result.Generation == prior.Result.Generation && !rebound {
				claim.Native = prior.Native
				claim.Removed = prior.Removed
				claim.Removal = prior.Removal
				if claim.Command == prior.Command {
					claim.Retained, claim.RetainProof = prior.Retained, prior.RetainProof
				}
			}
		}
		if s.Observation != nil {
			if claim.Native != "" && claim.Native != s.Observation.Native {
				return a, inputError("NATIVE_IDENTITY_CHANGED", s.Key)
			}
			claim.Native = s.Observation.Native
			claim.Retained = claim.Retained || step.Retain && s.Observation.Released && s.Observation.Retained
		}
		if j < 0 {
			if len(n.d.Claims) >= 1024 {
				return a, inputError("ADVANCE_TOO_MANY_CLAIMS", "advance")
			}
			n.d.Claims = append(n.d.Claims, claim)
		} else {
			n.d.Claims[j] = claim
		}
	}
	slices.SortFunc(n.d.Claims, func(x, y Claim) int { return strings.Compare(x.Step.Key, y.Step.Key) })
	n.d.Active = &next.d
	// Own a clone, not an alias to a caller's decoded execution slices.
	raw, _ := json.Marshal(n.d)
	_ = json.Unmarshal(raw, &n.d)
	return n.syncRetirement()
}
