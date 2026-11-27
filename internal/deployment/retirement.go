// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
)

type retirementTarget struct {
	Original             Claim
	Drain, Proof, Delete *Mutation
	Gone                 []byte
	Retained             *RetainReceipt
	Closed               bool
}
type retirementRecord struct {
	KeepExecution        bool `json:",omitempty"`
	ID, Actor, Submitter string
	Epoch                uint64
	Revision             uint64
	Down                 bool
	Keys                 []string
	Targets              []retirementTarget
}

// RetirementView is an owned view of the same Inventory journal. It adds no
// authority or alternative state machine; adapters call the existing methods.
type RetirementView struct {
	KeepExecution        bool `json:",omitempty"`
	ID, Actor, Submitter string
	Epoch, Revision      uint64
	Down                 bool
	Targets              []RetirementTarget
}
type RetirementTarget struct {
	Original             Claim
	Drain, Proof, Delete *Mutation
	Gone                 []byte
	Retained             *RetainReceipt
	Closed               bool
}

// Preserves separates an unselected running native from a wave's exact stop
// closure. It grants no authority and never exempts a whole-app retirement.
func (r RetirementView) Preserves(key string) bool {
	if key == "" || !r.KeepExecution || r.Down {
		return false
	}
	for _, target := range r.Targets {
		if target.Original.Step.Key == key {
			return false
		}
	}
	return true
}

func (a Inventory) Retirement() (RetirementView, bool) {
	if a.d.Retirement == nil {
		return RetirementView{}, false
	}
	raw, _ := json.Marshal(a.d.Retirement)
	var view RetirementView
	_ = json.Unmarshal(raw, &view)
	return view, true
}
func (a Inventory) CanRetire(key string) bool { return a.canRetire(key) }
func (a Inventory) Operation(id string) (OperationSummary, bool) {
	if current, ok := a.Active(); ok && current.ID == id {
		return current, true
	}
	for _, summary := range a.d.History {
		if summary.ID == id {
			return summary, true
		}
	}
	return OperationSummary{}, false
}

func lifetimeDependencies(s Step) []Dependency {
	var out []Dependency
	for _, d := range s.Dependencies {
		if !slices.Contains(s.Identity, d.Key) {
			out = append(out, d)
		}
	}
	for _, activation := range s.Activation {
		if i := slices.IndexFunc(out, func(d Dependency) bool { return d.Key == activation.Key }); i >= 0 {
			out[i] = activation
		} else {
			out = append(out, activation)
		}
	}
	return out
}
func (a Inventory) pendingSubmission() bool {
	e, ok := a.Execution()
	if !ok {
		return false
	}
	for _, s := range e.d.Stages {
		if s.Journal.Pending != nil {
			return true
		}
	}
	return false
}
func (a Inventory) target(key string) int {
	if a.d.Retirement == nil {
		return -1
	}
	return slices.IndexFunc(a.d.Retirement.Targets, func(t retirementTarget) bool { return t.Original.Step.Key == key })
}
func (a Inventory) canRetire(key string) bool {
	if a.d.Retirement == nil || a.pendingSubmission() {
		return false
	}
	if at := a.target(key); at >= 0 && a.d.Retirement.KeepExecution {
		target := a.d.Retirement.Targets[at]
		// Once this immutable Drain has been durably dispatched its unknown
		// result/proof/delete must remain collectible even as views advance.
		if target.Original.Step.Kind == "task" && target.Drain != nil && target.Drain.Journal.Pending != nil && target.Drain.Journal.Pending.Phase == reconcile.Prepared && !a.ingressDrainReady(target.Original) {
			return false
		}
	}
	for _, c := range a.d.Claims {
		if c.Removed {
			continue
		}
		for _, d := range lifetimeDependencies(c.Step) {
			if d.Key == key {
				j := a.target(c.Step.Key)
				if j < 0 || !a.d.Retirement.Targets[j].Closed {
					return false
				}
			}
		}
	}
	return true
}

func (a Inventory) ingressDrainReady(task Claim) bool {
	e, active := a.Execution()
	ref := ObjectRef{Key: task.Step.Key, Generation: task.Result.Generation, Revision: task.Result.Revision}
	for _, claim := range a.d.Claims {
		if claim.Removed || claim.Step.Kind != "ingress" || !slices.Contains(claim.Step.Identity, task.Step.Key) {
			continue
		}
		if at := a.target(claim.Step.Key); at >= 0 && a.d.Retirement.Targets[at].Closed {
			continue
		}
		stage, exists := e.Stage(claim.Step.Key)
		if !active || !exists || stage.Result == nil || stage.Result.Generation != claim.Result.Generation || stage.Result.Revision != claim.Result.Revision || stage.Command == nil || stage.Command.Value != claim.Command.Value || stage.Observation == nil || !slices.Contains(stage.Observation.IngressDrained, ref) {
			return false
		}
	}
	return true
}
func retirementNonce(cluster [32]byte, id, key string, generation uint64) [16]byte {
	data := append([]byte("sfc-app-drain-1\x00"), cluster[:]...)
	data = append(data, []byte(id+"\x00"+key)...)
	data = binary.LittleEndian.AppendUint64(data, generation)
	digest := sha256.Sum256(data)
	return [16]byte(digest[:16])
}
func retireCommand(r retirementRecord, c Claim, phase string, value string, expected uint64, remove bool) state.Command {
	return state.Command{Actor: r.Submitter, Epoch: r.Epoch, RequestID: requestID("retire-"+r.ID+"-"+phase+"-"+string(goal(r.Revision)), c.Step.Key+"/"+string(goal(c.Result.Generation))), Key: c.Step.Key, Value: value, Expected: expected, Delete: remove}
}
func (a Inventory) syncRetirement() (Inventory, error) {
	if a.d.Retirement == nil {
		return a, nil
	}
	r := a.d.Retirement
	for _, c := range a.d.Claims {
		if c.Removed || a.target(c.Step.Key) >= 0 || !r.Down && !slices.Contains(r.Keys, c.Step.Key) {
			continue
		}
		t := retirementTarget{Original: c}
		if !c.Step.Retain {
			var g GoalCommand
			if json.Unmarshal([]byte(c.Command.Value), &g) != nil || g.Lifecycle != nil {
				return a, ErrInputs
			}
			if c.Step.Owner == ([32]byte{}) {
				if c.Step.Kind != "delivery" {
					return a, inputError("MODULE_CLOSURE_REQUIRED", c.Step.Key)
				}
				m, err := newMutation(retireCommand(*r, c, "delete", "", c.Result.Revision, true), a.d.Revision)
				if err != nil {
					return a, err
				}
				t.Delete = &m
			} else {
				g.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: retirementNonce(a.d.Cluster, r.ID+"/"+string(goal(r.Revision)), c.Step.Key, c.Result.Generation)}
				m, err := newMutation(retireCommand(*r, c, "drain", string(goal(g)), c.Result.Revision, false), a.d.Revision)
				if err != nil {
					return a, err
				}
				t.Drain = &m
			}
		}
		r.Targets = append(r.Targets, t)
	}
	return a, nil
}

// retirementSelection is the single dependency-closure algorithm used by both
// the explicit impact preview and actual retirement. Planning must not invent
// a smaller stop set than the owner will execute.
func (a Inventory) retirementSelection(keys []string, down bool) (map[string]bool, error) {
	selected := map[string]bool{}
	if down {
		for _, claim := range a.d.Claims {
			if !claim.Removed {
				selected[claim.Step.Key] = true
			}
		}
	} else {
		for _, key := range keys {
			j := a.claim(key)
			if j < 0 || a.d.Claims[j].Removed {
				return nil, ErrInputs
			}
			selected[key] = true
		}
	}
	if len(selected) == 0 && !down {
		return nil, ErrInputs
	}
	for changed := true; changed; {
		changed = false
		for _, claim := range a.d.Claims {
			if claim.Removed {
				continue
			}
			if selected[claim.Step.Key] && claim.Step.Kind == "task" {
				for _, d := range claim.Step.Activation {
					if !selected[d.Key] {
						selected[d.Key] = true
						changed = true
					}
				}
			}
			for _, d := range lifetimeDependencies(claim.Step) {
				if selected[d.Key] && !selected[claim.Step.Key] {
					selected[claim.Step.Key] = true
					changed = true
				}
			}
		}
	}
	return selected, nil
}

// PreviewRetirement returns owned current claims in deterministic key order.
// It changes no state and supplies no authority/closure receipt. Consumers must
// authenticate and bind the chosen targets to their signed operation/CAS.
func (a Inventory) PreviewRetirement(keys []string, down bool) ([]Claim, error) {
	if a.d.Retirement != nil || !down && len(a.d.History) >= 127 {
		return nil, ErrInputs
	}
	selected, err := a.retirementSelection(keys, down)
	if err != nil {
		return nil, err
	}
	if e, ok := a.Execution(); !down && ok && e.Status() != "Succeeded" && e.Status() != "Closed" {
		return nil, inputError("ORIGINAL_OPERATION_PENDING", e.d.Operation)
	}
	var out []Claim
	for _, claim := range a.Claims() {
		if !claim.Removed && selected[claim.Step.Key] {
			out = append(out, claim)
		}
	}
	slices.SortFunc(out, func(a, b Claim) int { return strings.Compare(a.Step.Key, b.Step.Key) })
	return out, nil
}

// Retire selects only owned resources and all affected lifetime dependents.
// Replacing a task also retires its generation-bound private input material.
// Retain targets are settled and kept. A partial initial apply must be stopped
// as one original operation; its unknown submissions are resolved before Drain.
func (a Inventory) Retire(expected uint64, c access.Catalog, actor, id, submitter string, epoch uint64, keys []string, down bool) (Inventory, error) {
	return a.retire(expected, c, actor, id, submitter, epoch, keys, down, false)
}

func (a Inventory) retire(expected uint64, c access.Catalog, actor, id, submitter string, epoch uint64, keys []string, down, keepExecution bool) (Inventory, error) {
	return a.retireAuthorized(expected, c, actor, id, submitter, epoch, keys, down, keepExecution, false)
}

// RetireAcceptedPolicy consumes only the original controller-authenticated
// expiration policy. It creates no placement or start authority.
func (a Inventory) RetireAcceptedPolicy(expected uint64, actor, id, submitter string, epoch uint64) (Inventory, error) {
	return a.retireAuthorized(expected, access.Catalog{}, actor, id, submitter, epoch, nil, true, false, true)
}
func (a Inventory) retireAuthorized(expected uint64, c access.Catalog, actor, id, submitter string, epoch uint64, keys []string, down, keepExecution, accepted bool) (Inventory, error) {
	if expected != a.d.Revision || a.d.Retirement != nil || !identifier(id) || submitter == "" || len(submitter) > 256 || epoch == 0 || (!accepted && c.AuthorizeCleanup(actor, a.d.Tenant, access.Deploy) != nil) {
		return a, ErrInputs
	}
	selected, err := a.retirementSelection(keys, down)
	if err != nil {
		return a, err
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	n.d.Stopping = true
	if e, ok := n.Execution(); ok && e.Status() != "Succeeded" && e.Status() != "Closed" {
		if keepExecution {
			if down || e.d.Replacement == nil || e.d.Replacement.Phase != "retiring" || id != e.replacementRetirementID() || e.d.Submitter != submitter || e.d.Epoch != epoch || a.pendingSubmission() {
				return a, ErrInputs
			}
		} else {
			if !down {
				return a, inputError("ORIGINAL_OPERATION_PENDING", e.d.Operation)
			}
			stopped, err := e.stop(e.Revision(), accepted || c.AuthorizeCleanup(actor, a.d.Tenant, access.Deploy) == nil)
			if err != nil {
				return a, err
			}
			n.d.Active = &stopped.d
		}
	}
	r := retirementRecord{ID: id, Actor: actor, Submitter: submitter, Epoch: epoch, Revision: n.d.Revision, Down: down, KeepExecution: keepExecution}
	for key := range selected {
		r.Keys = append(r.Keys, key)
	}
	slices.Sort(r.Keys)
	n.d.Retirement = &r
	return n.syncRetirement()
}
func (a Inventory) Removal(key, phase string) (Mutation, bool) {
	j := a.target(key)
	if j < 0 {
		return Mutation{}, false
	}
	t := a.d.Retirement.Targets[j]
	var m *Mutation
	switch phase {
	case "drain":
		m = t.Drain
	case "proof":
		m = t.Proof
	case "delete":
		m = t.Delete
	}
	if m == nil {
		return Mutation{}, false
	}
	return m.copy(), true
}
func (a Inventory) modifyRemoval(expected uint64, key, phase string, change func(Mutation) (Mutation, error)) (Inventory, error) {
	if expected != a.d.Revision || !a.canRetire(key) {
		return a, ErrInputs
	}
	j := a.target(key)
	m, ok := a.Removal(key, phase)
	if j < 0 || !ok || a.d.Retirement.Targets[j].Closed {
		return a, ErrInputs
	}
	updated, err := change(m)
	if err != nil {
		return a, err
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	switch phase {
	case "drain":
		n.d.Retirement.Targets[j].Drain = &updated
	case "proof":
		n.d.Retirement.Targets[j].Proof = &updated
	case "delete":
		n.d.Retirement.Targets[j].Delete = &updated
	default:
		return a, ErrInputs
	}
	return n, nil
}
func (a Inventory) SendRemoval(expected uint64, c access.Catalog, actor, key, phase string) (Inventory, error) {
	if c.AuthorizeCleanup(actor, a.d.Tenant, access.Deploy) != nil {
		return a, access.ErrDenied
	}
	return a.modifyRemoval(expected, key, phase, func(m Mutation) (Mutation, error) { return m.dispatch() })
}

// SendAcceptedPolicyRemoval advances an exact already-retained cleanup intent.
// The control caller verifies its accepted policy receipt on every dispatch.
func (a Inventory) SendAcceptedPolicyRemoval(expected uint64, key, phase string) (Inventory, error) {
	return a.modifyRemoval(expected, key, phase, func(m Mutation) (Mutation, error) { return m.dispatch() })
}
func (a Inventory) UnknownRemoval(expected uint64, key, phase string) (Inventory, error) {
	return a.modifyRemoval(expected, key, phase, func(m Mutation) (Mutation, error) { return m.uncertain() })
}

// AuthorizeRemovalReplay requires an explicit current management decision. An
// absent result remains Unknown; only the exact retained Raft proposal may be
// transmitted once. A late result is collected normally instead of replayed.
func (a Inventory) AuthorizeRemovalReplay(expected uint64, c access.Catalog, actor, key, phase, request string, digest [32]byte, shared state.State) (Inventory, error) {
	if c.AuthorizeCleanup(actor, a.d.Tenant, access.Deploy) != nil || request == "" || len(request) > 512 {
		return a, ErrInputs
	}
	return a.modifyRemoval(expected, key, phase, func(m Mutation) (Mutation, error) {
		epoch, retained := shared.LedgerEpoch(m.Command.Actor)
		if m.Result != nil || m.Journal.Pending == nil || m.Journal.Pending.Phase != reconcile.RecoveryRequired || state.Digest(m.Command) != digest ||
			!retained || epoch != m.Command.Epoch || shared.ModuleExpired(m.Command) || m.Replay != nil && (!m.Replay.Dispatched || m.Replay.Request == request) {
			return m, ErrInputs
		}
		if _, found := shared.LookupResult(m.Command); found {
			return m, ErrInputs
		}
		n := m.copy()
		n.Replay = &MutationReplay{Request: request, Revision: expected}
		return n, nil
	})
}
func (a Inventory) SettleRemoval(expected uint64, key, phase string, shared state.State) (Inventory, error) {
	if expected != a.d.Revision {
		return a, ErrInputs
	}
	if m, ok := a.Removal(key, phase); ok && m.Result != nil {
		// A durable original result is final. In particular a duplicate proof
		// result must not replace an already dispatched/unknown Delete journal.
		return a, nil
	}
	n, err := a.modifyRemoval(expected, key, phase, func(m Mutation) (Mutation, error) { return m.settle(shared) })
	if err != nil {
		return a, err
	}
	j := n.target(key)
	t := &n.d.Retirement.Targets[j]
	m, _ := n.Removal(key, phase)
	if m.Result == nil || m.Result.Code != state.Applied {
		return n, nil
	}
	if m.Result.Generation != t.Original.Result.Generation {
		return a, ErrInputs
	}
	if phase == "proof" {
		cmd := retireCommand(*n.d.Retirement, t.Original, "delete", "", m.Result.Revision, true)
		call, err := newMutation(cmd, n.d.Revision)
		if err != nil {
			return a, err
		}
		t.Delete = &call
	} else if phase == "delete" {
		object := shared.Object(key)
		if object.Present || object.Generation != t.Original.Result.Generation || object.Revision != m.Result.Revision {
			return a, ErrInputs
		}
		t.Closed = true
		i := n.claim(key)
		n.d.Claims[i].Removed = true
		n.d.Claims[i].Removal = &RemovalProof{ID: n.d.Retirement.ID, Revision: n.d.Retirement.Revision, Drain: t.Drain, Proof: t.Proof, Delete: t.Delete, Gone: bytes.Clone(t.Gone)}
	}
	return n, nil
}

// Gone is a module-produced positive closure signature over the exact original
// generation and committed Drain intent. Timeout, absent inspect, or a current
// arbitrary object can never create the Proof/Delete requests.
func (a Inventory) Gone(expected uint64, key string, signature []byte) (Inventory, error) {
	j := a.target(key)
	if expected != a.d.Revision || j < 0 || !a.canRetire(key) {
		return a, ErrInputs
	}
	t := a.d.Retirement.Targets[j]
	if t.Drain == nil || t.Drain.Result == nil || t.Drain.Result.Code != state.Applied || t.Proof != nil {
		return a, ErrInputs
	}
	var g GoalCommand
	if json.Unmarshal([]byte(t.Drain.Command.Value), &g) != nil || g.Lifecycle == nil || schema.VerifyGone(t.Original.Step.Owner, a.d.Cluster, key, t.Original.Result.Generation, []byte(t.Drain.Command.Value), signature) != nil {
		return a, ErrInputs
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	g.Lifecycle.Proof = bytes.Clone(signature)
	cmd := retireCommand(*n.d.Retirement, t.Original, "proof", string(goal(g)), t.Drain.Result.Revision, false)
	m, err := newMutation(cmd, n.d.Revision)
	if err != nil {
		return a, err
	}
	n.d.Retirement.Targets[j].Proof = &m
	n.d.Retirement.Targets[j].Gone = bytes.Clone(signature)
	return n, nil
}
func (a Inventory) Retained(expected uint64, key string, o *RetainReceipt) (Inventory, error) {
	j := a.target(key)
	if expected != a.d.Revision || j < 0 || !a.canRetire(key) {
		return a, ErrInputs
	}
	t := a.d.Retirement.Targets[j]
	c := t.Original
	if !c.Step.Retain || t.Closed {
		return a, ErrInputs
	}
	if c.Step.Owner != ([32]byte{}) {
		if o == nil || o.Cluster != a.d.Cluster || o.Retirement != a.d.Retirement.ID || o.StopRevision != a.d.Retirement.Revision || !o.Fenced || o.Key != key || o.Owner != c.Step.Owner || o.Command != state.Digest(c.Command) || o.Generation != c.Result.Generation || o.Revision != c.Result.Revision || !o.Released || !o.Stopped || !o.Retained || o.Gone || o.Pins != 0 || c.Native != "" && o.Native != c.Native || !ed25519.Verify(c.Step.Owner[:], RetainReceiptBytes(*o), o.Signature) {
			return a, ErrInputs
		}
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	n.d.Retirement.Targets[j].Closed = true
	if o != nil {
		copy := *o
		copy.Signature = bytes.Clone(o.Signature)
		o = &copy
	}
	n.d.Retirement.Targets[j].Retained = o
	i := n.claim(key)
	n.d.Claims[i].Retained = true
	n.d.Claims[i].RetainProof = o
	return n, nil
}
func (a Inventory) FinishRetirement(expected uint64) (Inventory, error) {
	if expected != a.d.Revision || a.d.Retirement == nil || a.pendingSubmission() {
		return a, ErrInputs
	}
	for _, t := range a.d.Retirement.Targets {
		if !t.Closed {
			return a, ErrInputs
		}
	}
	n, err := a.clone()
	if err != nil {
		return a, err
	}
	if e, ok := n.Execution(); ok {
		if n.d.Retirement.KeepExecution {
			updated, err := n.finishReplacementRetirement(e)
			if err != nil {
				return a, err
			}
			n.d.Active = &updated.d
		} else {
			n.d.History = append(n.d.History, summarize(e, "Retired"))
			n.d.Active = nil
		}
	}
	n.d.Retirement = nil
	n.d.Stopping = false
	return n, nil
}

type RetainReceipt struct {
	Cluster                                   [32]byte
	Retirement, Key, Native                   string
	StopRevision                              uint64
	Owner                                     [32]byte
	Command                                   [32]byte
	Generation, Revision                      uint64
	Released, Stopped, Retained, Gone, Fenced bool
	Pins                                      uint64
	Signature                                 []byte
}

func RetainReceiptBytes(o RetainReceipt) []byte {
	o.Signature = nil
	return append([]byte("sfc-app-retained-1\x00"), goal(o)...)
}

type RemovalProof struct {
	ID                   string
	Revision             uint64
	Drain, Proof, Delete *Mutation
	Gone                 []byte
}
