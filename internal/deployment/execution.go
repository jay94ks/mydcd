// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

type ObjectRef struct {
	Key                  string
	Revision, Generation uint64
}

// GoalCommand is shared declaration metadata. A real module adapter must verify
// the typed goal, refs, current input/writer gates and native ownership before
// effect. It is not the existing legacy ContainerSpec or a claim of readiness.
type GoalCommand struct {
	ResourceKeys                        []lifecycle.IdentityTransition `json:",omitempty"`
	Follow                              []string                       `json:",omitempty"` // explicit Ingress backend identities, not lifetime dependencies
	Lifecycle                           *schema.Lifecycle              `json:",omitempty"`
	Activation                          []Dependency                   `json:",omitempty"`
	Schema                              uint8
	Cluster                             [32]byte
	Tenant, App, Deployment, Kind, Node string
	Owner                               [32]byte
	Config                              json.RawMessage
	Dependencies                        []ObjectRef
}
type StageRecord struct {
	Previous    *Claim `json:",omitempty"` // original native held until positive replacement closure
	Key         string
	Command     *state.Command
	Journal     reconcile.State // A2 journals the management submission, not native Ready
	Result      *state.Result
	Noop        bool
	Observation *Observation
	// Replay is an explicit authorization to send the same Command again
	// after its first send was left Unknown.
	Replay *MutationReplay `json:",omitempty"`
}

type executionRecord struct {
	Replacement              *replacementExecution `json:",omitempty"`
	Schema                   uint8
	Plan                     blueprintRecord
	Operation, Submitter     string
	Epoch, Revision          uint64
	Paused, Stopping, Closed bool
	CompletedAt              uint64
	CompletionWitness        []Observation
	Stages                   []StageRecord
	// Images: the deploy's tag resolutions (execution_images.go), nil until
	// resolved.
	Images []ImageResolution `json:",omitempty"`
}

// Execution shares an immutable private record with read-only Inventory views.
// Every transition must clone before writing; public mutable values are owned
// copies, so neither another reader nor the original Inventory can be changed.
type Execution struct{ d executionRecord }

func NewExecution(b Blueprint, c access.Catalog, ctx PlanningContext, operation, submitter string, epoch uint64) (Execution, error) {
	if !identifier(operation) || submitter == "" || len(submitter) > 256 || epoch == 0 {
		return Execution{}, ErrInputs
	}
	if e := b.ValidateCurrent(c, ctx); e != nil {
		return Execution{}, e
	}
	e := Execution{executionRecord{Schema: 1, Plan: b.d, Operation: operation, Submitter: submitter, Epoch: epoch, Revision: 1}}
	for _, s := range b.Steps() {
		e.d.Stages = append(e.d.Stages, StageRecord{Key: s.Key})
	}
	return e.cloneAt(1)
}
func (e Execution) cloneAt(revision uint64) (Execution, error) {
	raw, err := json.Marshal(e.d)
	if err != nil {
		return e, err
	}
	var d executionRecord
	if json.Unmarshal(raw, &d) != nil {
		return e, ErrInputs
	}
	d.Revision = revision
	return Execution{d}, nil
}
func (e Execution) clone() (Execution, error) {
	if e.d.Schema != 1 || e.d.Revision == ^uint64(0) {
		return e, ErrInputs
	}
	return e.cloneAt(e.d.Revision + 1)
}
func (e Execution) Revision() uint64 { return e.d.Revision }
func (e Execution) index(key string) int {
	return slices.IndexFunc(e.d.Stages, func(s StageRecord) bool { return s.Key == key })
}
func (e Execution) Stage(key string) (StageRecord, bool) {
	i := e.index(key)
	if i < 0 {
		return StageRecord{}, false
	}
	raw, _ := json.Marshal(e.d.Stages[i])
	var s StageRecord
	_ = json.Unmarshal(raw, &s)
	return s, true
}

// StageDigest names the stage record a member planned a stage report
// against. A stage report applies while that record is unchanged, however far
// the rest of the app has moved; "" when key is not a stage.
func (e Execution) StageDigest(key string) string {
	i := e.index(key)
	if i < 0 {
		return ""
	}
	raw, _ := json.Marshal(e.d.Stages[i])
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func requestID(operation, key string) string {
	h := sha256.Sum256([]byte(key))
	return operation + "/" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:]))
}
func (s Step) Action() access.Action {
	action := access.Deploy
	switch s.Kind {
	case "bridge", "tunnel", "network-ref":
		action = access.ManageNetwork
	case "dns":
		action = access.ManageServices
	case "volume":
		action = access.ManageVolumes
	case "namespace":
		action = access.ManageSecrets
	case "registry":
		action = access.ManageRegistry
	case "route":
		action = access.ManageRoutes
	case "delivery":
		action = access.ManageCD
	}
	return action
}

func (e Execution) authorize(c access.Catalog, i int) error {
	b := e.d.Plan
	s := b.Steps[i]
	action := s.Action()
	if err := c.Authorize(b.Actor, b.Tenant, action, s.Node); err != nil {
		return err
	}
	if s.Kind == "task" {
		var service ComposeService
		if json.Unmarshal(s.Goal, &service) != nil {
			return ErrInputs
		}
		if _, err := c.CheckImageRef(b.Actor, b.Tenant, s.Node, service.Image); err != nil {
			return err
		}
	}

	if s.Kind == "registry" {
		var r RegistryDeclaration
		if json.Unmarshal(s.Goal, &r) != nil {
			return ErrInputs
		}
		if _, err := c.CheckImage(b.Actor, b.Tenant, s.Node, r.Image); err != nil {
			return err
		}
	}
	return nil
}
func (e Execution) satisfies(i int, condition Condition, now uint64) bool {
	s := e.d.Stages[i]
	if s.Result == nil || s.Result.Code != state.Applied {
		return false
	}
	if condition == Committed {
		return true
	}
	o := s.Observation
	if o == nil || !o.Live(now) {
		return false
	}
	switch condition {
	case Applied:
		return appliedObservation(*o)
	case Healthy:
		return o.Applied && o.Healthy && e.ingressAllReady(i, *o)
	case Completed:
		return successfulCompletion(*o)
	case Released:
		return o.Released && o.Stopped && o.Pins == 0 && (e.d.Plan.Steps[i].Retain && o.Retained || !e.d.Plan.Steps[i].Retain && o.Gone)
	}
	return false
}
func (e Execution) dependencies(i int, now uint64) bool {
	if !e.imagesReady(i) {
		return false
	}
	for _, d := range e.d.Plan.Steps[i].Dependencies {
		if ingressIdentity(e.d.Plan.Steps[i], d.Key) {
			continue // backend availability is observed independently by the listener
		}
		index := e.index(d.Key)
		if index < 0 || !e.satisfies(index, d.Condition, now) {
			return false
		}
	}
	return true
}

// Waiting describes up to limit steps that have no command yet (or are only
// prepared), with their server and unmet dependencies.
func (e Execution) Waiting(now uint64, limit int) []string {
	var out []string
	for i, step := range e.d.Plan.Steps {
		s := e.d.Stages[i]
		if s.Result != nil || s.Command != nil && (s.Journal.Pending == nil || s.Journal.Pending.Phase != reconcile.Prepared) {
			continue
		}
		if len(out) == limit {
			out = append(out, "...")
			break
		}
		if pending := e.WaitingOn(step.Key, now); len(pending) > 0 {
			out = append(out, fmt.Sprintf("%s on %s waits on %s", step.Key, step.Node, strings.Join(pending, ", ")))
			continue
		}
		out = append(out, fmt.Sprintf("%s on %s is ready; its server has not started it (see that server's log)", step.Key, step.Node))
	}
	return out
}

// WaitingOn describes the dependencies of key that do not yet meet their
// condition, for logs and status only; admission still uses dependencies.
func (e Execution) WaitingOn(key string, now uint64) []string {
	i := e.index(key)
	if i < 0 {
		return nil
	}
	var out []string
	if !e.imagesReady(i) {
		out = append(out, "image tag resolution")
	}
	for _, d := range e.d.Plan.Steps[i].Dependencies {
		if ingressIdentity(e.d.Plan.Steps[i], d.Key) {
			continue
		}
		j := e.index(d.Key)
		if j < 0 {
			out = append(out, d.Key+" (not in the plan)")
			continue
		}
		if e.satisfies(j, d.Condition, now) {
			continue
		}
		s := e.d.Stages[j]
		why := "no result yet"
		switch {
		case s.Result != nil && s.Result.Code != state.Applied:
			why = fmt.Sprintf("result %v", s.Result.Code)
		case s.Result != nil && s.Observation == nil:
			why = "not observed yet"
		case s.Result != nil && s.Observation.At > now:
			why = "observed in the future"
		case s.Result != nil && s.Observation.Expired:
			why = fmt.Sprintf("owner stopped reporting %ds ago", now-s.Observation.At)
		case s.Result != nil:
			why = "observed, not yet " + string(d.Condition)
		}
		out = append(out, fmt.Sprintf("%s (%s %s: %s)", d.Key, e.d.Plan.Steps[j].Node, d.Condition, why))
	}
	return out
}
func (e Execution) commandValue(i int) (string, error) {
	b := e.d.Plan
	s := b.Steps[i]
	g := GoalCommand{Schema: 1, Cluster: b.Cluster, Tenant: b.Tenant, App: b.App, Deployment: b.Deployment, Kind: s.Kind, Node: s.Node, Owner: s.Owner, Config: bytes.Clone(s.Goal), Activation: slices.Clone(s.Activation)}
	if n := b.Nodes[s.Node]; n.Key == s.Owner {
		g.ResourceKeys = lifecycle.OwnIdentityTransitions(n.ResourceKeys)
	}
	if s.Kind == "ingress" {
		g.Follow = slices.Clone(s.Identity)
	}
	for _, d := range s.Dependencies {
		if ingressIdentity(s, d.Key) {
			continue
		}
		j := e.index(d.Key)
		if j < 0 || e.d.Stages[j].Result == nil || e.d.Stages[j].Result.Code != state.Applied {
			return "", ErrInputs
		}
		r := e.d.Stages[j].Result
		ref := ObjectRef{d.Key, r.Revision, r.Generation}
		for _, stable := range s.Stable {
			if stable.Key == d.Key {
				if stable.Generation != r.Generation {
					// A Task producer the planner judged alias-only may
					// still have been replaced (its claim was not
					// current); the consumer then follows the new one.
					if b.Steps[j].Kind == "task" {
						continue
					}
					return "", ErrInputs
				}
				ref = stable
			}
		}
		g.Dependencies = append(g.Dependencies, ref)
	}
	raw, err := json.Marshal(g)
	if err != nil || len(raw) > 64<<10 {
		return "", ErrInputs
	}
	return string(raw), nil
}

// Prepare freezes exact actor/epoch/request/key/CAS/value after dependencies
// have committed and met their distinct native gates. Persist the candidate
// BEFORE Send. A repeated prepare returns the original command unchanged.
func (e Execution) Prepare(c access.Catalog, expected uint64, key string, base state.Object, now uint64) (Execution, state.Command, error) {
	i := e.index(key)
	if i < 0 || expected != e.d.Revision || e.d.Closed || e.d.Stopping || e.d.Paused || e.d.CompletedAt != 0 {
		return e, state.Command{}, ErrInputs
	}
	if err := e.authorize(c, i); err != nil {
		return e, state.Command{}, err
	}
	if old := e.d.Stages[i].Command; old != nil {
		return e, *old, nil
	}
	if !e.replacementAllows(i) {
		return e, state.Command{}, inputError("REPLACEMENT_WAVE_PENDING", key)
	}
	baseRef, present := e.preparationBase(i)
	if base.Revision != baseRef.Revision || base.Generation != baseRef.Generation || base.Present != present {
		return e, state.Command{}, inputError("PLAN_BASE_CONFLICT", key)
	}
	if !e.dependencies(i, now) {
		return e, state.Command{}, inputError("DEPENDENCY_PENDING", key)
	}
	value, err := e.commandValue(i)
	if err != nil {
		return e, state.Command{}, err
	}
	if r := e.d.Replacement; r != nil && (r.Phase == "retiring" || r.Phase == phaseSurging && !e.surgeTask(i)) && (!base.Present || base.Value != value) {
		return e, state.Command{}, inputError("REPLACEMENT_WAVE_PENDING", key)
	}
	if e.replacementFutureNode(i) && (!base.Present || base.Value != value) {
		return e, state.Command{}, inputError("REPLACEMENT_WAVE_PENDING", key)
	}
	cmd := state.Command{Actor: e.d.Submitter, Epoch: e.d.Epoch, RequestID: requestID(e.d.Operation, key), Key: key, Value: value, Expected: base.Revision}
	// A surged target replaces a native that keeps running: its object gets
	// a new generation in place.
	cmd.Renew = present && e.surgeTarget(i)
	n, err := e.clone()
	if err != nil {
		return e, state.Command{}, err
	}
	n.d.Stages[i].Command = &cmd
	if !cmd.Renew && base.Present && base.Value == value && base.Revision > 0 && base.Generation > 0 {
		n.d.Stages[i].Noop = true
		n.d.Stages[i].Result = &state.Result{Code: state.Applied, Index: base.Revision, Revision: base.Revision, Generation: base.Generation}
		return n, cmd, nil
	}
	j, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: n.d.Revision, Resource: reconcile.Resource{Generation: n.d.Revision, Spec: string(goal(cmd)), Present: true}})
	if err != nil {
		return e, state.Command{}, err
	}
	j, _, err = reconcile.Plan(j)
	if err != nil {
		return e, state.Command{}, err
	}
	n.d.Stages[i].Journal = j
	return n, cmd, nil
}
func (e Execution) Send(c access.Catalog, expected uint64, key string, now uint64) (Execution, state.Command, error) {
	i := e.index(key)
	if i < 0 || expected != e.d.Revision || e.d.Closed || e.d.Paused || e.d.Stopping || e.d.CompletedAt != 0 || !e.replacementAllows(i) || e.d.Stages[i].Command == nil || e.d.Stages[i].Noop || e.d.Stages[i].Result != nil || !e.dependencies(i, now) {
		return e, state.Command{}, ErrInputs
	}
	if err := e.authorize(c, i); err != nil {
		return e, state.Command{}, err
	}
	old := e.d.Stages[i].Journal
	if old.Pending == nil {
		return e, state.Command{}, ErrInputs
	}
	if e.d.Stages[i].ReplayDue() {
		n, err := e.clone()
		if err != nil {
			return e, state.Command{}, err
		}
		// Keep the original pending ID, target and Unknown history: this is
		// the authorized second transmission of the same command, not a reset.
		n.d.Stages[i].Journal.Pending.Phase = reconcile.Dispatched
		n.d.Stages[i].Replay.Dispatched = true
		return n, *n.d.Stages[i].Command, nil
	}
	j, err := reconcile.Dispatch(old, old.Pending.ID)
	if err != nil {
		return e, state.Command{}, err
	}
	n, err := e.clone()
	if err != nil {
		return e, state.Command{}, err
	}
	n.d.Stages[i].Journal = j
	return n, *n.d.Stages[i].Command, nil
}

// UnknownStep is a stage whose command send is Unknown and may be resent.
type UnknownStep struct {
	Key     string
	Command [32]byte
	// Resent is true when an authorized resend is waiting to go out.
	Resent bool `json:",omitempty"`
}

// UnknownSteps lists the stages whose send is Unknown, in plan order.
func (e Execution) UnknownSteps() []UnknownStep {
	var out []UnknownStep
	for _, s := range e.d.Stages {
		if s.Command != nil && s.Result == nil && s.Journal.Pending != nil && s.Journal.Pending.Phase == reconcile.RecoveryRequired {
			out = append(out, UnknownStep{Key: s.Key, Command: state.Digest(*s.Command), Resent: s.ReplayDue()})
		}
	}
	return out
}

// ReplayDue reports whether an authorized replay is waiting to be sent.
func (s StageRecord) ReplayDue() bool {
	return s.Result == nil && s.Replay != nil && !s.Replay.Dispatched && s.Journal.Pending != nil && s.Journal.Pending.Phase == reconcile.RecoveryRequired
}

// Sendable reports whether the stage's command is waiting to be sent: first
// prepared, or an authorized replay.
func (s StageRecord) Sendable() bool {
	return s.Journal.Pending != nil && s.Journal.Pending.Phase == reconcile.Prepared || s.ReplayDue()
}

// AuthorizeReplay lets the exact command of a stage left Unknown be sent once
// more, on an explicit current management decision. The shared ledger
// deduplicates the command by its request ID, so if the first send did
// commit, the replay only finds that result; a late result is collected
// normally. It never asserts the first send was not applied.
func (e Execution) AuthorizeReplay(expected uint64, key, request string, digest [32]byte, shared state.State) (Execution, error) {
	i := e.index(key)
	if i < 0 || expected != e.d.Revision || request == "" || len(request) > 512 || e.d.Closed || e.d.Stopping || e.d.Paused {
		return e, ErrInputs
	}
	s := e.d.Stages[i]
	if s.Command == nil || s.Noop || s.Result != nil || s.Journal.Pending == nil || s.Journal.Pending.Phase != reconcile.RecoveryRequired || state.Digest(*s.Command) != digest || s.Replay != nil && (!s.Replay.Dispatched || s.Replay.Request == request) {
		return e, ErrInputs
	}
	epoch, retained := shared.LedgerEpoch(s.Command.Actor)
	if !retained || epoch != s.Command.Epoch || shared.ModuleExpired(*s.Command) {
		return e, inputError("ORIGINAL_COMMAND_EXPIRED", key)
	}
	if _, found := shared.LookupResult(*s.Command); found {
		return e, ErrInputs
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	n.d.Stages[i].Replay = &MutationReplay{Request: request, Revision: expected}
	return n, nil
}
func (e Execution) Unknown(expected uint64, key string) (Execution, error) {
	i := e.index(key)
	if i < 0 || expected != e.d.Revision {
		return e, ErrInputs
	}
	old := e.d.Stages[i].Journal
	if old.Pending == nil {
		return e, ErrInputs
	}
	j, err := reconcile.Settle(old, old.Pending.ID, reconcile.EffectUnknown)
	if err != nil {
		return e, err
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	n.d.Stages[i].Journal = j
	return n, nil
}

// Commit consumes an authenticated authoritative result/lookup of the EXACT
// original request. An absent lookup is not an input to this function and does
// not clear Unknown. Current user revocation does not erase an original result.
func (e Execution) Commit(expected uint64, key string, original state.Command, result state.Result) (Execution, error) {
	i := e.index(key)
	if i < 0 || expected != e.d.Revision || e.d.Stages[i].Command == nil || *e.d.Stages[i].Command != original || !validResult(result) {
		return e, ErrInputs
	}
	s := e.d.Stages[i]
	if s.Result != nil {
		if *s.Result == result {
			return e, nil
		}
		return e, ErrInputs
	}
	if s.Journal.Pending == nil {
		return e, ErrInputs
	}
	outcome := reconcile.EffectNotApplied
	if result.Code == state.Applied {
		outcome = reconcile.EffectApplied
	}
	j, err := reconcile.Settle(s.Journal, s.Journal.Pending.ID, outcome)
	if err != nil {
		return e, err
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	n.d.Stages[i].Journal = j
	n.d.Stages[i].Result = &result
	return n, nil
}

type Observation struct {
	IngressBackends                                     []ObjectRef            `json:",omitempty"`
	IngressDrained                                      []ObjectRef            `json:",omitempty"`
	TaskFact                                            *containerops.TaskFact `json:",omitempty"`
	LogDriver                                           string                 `json:",omitempty"`
	Cluster                                             [32]byte
	Plan                                                [32]byte
	Operation, Key, Native                              string
	Owner                                               [32]byte
	Command                                             [32]byte
	Generation, Revision, Sequence, At                  uint64
	Applied, Healthy, Released, Stopped, Gone, Retained bool
	Pins                                                uint64
	Signature                                           []byte
	Exit                                                *engine.ContainerExit `json:",omitempty"`
	StartedAt                                           int64                 `json:",omitempty"`
	// Expired is set only by the reducer when the owner stopped renewing
	// this observation. It is not signed and clears with the next fact.
	Expired   bool            `json:",omitempty"`
	Restart   *TaskRestart    `json:",omitempty"`
	OwnerBoot string          `json:",omitempty"`
	AppChecks *AppCheckResult `json:",omitempty"`
	// Failure is a signed permanent Task preparation failure (task_failure.go).
	Failure string `json:",omitempty"`
}

func successfulCompletion(o Observation) bool {
	return o.Applied && !o.Released && o.Exit != nil && o.Exit.Valid() && o.Exit.Code == 0
}

func appliedObservation(o Observation) bool {
	return o.Applied && (o.Exit == nil || o.Exit.Valid() && o.Exit.Code == 0)
}

func validExitObservation(step Step, o Observation) bool {
	return o.Exit == nil || step.Kind == "task" && o.Applied && !o.Healthy && !o.Released && !o.Stopped && !o.Gone && !o.Retained && o.Exit.Valid() && uint64(o.Exit.FinishedAt/1_000_000_000) <= o.At
}

// ObservationRenews reports whether o only renews old: the same owner facts
// with a later sequence and a time no earlier.
func ObservationRenews(old, o Observation) bool {
	if o.Sequence <= old.Sequence || o.At < old.At {
		return false
	}
	old.Sequence, old.At, old.Signature = 0, 0, nil
	o.Sequence, o.At, o.Signature = 0, 0, nil
	return bytes.Equal(goal(old), goal(o))
}

func ObservationBytes(o Observation) []byte {
	o.Signature, o.Expired = nil, false
	raw, _ := json.Marshal(o)
	return append([]byte("sfc-app-observation-1\x00"), raw...)
}
func (e Execution) validObservation(i int, o Observation) bool {
	return e.validObservationForPlan(i, o, (Blueprint{e.d.Plan}).Digest())
}

// planDigest belongs to the exact plan already validated by the caller in
// this same call; it is neither a cached authority nor an observation shortcut.
func (e Execution) validObservationForPlan(i int, o Observation, planDigest [32]byte) bool {
	s := e.d.Stages[i]
	step := e.observationStep(i)
	if !e.validIngressBackends(i, o) {
		return false
	}
	if s.Held() {
		if o.AppChecks != nil || o.Released || s.Previous.Native != "" && o.Native != s.Previous.Native {
			return false
		}
		s.Command, s.Result = &s.Previous.Command, &s.Previous.Result
	}
	if o.TaskFact != nil && (step.Kind != "task" || !o.TaskFact.Valid(o.At) || o.TaskFact.State == "running" && (!o.Applied || o.Stopped || o.Gone || o.Exit != nil) || o.TaskFact.State != "running" && o.Healthy || o.Exit != nil && o.TaskFact.State != "exited") {
		return false
	}
	if !containerops.ValidLogDriver(o.LogDriver) || o.LogDriver != "" && step.Kind != "task" {
		return false
	}
	if !e.validTaskInstance(i, o) || !e.validFailureObservation(i, o) {
		return false
	}
	if !e.d.Stages[i].Held() && !e.validAppChecks(i, o) {
		return false
	}
	return step.Owner != ([32]byte{}) && s.Command != nil && s.Result != nil && s.Result.Code == state.Applied && o.Cluster == e.d.Plan.Cluster && o.Plan == planDigest && o.Operation == e.d.Operation && o.Key == s.Key && o.Native != "" && len(o.Native) <= 256 && !strings.ContainsAny(o.Native, "\x00\r\n") && o.Owner == step.Owner && o.Command == state.Digest(*s.Command) && o.Generation == s.Result.Generation && o.Revision == s.Result.Revision && o.Sequence > 0 && o.At > 0 && (!o.Healthy || o.Applied) && validExitObservation(step, o) && (!o.Released || o.Stopped && o.Pins == 0 && (step.Retain && o.Retained && !o.Gone || !step.Retain && o.Gone && !o.Retained)) && ed25519.Verify(ed25519.PublicKey(o.Owner[:]), ObservationBytes(o), o.Signature)
}
func (e Execution) Observe(expected uint64, o Observation, now uint64) (Execution, error) {
	i := e.index(o.Key)
	if i < 0 || expected != e.d.Revision || o.At > now || o.Expired || !e.validObservation(i, o) {
		return e, ErrInputs
	}
	if o.Applied && !e.d.Stages[i].Held() && !e.activationReady(i) {
		return e, inputError("ACTIVATION_PENDING", o.Key)
	}
	if o.Released && !e.CanRelease(o.Key) {
		return e, inputError("LIFETIME_PENDING", o.Key)
	}
	if old := e.d.Stages[i].Observation; old != nil {
		if o.Sequence == old.Sequence {
			if bytes.Equal(goal(o), goal(*old)) {
				return e, nil
			}
			return e, ErrInputs
		}
		if o.Sequence < old.Sequence || o.At < old.At || o.Native != old.Native || old.Released && !o.Released {
			return e, ErrInputs
		}
		if !o.Released && !validInstanceTransition(*old, o) {
			return e, ErrInputs
		}
		// Docker's logger is fixed when this native container is created.
		// Old peers may omit it; once observed it cannot become a different
		// driver on the same native lifetime. Closure may omit live metadata.
		if !o.Released && old.LogDriver != "" && o.LogDriver != old.LogDriver {
			return e, ErrInputs
		}
		if !validExitTransition(*old, o) || !validFailureTransition(*old, o) {
			return e, ErrInputs
		}
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	o.Signature = bytes.Clone(o.Signature)
	if o.Exit != nil {
		exit := *o.Exit
		o.Exit = &exit
	}
	if o.Restart != nil {
		proof := o.Restart.Clone()
		o.Restart = &proof
	}
	if o.AppChecks != nil {
		copy := *o.AppChecks
		o.AppChecks = &copy
	}
	n.d.Stages[i].Observation = &o
	return n, nil
}

// CheckRenewal reports whether o, sent over SFCP instead of Raft, only
// renews key's stored observation: same signed facts, later sequence, not
// expired. A renewal never changes the Execution.
func (e Execution) CheckRenewal(o Observation, now uint64) error {
	i := e.index(o.Key)
	if i < 0 || o.At > now || o.Expired || !e.validObservation(i, o) {
		return ErrInputs
	}
	old := e.d.Stages[i].Observation
	if old == nil || old.Expired || !ObservationRenews(*old, o) {
		return ErrInputs
	}
	return nil
}

// ExpireObservation marks key's observation Expired once its owner stopped
// renewing it for maxAge. sequence names the observation the leader found
// stale, so a newer fact is never expired. It is one Raft write per outage.
func (e Execution) ExpireObservation(expected uint64, key string, sequence, now, maxAge uint64) (Execution, error) {
	i := e.index(key)
	if i < 0 || expected != e.d.Revision || maxAge == 0 {
		return e, ErrInputs
	}
	o := e.d.Stages[i].Observation
	if o == nil || o.Expired || o.Sequence != sequence || o.At > now || now-o.At <= maxAge {
		return e, ErrInputs
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	expired := *n.d.Stages[i].Observation
	expired.Expired = true
	n.d.Stages[i].Observation = &expired
	return n, nil
}

func (e Execution) Pause(c access.Catalog, actor string, expected uint64, paused bool) (Execution, error) {
	if expected != e.d.Revision || e.d.Stopping || e.d.Closed || e.d.CompletedAt != 0 || c.Authorize(actor, e.d.Plan.Tenant, access.Deploy, "") != nil {
		return e, ErrInputs
	}
	if e.d.Paused == paused {
		return e, nil
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	n.d.Paused = paused
	return n, nil
}
func (e Execution) Finish(expected, now uint64) (Execution, error) {
	if e.d.Replacement != nil && e.d.Replacement.Phase != "complete" {
		return e, inputError("REPLACEMENT_WAVE_PENDING", "finish")
	}
	if expected != e.d.Revision || now == 0 || e.d.Stopping || e.d.Closed || e.d.Paused {
		return e, ErrInputs
	}
	if e.d.CompletedAt != 0 {
		return e, nil
	}
	for i, step := range e.d.Plan.Steps {
		if !e.satisfies(i, step.Completion, now) {
			return e, ErrInputs
		}
	}
	if e.appChecksStatus(now) != contract.Pass {
		return e, ErrInputs
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	n.d.CompletedAt = now
	for i, step := range n.d.Plan.Steps {
		if step.Completion != Committed {
			if n.d.Stages[i].Observation == nil {
				return e, ErrInputs
			}
			o := *n.d.Stages[i].Observation
			o.Signature = bytes.Clone(o.Signature)
			n.d.CompletionWitness = append(n.d.CompletionWitness, o)
		}
	}
	return n, nil
}

// Stop prevents new dispatch and safely aborts only Prepared A2 calls. Already
// dispatched/unknown calls keep their original operation and references until
// authoritative settlement. It does not rewind Desired or delete native data.
func (e Execution) Stop(c access.Catalog, actor string, expected uint64) (Execution, error) {
	return e.stop(expected, c.AuthorizeCleanup(actor, e.d.Plan.Tenant, access.Deploy) == nil)
}

func (e Execution) stop(expected uint64, authorized bool) (Execution, error) {
	if expected != e.d.Revision || e.d.Closed || !authorized {
		return e, ErrInputs
	}
	if e.d.Stopping {
		return e, nil
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	n.d.Stopping = true
	for i, s := range n.d.Stages {
		if s.Command != nil && !s.Noop {
			j := reconcile.Stop(s.Journal)
			if j.Pending != nil && j.Pending.Phase == reconcile.Prepared {
				j, err = reconcile.AbortPrepared(j, j.Pending.ID)
				if err != nil {
					return e, err
				}
			}
			n.d.Stages[i].Journal = j
		}
	}
	return n, nil
}
func (e Execution) CanRelease(key string) bool {
	i := e.index(key)
	if i < 0 || !e.d.Stopping || e.d.Stages[i].Journal.Pending != nil {
		return false
	}
	for j, step := range e.d.Plan.Steps {
		if slices.ContainsFunc(step.Dependencies, func(d Dependency) bool { return d.Key == key && !slices.Contains(step.Identity, d.Key) }) || slices.ContainsFunc(step.Activation, func(d Dependency) bool { return d.Key == key }) {
			s := e.d.Stages[j]
			if s.Journal.Pending != nil || s.Result != nil && s.Result.Code == state.Applied && step.Node != "" && (s.Observation == nil || !s.Observation.Released) {
				return false
			}
		}
	}
	return true
}
func (e Execution) Close(expected uint64) (Execution, error) {
	if expected != e.d.Revision || !e.d.Stopping {
		return e, ErrInputs
	}
	if e.d.Closed {
		return e, nil
	}
	for i, s := range e.d.Stages {
		if s.Journal.Pending != nil || s.Result != nil && s.Result.Code == state.Applied && e.d.Plan.Steps[i].Node != "" && (s.Observation == nil || !s.Observation.Released) {
			return e, ErrInputs
		}
	}
	n, err := e.clone()
	if err != nil {
		return e, err
	}
	n.d.Closed = true
	return n, nil
}
func (e Execution) Status() string {
	if e.d.Closed {
		return "Closed"
	}
	if e.d.Stopping {
		return "Stopping"
	}
	if e.d.CompletedAt != 0 {
		return "Succeeded"
	}
	any, all := false, true
	for _, s := range e.d.Stages {
		if stageFailed(s) {
			return "Failed"
		}
		if s.Journal.Pending != nil && s.Journal.Pending.Phase == reconcile.RecoveryRequired {
			return "Unknown"
		}
		any = any || s.Command != nil
		all = all && s.Result != nil
	}
	if e.d.Paused {
		return "Paused"
	}
	if all {
		return "Verifying"
	}
	if any {
		return "Applying"
	}
	return "Planned"
}

func validResult(r state.Result) bool {
	if !r.ValidReason() || r.Index == 0 || r.Generation > r.Revision {
		return false
	}
	return r.Code != state.Applied || r.Revision == r.Index && r.Generation > 0
}

// Health is current owner evidence; it is independent of the immutable fact
// that an operation previously completed its required verification.
func (e Execution) Health(now uint64) string {
	health, _ := e.HealthWithReason(now)
	return health
}

// HealthWithReason is Health and, unless Healthy, the first cause found, for
// status display only.
func (e Execution) HealthWithReason(now uint64) (string, *HealthReason) {
	if e.d.Closed {
		return "Unknown", nil
	}
	if i, ok := e.partialReplicaIndex(now); ok {
		return "Degraded", e.stageReason(HealthReplicasPartial, i)
	}
	for index, step := range e.d.Plan.Steps {
		if step.Kind == "ingress" && len(step.Identity) != 0 {
			o := e.d.Stages[index].Observation
			if o != nil && o.AvailableAt(now) && !e.ingressAllReady(index, *o) {
				return "Degraded", e.stageReason(HealthIngressNotReady, index)
			}
		}
	}
	if e.d.Replacement != nil {
		// A still-pending later node cannot hide a known first-wave failure.
		// Held facts describe the original native, never target completion.
		for i, stage := range e.d.Stages {
			step, observation := e.observationStep(i), stage.Observation
			if step.Kind == "task" && observation != nil && observation.Live(now) {
				if code := observationProblem(step, *observation, false); code != "" {
					return "Degraded", e.observationReason(code, i, *observation)
				}
			}
		}
	}
	for i, step := range e.d.Plan.Steps {
		if step.Node == "" {
			continue
		}
		s := e.d.Stages[i]
		switch {
		case s.Result == nil:
			return "Unknown", e.stageReason(HealthStepPending, i)
		case s.Result.Code != state.Applied:
			return "Unknown", e.stageReason(HealthStepRejected, i)
		case s.Observation == nil || !s.Observation.Live(now):
			return "Unknown", e.stageReason(HealthNotObserved, i)
		}
		if code := observationProblem(step, *s.Observation, true); code != "" {
			return "Degraded", e.observationReason(code, i, *s.Observation)
		}
	}
	switch e.appChecksStatus(now) {
	case contract.Pass:
		return "Healthy", nil
	case contract.Fail:
		return "Degraded", &HealthReason{Code: HealthAppCheckFailed}
	default:
		return "Unknown", &HealthReason{Code: HealthAppCheckPending}
	}
}

// AvailableAt is serving evidence only. Callers separately validate the owner
// signature, current object/ref and node eligibility; it proves no new effect.
// Live reports whether o's owner still renews it at now. Owners renew an
// unchanged observation over SFCP, not Raft; the leader marks it Expired
// in Raft once renewals stop for AppObservationMaxAge. Age is never read
// from the stored At, which only moves when a fact changes.
func (o Observation) Live(now uint64) bool { return !o.Expired && o.At <= now }

func (o Observation) AvailableAt(now uint64) bool {
	return o.At != 0 && o.Live(now) && o.Applied && o.Healthy && !o.Released && !o.Stopped && !o.Gone && o.Exit == nil
}

// partialReplicaIndex is the first unavailable stage of a service whose
// other replicas still serve.
func (e Execution) partialReplicaIndex(now uint64) (int, bool) {
	type counts struct {
		total, available int
		down             []int
	}
	services := map[string]counts{}
	for i, step := range e.d.Plan.Steps {
		if step.Kind != "task" {
			continue
		}
		var service ComposeService
		if json.Unmarshal(step.Goal, &service) != nil || service.Sfc.Instance == nil {
			continue
		}
		count := services[service.Sfc.Instance.Service]
		count.total++
		stage := e.d.Stages[i]
		observation := stage.Observation
		if observation == nil && stage.Held() {
			observation = stage.Previous.Observation
		}
		if observation != nil && observation.AvailableAt(now) {
			count.available++
		} else {
			count.down = append(count.down, i)
		}
		services[service.Sfc.Instance.Service] = count
	}
	first := -1
	for _, count := range services {
		if count.available > 0 && count.available < count.total && (first < 0 || count.down[0] < first) {
			first = count.down[0]
		}
	}
	return first, first >= 0
}

// ActivationReady separates an exact committed Task intent from permission to
// create/start its native process. Adapters still check current policy and
// acquire the original native dependencies at their actual effect boundary.
func (e Execution) ActivationReady(key string) bool {
	i := e.index(key)
	if i >= 0 && !e.d.Stopping && !e.d.Closed {
		if old, held := e.heldExecution(key); held {
			return old.ActivationReady(key)
		}
	}
	if i < 0 || e.d.Paused || e.d.Stopping || e.d.Closed || e.d.Stages[i].Result == nil || e.d.Stages[i].Result.Code != state.Applied {
		return false
	}
	return e.activationReady(i)
}

func (e Execution) activationReady(i int) bool {
	for _, d := range e.d.Plan.Steps[i].Activation {
		j := e.index(d.Key)
		if j < 0 {
			return false
		}
		stage := e.d.Stages[j]
		if stage.Result == nil || stage.Result.Code != state.Applied || stage.Observation == nil || !stage.Observation.Applied || stage.Observation.Released {
			return false
		}
		if e.d.Plan.Steps[j].Kind == "inputs" {
			var g GoalCommand
			if stage.Command == nil || json.Unmarshal([]byte(stage.Command.Value), &g) != nil || e.d.Stages[i].Result == nil {
				return false
			}
			result := e.d.Stages[i].Result
			// The inputs were made for this generation; a same-generation
			// update of the Task (aliases) keeps them (Step.Stable).
			if !slices.ContainsFunc(g.Dependencies, func(ref ObjectRef) bool {
				return ref.Key == e.d.Stages[i].Key && ref.Generation == result.Generation && ref.Revision <= result.Revision
			}) {
				return false
			}
		}
	}
	return true
}
func (e Execution) Inputs(service, consumer string, requester [32]byte) (Needs, error) {
	key := ResourceKey("task", e.d.Plan.Tenant, e.d.Plan.App, service)
	i := e.index(key)
	if i < 0 || e.d.Stages[i].Result == nil || e.d.Stages[i].Result.Code != state.Applied {
		return Needs{}, inputError("TASK_GENERATION_PENDING", key)
	}
	return (Blueprint{e.d.Plan}).Inputs(service, consumer, e.d.Stages[i].Result.Generation, requester)
}
