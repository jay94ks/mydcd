// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

const AppObservationMaxAge uint64 = 30

// AppObservationLinkedMaxAge replaces AppObservationMaxAge while the owner
// has stayed connected to the leader since its last fact or renewal: the
// owner reports a changed fact at once, so a renewal only has to prove its
// loop is still running.
const AppObservationLinkedMaxAge uint64 = 300

// CheckAppBinding uses the actual immutable reducer before a member proposes a
// reservation. Missing approval/quota is a waiting condition, not a reason to
// create an endless stream of denied Raft entries. The FSM still rechecks the
// signed command and current CAS when the proposal is actually committed.
func (p Policy) CheckAppBinding(s state.State, r AppProgress) error {
	if r.Action != "bind-inputs" {
		return ErrCatalog
	}
	root := s.Object(AppsKey).Revision
	if r.RootRevision > root || r.Epoch != s.ModuleEpoch() {
		return fmt.Errorf("binding view changed: apps root %d/%d epoch %d/%d: %w", r.RootRevision, s.Object(AppsKey).Revision, r.Epoch, s.ModuleEpoch(), ErrCatalog)
	}
	cmd, err := r.Command()
	if err != nil {
		return err
	}
	if _, code := p.reduceAppProgress(s, cmd); code != state.Applied {
		return fmt.Errorf("binding reservation reducer rejected code=%d: %w", code, ErrCatalog)
	}
	return nil
}

// CheckObservationRenewal admits an owner's renewal of an unchanged
// observation. The leader keeps renewals in memory; they never reach Raft.
// It returns the stored observation's sequence the renewal extends.
func (p Policy) CheckObservationRenewal(s state.State, r AppProgress, now uint64) (uint64, error) {
	if r.Action != "observe" || r.Observation == nil || r.Observation.Key != r.Key {
		return 0, ErrCatalog
	}
	cmd, err := r.Command()
	if err != nil {
		return 0, err
	}
	if r, err = p.appProgress(s, cmd); err != nil {
		return 0, err
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return 0, err
	}
	entry, ok := a.entries[appKey(r.Tenant, r.App)]
	if !ok {
		return 0, ErrCatalog
	}
	e, ok := entry.Inventory.Execution()
	if !ok || e.ActiveOperation() != r.Operation || e.CheckRenewal(*r.Observation, now) != nil {
		return 0, ErrCatalog
	}
	stage, _ := e.Stage(r.Key)
	return stage.Observation.Sequence, nil
}

// AppProgress is an installed member's signed transition request. It contains
// no supplied commit result or replacement execution. Every transition consumes
// the original Execution/Inventory and the same authoritative A1 ledger.
type AppProgress struct {
	Schema                              uint8
	Cluster, Reporter                   [32]byte
	Tenant, App, Operation, Key, Action string
	Expected, At                        uint64
	Observation                         *deployment.Observation `json:",omitempty"`
	Epoch                               uint64
	RequestID                           string
	RootRevision                        uint64
	Signature                           []byte
	Release                             *AppBindingRelease     `json:",omitempty"`
	Volume                              *volumes.NativeReady   `json:",omitempty"`
	Retire                              *AppRetirementProgress `json:",omitempty"`
	// ExpireSequence names the observation an expire-observation report
	// marks Expired: the leader stopped receiving its owner's renewals.
	ExpireSequence uint64 `json:",omitempty"`
	// Stage is the digest of the stage record a stage report was planned
	// against (Execution.StageDigest). Stage reports are checked against it,
	// not against the whole app revision, so progress on other stages and
	// unrelated app changes do not reject them.
	Stage string `json:",omitempty"`
}

// StageDigest is the digest a member puts in a stage report planned on s.
func (p Policy) StageDigest(s state.State, tenant, app, key string) string {
	a, err := p.readOnlyApps(s)
	if err != nil {
		return ""
	}
	e, ok := a.Execution(tenant, app)
	if !ok {
		return ""
	}
	return e.StageDigest(key)
}

// StageReport reports whether action changes one stage record only. Its CAS
// is that stage's digest; any other action needs the exact app revision.
func StageReport(action string) bool {
	switch action {
	case "prepare", "send", "unknown", "collect", "bind-inputs", "release-inputs", "volume-ready", "project-dns", "expire-observation":
		return true
	}
	return false
}

func AppProgressBytes(r AppProgress) []byte {
	r.Signature = nil
	b, _ := json.Marshal(r)
	return append([]byte("mydc-app-progress-1\x00"), b...)
}
func (r AppProgress) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, RequestID: r.RequestID, Key: AppsKey, Expected: r.RootRevision, Value: string(raw)}
	// An observation is an immutable owner fact; every other transition is
	// bound to the exact app inventory revision it was planned against.
	if r.Action == "observe" {
		cmd.Target = state.AppObservationTarget
	} else {
		if r.RootRevision == 0 {
			return state.Command{}, ErrCatalog
		}
		cmd.Target = state.AppInventoryTarget
	}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) appProgress(s state.State, cmd state.Command) (AppProgress, error) {
	var r AppProgress
	if cmd.Kind != state.ModuleReport || cmd.Key != AppsKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Reporter == ([32]byte{}) || r.At == 0 || r.At > math.MaxInt64 || r.Epoch != s.ModuleEpoch() || r.Expected == 0 || r.Tenant == "" || r.App == "" || r.Operation == "" || !ed25519.Verify(ed25519.PublicKey(r.Reporter[:]), AppProgressBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	original, err := r.Command()
	if err != nil || original != cmd {
		return r, ErrCatalog
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(r.Reporter) || (r.Action == "recreate-continue" || r.Action == "advance-wave") && !members.WorkKey(r.Reporter) {
		return r, ErrCatalog
	}

	if isRetirementAction(r.Action) {
		if !validRetirementReport(r) {
			return r, ErrCatalog
		}
		return r, nil
	}
	if r.Observation != nil && r.Observation.Restart != nil && r.Observation.Restart.User != nil {
		a, err := p.readOnlyApps(s)
		if err != nil || !validUserRestart(a.entries[appKey(r.Tenant, r.App)], *r.Observation) {
			return r, ErrCatalog
		}
	}
	if r.Retire != nil || r.ExpireSequence != 0 && r.Action != "expire-observation" {
		return r, ErrCatalog
	}
	if StageReport(r.Action) != (len(r.Stage) == 64) || r.Stage != strings.ToLower(r.Stage) {
		return r, ErrCatalog
	}
	if r.Stage != "" {
		if _, err := hex.DecodeString(r.Stage); err != nil {
			return r, ErrCatalog
		}
	}
	switch r.Action {
	case "prepare", "send", "unknown", "collect", "bind-inputs", "project-dns":
		if r.Key == "" || r.Observation != nil || r.Release != nil || r.Volume != nil {
			return r, ErrCatalog
		}
	case "observe":
		if r.Observation == nil || r.Observation.Key != r.Key || r.Release != nil || r.Volume != nil {
			return r, ErrCatalog
		}
	case "finish", "recreate-continue", "advance-wave":
		if r.Key != "" || r.Observation != nil || r.Release != nil || r.Volume != nil {
			return r, ErrCatalog
		}
	case "expire-observation":
		if r.Key == "" || r.ExpireSequence == 0 || r.Observation != nil || r.Release != nil || r.Volume != nil {
			return r, ErrCatalog
		}
	case "release-inputs":
		if r.Key == "" || r.Release == nil || r.Observation == nil || r.Observation.Key != r.Key || r.Volume != nil {
			return r, ErrCatalog
		}
	case "volume-ready":
		if r.Key == "" || r.Volume == nil || r.Observation == nil || r.Observation.Key != r.Key || r.Release != nil {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	return r, nil
}

// Execution returns an owned execution value. It is a local internal view; any
// network caller must pass the existing current tenant/session read admission.
func (a Apps) Execution(tenant, app string) (deployment.Execution, bool) {
	e, ok := a.entries[appKey(tenant, app)]
	if !ok {
		return deployment.Execution{}, false
	}
	return e.Inventory.Execution()
}
func (a Apps) Origin(tenant, app string) (UserOperation, bool) {
	e, ok := a.entries[appKey(tenant, app)]
	if !ok {
		return UserOperation{}, false
	}
	raw, _ := json.Marshal(e.Origin)
	var op UserOperation
	_ = json.Unmarshal(raw, &op)
	return op, true
}
func (p Policy) authorizeAppStep(s state.State, c access.Catalog, entry appEntry, e deployment.Execution, key string) error {
	if p.authorizeLocalStep(s, c, entry, e, key) != nil {
		return access.ErrDenied
	}
	return p.authorizeAppSourceStep(s, c, entry, e, key)
}

// A held native uses its original BindingSource proof and frozen recipe.
// Current-target local metadata must not replace that already accepted grant.
func (p Policy) authorizeAppSourceStep(s state.State, c access.Catalog, entry appEntry, e deployment.Execution, key string) error {
	if e.Authorize(c, key) != nil {
		return access.ErrDenied
	}
	for _, step := range e.Steps() {
		if step.Key != key {
			continue
		}
		if c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, e.Scope().Tenant, step.Action(), step.Node) != nil {
			return access.ErrDenied
		}
		if entry.Sync != nil {
			if entry.Sync.Recreate == nil && c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, e.Scope().Tenant, access.ManageCD, "") != nil {
				return access.ErrDenied
			}
			if u := entry.Sync.User; u != nil {
				action := step.Action()
				if entry.Sync.Recreate != nil {
					action = access.Deploy
				}
				if entry.Sync.Recreate == nil && c.AuthorizeAccepted(u.Session, p.Cluster, u.At, e.Scope().Tenant, access.ManageCD, "") != nil || c.AuthorizeAccepted(u.Session, p.Cluster, u.At, e.Scope().Tenant, action, step.Node) != nil {
					return access.ErrDenied
				}
			}
		}
		if step.Node != "" {
			members, err := p.Members(s)
			if err != nil || !members.ResourceKeyActive(step.Owner) {
				return access.ErrDenied
			}
			peer, ok := members.Entry(step.Node)
			if !ok || !members.OwnsResource(mustCurrentPeer(peer), step.Owner) {
				return access.ErrDenied
			}
		}
		return nil
	}
	return access.ErrDenied
}

// CheckAcceptedAppStep previews the same current grant checks as prepare/send.
func (p Policy) CheckAcceptedAppStep(s state.State, a Apps, c access.Catalog, tenant, app, key string) error {
	entry, exists := a.entries[appKey(tenant, app)]
	e, active := entry.Inventory.Execution()
	if !exists || !active {
		return access.ErrDenied
	}
	return p.authorizeAppStep(s, c, entry, e, key)
}

func (p Policy) reduceAppProgress(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.appProgress(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	a, err := p.Apps(s)
	if err != nil {
		return nil, state.Invalid
	}
	entry, ok := a.entries[appKey(r.Tenant, r.App)]
	if !ok || r.Expected > entry.Inventory.Revision() {
		return nil, state.ConditionFailed
	}
	// An observation is checked by its sequence and a stage report by its
	// stage record. Only whole-app transitions need the exact app revision.
	switch {
	case cmd.Target == state.AppObservationTarget && r.Action == "observe":
	case r.Stage != "":
		if e, ok := entry.Inventory.Execution(); !ok || e.StageDigest(r.Key) != r.Stage {
			return nil, state.ConditionFailed
		}
	case entry.Inventory.Revision() != r.Expected:
		return nil, state.ConditionFailed
	}
	if r.Action == "recreate-continue" {
		if entry.PendingSync == nil || entry.PendingSync.Recreate == nil || r.Operation != entry.PendingSync.Choice.Operation || r.At < uint64(entry.PendingSync.User.At) {
			return nil, state.ConditionFailed
		}
		next, err := p.continueAppLogClear(s, entry)
		if err != nil {
			return nil, state.ConditionFailed
		}
		a.entries[appKey(r.Tenant, r.App)] = next
		return p.appsCheckpoint(s, a, r.At)
	}
	if isRetirementAction(r.Action) {
		return p.reduceAppRetirement(s, r, a, entry)
	}
	e, ok := entry.Inventory.Execution()
	if !ok || e.ActiveOperation() != r.Operation || r.At < uint64(entry.Origin.At) {
		return nil, state.ConditionFailed
	}
	if r.Action == "bind-inputs" || r.Action == "release-inputs" {
		return p.reduceAppBinding(s, r, a, entry, e)
	}
	if r.Action == "volume-ready" {
		return p.reduceAppVolumeReady(s, r, a, entry, e)
	}
	if r.Action == "project-dns" {
		return p.reduceAppDNS(s, r, a, entry, e)
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	if r.Action == "advance-wave" {
		for _, step := range e.Steps() {
			if p.authorizeAppStep(s, c, entry, e, step.Key) != nil {
				return nil, state.Forbidden
			}
		}
		updated, err := entry.Inventory.AdvanceReplacement(entry.Inventory.Revision(), c, r.At)
		if err != nil {
			return nil, state.ConditionFailed
		}
		entry.Inventory = updated
		a.entries[appKey(r.Tenant, r.App)] = entry
		return p.appsCheckpoint(s, a, r.At)
	}
	if r.Action == "prepare" || r.Action == "send" {
		if _, retiring := entry.Inventory.Retirement(); retiring && !(r.Action == "prepare" && e.ReplacementAllows(r.Key)) {
			return nil, state.Forbidden
		}
		if p.authorizeAppStep(s, c, entry, e, r.Key) != nil {
			return nil, state.Forbidden
		}
	}
	switch r.Action {
	case "prepare":
		e, _, err = e.Prepare(c, e.Revision(), r.Key, s.Object(r.Key), r.At)
	case "send":
		stage, ok := e.Stage(r.Key)
		if !ok || stage.Journal.Pending == nil || stage.Journal.Pending.Phase != reconcile.Prepared {
			return nil, state.ConditionFailed
		}
		e, _, err = e.Send(c, e.Revision(), r.Key, r.At)
	case "unknown":
		stage, ok := e.Stage(r.Key)
		if !ok || stage.Command == nil || stage.Journal.Pending == nil || stage.Journal.Pending.Phase != reconcile.Dispatched {
			return nil, state.ConditionFailed
		}
		if _, found := s.LookupResult(*stage.Command); found {
			return nil, state.ConditionFailed
		}
		e, err = e.Unknown(e.Revision(), r.Key)
	case "collect":
		stage, ok := e.Stage(r.Key)
		if !ok || stage.Command == nil {
			return nil, state.ConditionFailed
		}
		result, found := s.LookupResult(*stage.Command)
		if !found {
			return nil, state.ConditionFailed
		}
		e, err = e.Commit(e.Revision(), r.Key, *stage.Command, result)
	case "expire-observation":
		e, err = e.ExpireObservation(e.Revision(), r.Key, r.ExpireSequence, r.At, AppObservationMaxAge)
	case "observe":
		// Owner facts can be relayed by an installed member; the core verifies the
		// exact original command/native/owner/generation/signature and sequence.
		e, err = e.Observe(e.Revision(), *r.Observation, r.At)
	case "finish":
		e, err = e.Finish(e.Revision(), r.At)
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	entry.Inventory, err = p.advanceAppInventory(s, entry.Inventory, e)
	if err != nil {
		return nil, state.ConditionFailed
	}
	if r.Action == "finish" {
		for j := range entry.LogClears {
			if entry.LogClears[j].Source.Choice.Operation == r.Operation {
				entry.LogClears[j].Status = "succeeded"
				entry.LogClears[j].Replacements = recreatedContainers(entry.Inventory, entry.LogClears[j].Source.Recreate.Plan.Impact)
			}
		}
	}
	a.entries[appKey(r.Tenant, r.App)] = entry
	return p.appsCheckpoint(s, a, r.At)
}

// AdmitAppMutation grants no persistent rights. It authorizes only the exact
// Dispatched original command from an accepted app, with current authority or
// its original signed, bounded standalone cleanup policy.
// Activation in a product engine also requires its typed native projector.
func (p Policy) AdmitAppMutation(s state.State, cmd state.Command) bool {
	if cmd.Kind != state.Mutate || cmd.Target != "" || cmd.Rights != 0 || cmd.Epoch != s.ModuleEpoch() {
		return false
	}
	p, err := p.Current(s)
	if err != nil {
		return false
	}
	a, err := p.Apps(s)
	if err != nil {
		return false
	}
	if p.admitAppRemoval(s, a, cmd) {
		return true
	}
	if !strings.HasPrefix(cmd.Actor, "user/") || cmd.Delete {
		return false
	}
	if strings.HasPrefix(cmd.Key, "workload/task/") {
		var goal deployment.GoalCommand
		if json.Unmarshal([]byte(cmd.Value), &goal) != nil {
			return false
		}
		image, err := cacheGoalImage([]byte(cmd.Value))
		if err != nil || p.imageCacheAvailable(s, goal.Node, image) != nil {
			return false
		}
	}
	c, err := p.Catalog(s)
	if err != nil {
		return false
	}
	for _, entry := range a.entries {
		e, ok := entry.Inventory.Execution()
		if !ok || e.Status() == "Paused" || e.Status() == "Stopping" || e.Status() == "Closed" || e.Status() == "Succeeded" {
			continue
		}
		stage, ok := e.Stage(cmd.Key)
		if !ok || stage.Command == nil || *stage.Command != cmd || stage.Result != nil || stage.Journal.Pending == nil || stage.Journal.Pending.Phase != reconcile.Dispatched && stage.Journal.Pending.Phase != reconcile.RecoveryRequired {
			continue
		}
		return p.authorizeAppStep(s, c, entry, e, cmd.Key) == nil
	}
	return false
}

// validateAppCommands links every stored app goal back to its frozen command
// and actual A1 receipt. During validation of that one mutation the receipt is
// about to be added by the same A1 transaction; no report can supply a result.
func (p Policy) validateAppCommands(s state.State, a Apps, current state.Command) error {
	bound := map[string]bool{}
	for _, entry := range a.entries {
		e, ok := entry.Inventory.Execution()
		if ok {
			for _, step := range e.Steps() {
				stage, _ := e.Stage(step.Key)
				if stage.Command == nil {
					continue
				}
				cmd := *stage.Command
				o := s.Object(cmd.Key)
				if !o.Present || o.Value != cmd.Value {
					continue
				}
				result, found := s.LookupResult(cmd)
				if stage.Result != nil {
					if found && result != *stage.Result {
						return invariantFailure("step-result-mismatch")
					}
					result, found = *stage.Result, true
				}
				if found {
					if result.Code != state.Applied || result.Revision != o.Revision || result.Generation != o.Generation {
						return invariantFailure("step-result-stale")
					}
				} else {
					base, present, known := e.PreparationBase(step.Key)
					if !known || current != cmd || o.Revision != s.Index() || stage.Journal.Pending == nil || (stage.Journal.Pending.Phase != reconcile.Dispatched && stage.Journal.Pending.Phase != reconcile.RecoveryRequired) || cmd.Expected != base.Revision || o.Revision <= cmd.Expected || present && o.Generation != base.Generation || !present && o.Generation != o.Revision {
						return invariantFailure("step-unrecorded")
					}
				}
				bound[cmd.Key] = true
			}
		}
		for _, claim := range entry.Inventory.Claims() {
			o := s.Object(claim.Step.Key)
			if o.Present && o.Value == claim.Command.Value && o.Revision == claim.Result.Revision && o.Generation == claim.Result.Generation && claim.Result.Code == state.Applied {
				bound[claim.Step.Key] = true
			}
		}
		if retirement, ok := entry.Inventory.Retirement(); ok {
			for _, target := range retirement.Targets {
				for _, m := range []*deployment.Mutation{target.Drain, target.Proof, target.Delete} {
					if m == nil || m.Command.Delete {
						continue
					}
					o := s.Object(m.Command.Key)
					if !o.Present || o.Value != m.Command.Value {
						continue
					}
					result, found := s.LookupResult(m.Command)
					if m.Result != nil {
						if found && result != *m.Result {
							return invariantFailure("retirement-result-mismatch")
						}
						result, found = *m.Result, true
					}
					if found {
						if result.Code != state.Applied || result.Revision != o.Revision || result.Generation != o.Generation {
							return invariantFailure("retirement-result-stale")
						}
					} else if current != m.Command || o.Revision != s.Index() || o.Generation != target.Original.Result.Generation || m.Journal.Pending == nil || (m.Journal.Pending.Phase != reconcile.Dispatched && m.Journal.Pending.Phase != reconcile.RecoveryRequired) {
						return invariantFailure("retirement-unrecorded")
					}
					bound[m.Command.Key] = true
				}
			}
		}
	}
	for key, o := range s.Objects("") {
		if !o.Present || !strings.HasPrefix(key, "network/") && !strings.HasPrefix(key, "workload/") && !strings.HasPrefix(key, "ingress/") {
			continue
		}
		var head struct{ Kind string }
		if json.Unmarshal([]byte(o.Value), &head) != nil || head.Kind == "" {
			continue
		}
		var g deployment.GoalCommand
		if canonical([]byte(o.Value), &g) != nil || g.Schema != 1 || g.Cluster != p.Cluster || !bound[key] {
			return invariantFailure("unbound-goal")
		}
	}
	return nil
}
