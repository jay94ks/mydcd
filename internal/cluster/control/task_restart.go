// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

type TaskRestartPlan struct {
	ManagementTarget                                    *[32]byte               `json:",omitempty"`
	Action                                              checker.ContainerAction `json:",omitempty"`
	StandaloneRevision                                  uint64                  `json:",omitempty"`
	Schema                                              uint8
	Tenant, App                                         string
	InventoryRevision                                   uint64
	Target                                              [32]byte
	Registration                                        [32]byte
	Container                                           containerops.Target
	OwnerBoot                                           string
	StopGraceSeconds                                    int
	PreserveNative, PreserveWritableLayer, PreserveLogs bool
}
type TaskRestartChange struct {
	ManagementTarget       *[32]byte `json:",omitempty"`
	Standalone             string    `json:",omitempty"`
	Tenant, App, Operation string
	Selection              struct{ Service, Instance string }
	Target                 [32]byte
}

func (q TaskRestartChange) selection() containerops.Selection {
	return containerops.Selection{App: q.App, Standalone: q.Standalone, Service: q.Selection.Service, Instance: q.Selection.Instance}
}
func (q TaskRestartChange) valid() bool {
	return (q.ManagementTarget == nil || q.Standalone != "" && *q.ManagementTarget != ([32]byte{})) && lifecycle.ValidID(q.Tenant) && (q.App != "" || q.Standalone != "") && lifecycle.ValidID(q.Operation) && q.Target != ([32]byte{}) && q.selection().Valid()
}
func TaskRestartCASAllowed(c Change) bool {
	var q TaskRestartChange
	return (c.Action == "restart-task" || standaloneControlAction(c.Action) != "") && c.Expected > 0 && canonical(c.Payload, &q) == nil && q.valid()
}

type TaskRestartQuery struct {
	Action    string `json:",omitempty"`
	Selection containerops.Selection
	Operation string
}

func (q TaskRestartQuery) Valid(plan bool) bool {
	if plan {
		return q.Operation == "" && q.Selection.Valid() && (q.Action == "" || q.Selection.Standalone != "" && standaloneControlAction(q.Action) != "")
	}
	return q.Action == "" && (lifecycle.ValidID(q.Selection.App) && q.Selection.Standalone == "" || q.Selection.App == "" && lifecycle.ValidID(q.Selection.Standalone)) && q.Selection.Service == "" && q.Selection.Instance == "" && lifecycle.ValidID(q.Operation)
}

// The accepted user grant and exact plan live with the app, not a new queue or
// DB. The node's private receipt holds sent-before-SDK phases; signed reports
// mirror progress here and never authorize another operation.
type TaskRestartRecord struct {
	Policy   *StandalonePolicyReport `json:",omitempty"`
	Origin   UserOperation
	Plan     TaskRestartPlan
	Revision uint64
	Control  *checker.ContainerControl `json:",omitempty"`
	At       uint64
}
type TaskRestartStatus struct {
	Operation, Status, User string
	Reason                  *OperationReason `json:",omitempty"`
	Plan                    TaskRestartPlan
	Revision, At            uint64
	Control                 *checker.ContainerControl `json:",omitempty"`
}

func taskRestartTarget(plan TaskRestartPlan) [32]byte {
	plan.InventoryRevision = 0
	plan.Target = [32]byte{}
	if plan.ManagementTarget != nil {
		// Only the explicitly selected new mode replaces observation-only
		// metadata revision with the stable signed management intent. Nil
		// retains the exact historical hash, including StandaloneRevision.
		plan.StandaloneRevision = 0
	}
	raw, _ := json.Marshal(plan)
	return sha256.Sum256(append([]byte("sfc-task-restart-target-1\x00"), raw...))
}
func taskRestartRequest(op UserOperation) [32]byte {
	return sha256.Sum256(append([]byte("sfc-task-restart-request-1\x00"), OperationBytes(op)...))
}

func (r TaskRestartRecord) InitialControl() (checker.ContainerControl, error) {
	digest := r.RequestDigest()
	t := r.Plan.Container
	target := contract.Target{Service: t.Service, TaskKey: t.Instance, NativeID: t.NativeID, Owner: hex.EncodeToString(t.Owner[:]), OwnerBoot: r.Plan.OwnerBoot, Generation: t.Generation, Revision: t.Revision, StartedAt: t.StartedAt}
	action := r.Plan.Action
	if action == "" {
		action = checker.RestartContainer
	}
	return checker.NewRequestedContainerControl(hex.EncodeToString(digest[:]), digest, target, action)
}
func ownTaskRestart(r TaskRestartRecord) TaskRestartRecord {
	raw, _ := json.Marshal(r)
	var own TaskRestartRecord
	_ = json.Unmarshal(raw, &own)
	return own
}

func validateTaskRestarts(rows []TaskRestartRecord, scope deployment.AppScope) error {
	if len(rows) > 128 {
		return ErrCatalog
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Policy != nil {
			if !validStandalonePolicyRestart(r, scope) || seen[r.Operation()] {
				return ErrCatalog
			}
			seen[r.Operation()] = true
			continue
		}
		var q TaskRestartChange
		if r.Origin.VerifyOriginal(scope.Cluster) != nil || !TaskRestartCASAllowed(r.Origin.Change) || canonical(r.Origin.Change.Payload, &q) != nil || (r.Origin.Change.Action == "restart-task" && (r.Plan.Action != "" || q.Standalone != "") || r.Origin.Change.Action != "restart-task" && r.Plan.Action != standaloneControlAction(r.Origin.Change.Action)) || q.Tenant != scope.Tenant || (q.Standalone == "" && q.App != scope.App || q.Standalone != "" && (q.App != "" || r.Plan.Container.Standalone != q.Standalone)) || r.Plan.Schema != 1 || !r.Plan.Container.Valid() || r.Plan.Registration == ([32]byte{}) || r.Plan.Target != taskRestartTarget(r.Plan) || r.Plan.StopGraceSeconds < 0 || r.Plan.StopGraceSeconds > 86400 || r.Plan.Target != q.Target || r.Plan.Tenant != q.Tenant || r.Plan.App != scope.App || r.Plan.InventoryRevision != r.Origin.Change.Expected || r.Plan.Container.Cluster != scope.Cluster || r.Plan.Container.Tenant != q.Tenant || r.Plan.Container.App != scope.App || q.Selection.Service != "" && r.Plan.Container.Service != q.Selection.Service || q.Selection.Instance != "" && r.Plan.Container.Instance != q.Selection.Instance || !r.Plan.PreserveNative || !r.Plan.PreserveLogs || !r.Plan.PreserveWritableLayer || r.Revision == 0 || r.At < uint64(r.Origin.At) || seen[q.Operation] {
			return ErrCatalog
		}
		if StandaloneCASAllowed(r.Origin.Change) {
			if q.ManagementTarget == nil || r.Plan.ManagementTarget == nil || *q.ManagementTarget != *r.Plan.ManagementTarget || r.Plan.StandaloneRevision != r.Origin.Change.Expected {
				return ErrCatalog
			}
		} else if q.ManagementTarget != nil || r.Plan.ManagementTarget != nil {
			return ErrCatalog
		}
		initial, err := r.InitialControl()
		if err != nil {
			return err
		}
		if r.Control != nil && (r.Control.Validate() != nil || r.Control.RunID != initial.RunID || r.Control.RequestDigest != initial.RequestDigest || r.Control.Target != initial.Target || r.Control.Action != initial.Action) {
			return ErrCatalog
		}
		seen[q.Operation] = true
	}
	return nil
}

func (p Policy) PlanTaskRestart(s state.State, session access.Session, at int64, tenant string, selection containerops.Selection) (TaskRestartPlan, error) {
	return p.PlanTaskControl(s, session, at, tenant, selection, "restart-task")
}

func (p Policy) PlanTaskControl(s state.State, session access.Session, at int64, tenant string, selection containerops.Selection, method string) (TaskRestartPlan, error) {
	return p.planTaskControl(s, session, at, tenant, selection, method, false)
}

// A new signed standalone CAS may consume a later ALREADY ADMITTED observation
// of the same exact native/StartedAt/boot. It never changes the signed user At.
// Ordinary reads and saved legacy controls retain the original time boundary.
func (p Policy) planTaskControl(s state.State, session access.Session, at int64, tenant string, selection containerops.Selection, method string, allowNewerObservation bool) (TaskRestartPlan, error) {
	var plan TaskRestartPlan
	var err error
	p, err = p.Current(s)
	if err != nil {
		return plan, err
	}
	target, err := p.containerSelectionTarget(s, session, at, tenant, selection)
	if err != nil {
		return plan, err
	}
	c, err := p.Catalog(s)
	if err != nil || c.OperationAllowed(session, method) != nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Deploy, target.Node) != nil {
		return plan, access.ErrDenied
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return plan, err
	}
	scope := selection.App
	if selection.Standalone != "" {
		scope, _ = a.StandaloneScope(tenant, selection.Standalone)
	}
	entry, ok := a.entries[appKey(tenant, scope)]
	if method == "restart-task" && entry.Standalone != nil {
		return plan, access.ErrDenied
	}
	if method != "restart-task" && (entry.Standalone == nil || standaloneControlAction(method) == "") {
		return plan, access.ErrDenied
	}
	if !ok || !standaloneActor(c, entry, session.User) || entry.Standalone != nil && entry.Standalone.Lifetime == "temp" && at >= entry.Standalone.ExpiresAt || entry.Down != nil || entry.PendingSync != nil {
		return plan, containerops.ErrTarget
	}
	if _, retiring := entry.Inventory.Retirement(); retiring {
		return plan, containerops.ErrTarget
	}
	ref := deployment.ObjectRef{Key: target.Instance, Generation: target.Generation, Revision: target.Revision}
	claim, ok := a.Claim(tenant, scope, ref)
	if !ok || claim.Observation == nil || claim.Observation.Released || claim.Observation.OwnerBoot == "" || target.StartedAt == "" || target.NativeID == "" {
		return plan, containerops.ErrTarget
	}
	if claim.Observation.At > uint64(at) {
		if !allowNewerObservation {
			return plan, containerops.ErrTarget
		}
	} else if claim.Observation.Expired {
		return plan, containerops.ErrTarget
	}
	for _, row := range entry.TaskRestarts {
		if row.Plan.Container.Instance == target.Instance && (row.Control == nil || !row.Control.Terminal()) {
			return plan, access.ErrConflict
		}
	}
	var goal deployment.GoalCommand
	var service deployment.ComposeService
	if canonical([]byte(claim.Command.Value), &goal) != nil || canonical(goal.Config, &service) != nil {
		return plan, ErrCatalog
	}
	stop, err := engine.ParseStopPolicy(service.StopGracePeriod, service.StopSignal)
	if err != nil {
		return plan, err
	}
	grace := 10
	if stop != nil {
		grace = stop.GraceSeconds
	}
	plan = TaskRestartPlan{Schema: 1, Tenant: tenant, App: scope, InventoryRevision: entry.Inventory.Revision(), Container: target, OwnerBoot: claim.Observation.OwnerBoot, StopGraceSeconds: grace, PreserveNative: true, PreserveWritableLayer: true, PreserveLogs: true}
	if method != "restart-task" {
		plan.Action = standaloneControlAction(method)
		plan.StandaloneRevision = entry.Standalone.Revision
		management := entry.standaloneTarget()
		plan.ManagementTarget = &management
	}
	plan.Registration = appRegistrationDigest(entry.Origin)
	plan.Target = taskRestartTarget(plan)
	return plan, nil
}

func (p Policy) beginTaskRestart(s state.State, a Apps, op UserOperation) (map[string][]byte, state.Code) {
	var q TaskRestartChange
	if !TaskRestartCASAllowed(op.Change) || canonical(op.Change.Payload, &q) != nil {
		return nil, state.Invalid
	}
	plan, err := p.planTaskControl(s, op.Session, op.At, q.Tenant, q.selection(), op.Change.Action, StandaloneCASAllowed(op.Change))
	if err == nil && q.Standalone != "" && !StandaloneCASAllowed(op.Change) {
		// A previously stored request contains the historical full metadata
		// ordinal in its hash. Reproduce that plan, never upgrade its mode.
		plan.ManagementTarget = nil
		plan.Target = taskRestartTarget(plan)
	}
	if err != nil || plan.Target != q.Target || plan.StandaloneRevision == 0 && op.Change.Expected > plan.InventoryRevision {
		return nil, state.ConditionFailed
	}
	entry := a.entries[appKey(q.Tenant, plan.App)]
	if entry.Standalone != nil {
		if StandaloneCASAllowed(op.Change) {
			if !StandaloneCASAllowed(op.Change) || q.ManagementTarget == nil || plan.ManagementTarget == nil || *q.ManagementTarget != *plan.ManagementTarget || op.Change.Expected > entry.Standalone.Revision {
				return nil, state.ConditionFailed
			}
		} else if entry.Standalone.Revision != op.Change.Expected {
			return nil, state.ConditionFailed
		}
	}
	if len(entry.TaskRestarts) >= 128 {
		return nil, state.ConditionFailed
	}
	for _, old := range entry.TaskRestarts {
		var previous TaskRestartChange
		_ = json.Unmarshal(old.Origin.Change.Payload, &previous)
		if previous.Operation == q.Operation {
			return nil, state.ConditionFailed
		}
	}
	plan.InventoryRevision = op.Change.Expected
	if StandaloneCASAllowed(op.Change) {
		plan.StandaloneRevision = op.Change.Expected
	}
	row := TaskRestartRecord{Origin: op, Plan: plan, Revision: 1, At: uint64(op.At)}
	if _, err = row.InitialControl(); err != nil {
		return nil, state.Invalid
	}
	entry.TaskRestarts = append(slices.Clone(entry.TaskRestarts), row)
	if entry.Standalone != nil {
		m := *entry.Standalone
		m.Revision++
		if op.Change.Action == "standalone-stop" {
			m.Desired = "stopped"
		} else {
			m.Desired = "running"
		}
		entry.Standalone = &m
	}
	a.entries[appKey(q.Tenant, plan.App)] = entry
	return p.appsCheckpoint(s, a)
}

func (a Apps) TaskRestart(tenant, app, operation string) (TaskRestartRecord, bool) {
	entry, ok := a.entries[appKey(tenant, app)]
	if !ok {
		return TaskRestartRecord{}, false
	}
	for _, r := range entry.TaskRestarts {
		var q TaskRestartChange
		_ = json.Unmarshal(r.Origin.Change.Payload, &q)
		if r.Operation() == operation {
			return ownTaskRestart(r), true
		}
	}
	return TaskRestartRecord{}, false
}
func (a Apps) TaskRestartStatus(tenant, app, operation string) *TaskRestartStatus {
	r, ok := a.TaskRestart(tenant, app, operation)
	if !ok {
		return nil
	}
	status := "Accepted"
	if r.Control != nil {
		status = string(r.Control.Phase)
	}
	return &TaskRestartStatus{Operation: operation, Status: status, User: r.Origin.Session.User, Reason: r.Origin.Reason, Plan: r.Plan, Revision: r.Revision, At: r.At, Control: r.Control}
}
func (a Apps) TaskRestarts(owner [32]byte) []TaskRestartRecord {
	var out []TaskRestartRecord
	for _, entry := range a.entries {
		for _, r := range entry.TaskRestarts {
			if r.Plan.Container.Owner == owner && (r.Control == nil || !r.Control.Terminal()) {
				out = append(out, ownTaskRestart(r))
			}
		}
	}
	slices.SortFunc(out, func(a, b TaskRestartRecord) int { return time.Unix(a.Origin.At, 0).Compare(time.Unix(b.Origin.At, 0)) })
	return out
}

func (a Apps) TaskRestartPending(owner [32]byte, key string) bool {
	for _, row := range a.TaskRestarts(owner) {
		if row.Plan.Container.Instance == key {
			return true
		}
	}
	return false
}
func (a Apps) TaskRestartEvidence(owner [32]byte, key, native string, generation, revision uint64, before string) []TaskRestartRecord {
	var out []TaskRestartRecord
	for _, entry := range a.entries {
		for _, row := range entry.TaskRestarts {
			t := row.Plan.Container
			if t.Owner == owner && t.Instance == key && t.NativeID == native && t.Generation == generation && t.Revision == revision && t.StartedAt == before && row.RestartEvidence() != nil {
				out = append(out, ownTaskRestart(row))
			}
		}
	}
	return out
}

func (p TaskRestartPlan) Valid() bool {
	return (p.ManagementTarget == nil || *p.ManagementTarget != ([32]byte{}) && p.Container.Standalone != "" && p.StandaloneRevision > 0) && p.Schema == 1 && p.Container.Valid() && p.Container.Tenant == p.Tenant && p.Container.App == p.App && p.InventoryRevision > 0 && p.Registration != ([32]byte{}) && p.Target == taskRestartTarget(p) && p.Container.NativeID != "" && p.Container.StartedAt != "" && p.OwnerBoot != "" && p.StopGraceSeconds >= 0 && p.StopGraceSeconds <= 86400 && p.PreserveNative && p.PreserveLogs && p.PreserveWritableLayer
}

func pendingTaskRestarts(entry appEntry) bool {
	for _, row := range entry.TaskRestarts {
		if row.Control == nil || !row.Control.Terminal() {
			return true
		}
	}
	return false
}

func standaloneControlAction(action string) checker.ContainerAction {
	switch action {
	case "standalone-stop":
		return checker.StopContainer
	case "standalone-start":
		return checker.StartContainer
	case "standalone-restart":
		return checker.RestartContainer
	}
	return ""
}
