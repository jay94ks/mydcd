// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"math"
	"slices"
	"time"
)

// StandalonePolicyReport is the exact owner's observation against the original
// accepted policy. It is never a replacement user login or a new down request.
type StandalonePolicyReport struct {
	Schema                            uint8
	Kind, Action, Tenant, App, Reason string
	Cluster, Reporter, Registration   [32]byte
	Authorization                     [32]byte
	RootRevision, Expected, Epoch     uint64
	At                                int64
	Connections                       int
	DisconnectedAt                    int64 `json:",omitempty"`
	Signature                         []byte
	ResourceOwner                     *[32]byte `json:",omitempty"`
}

func (q StandalonePolicyReport) resourceOwner() [32]byte {
	if q.ResourceOwner != nil {
		return *q.ResourceOwner
	}
	return q.Reporter
}

func StandalonePolicyBytes(q StandalonePolicyReport) []byte {
	q.Signature = nil
	raw, _ := json.Marshal(q)
	return append([]byte("mydc-standalone-policy-1\x00"), raw...)
}
func (q StandalonePolicyReport) Command() (state.Command, error) {
	raw, err := json.Marshal(q)
	if err != nil {
		return state.Command{}, err
	}
	c := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(q.Reporter[:]), Epoch: q.Epoch, Key: AppsKey, Expected: q.RootRevision, Value: string(raw)}
	c.RequestID = state.ReportRequestID(c)
	_, err = state.EncodeCommand(c)
	return c, err
}
func standalonePolicyValue(raw []byte) bool {
	var q struct{ Kind string }
	return json.Unmarshal(raw, &q) == nil && q.Kind == "standalone-policy"
}
func (p Policy) standalonePolicyReport(s state.State, cmd state.Command) (StandalonePolicyReport, error) {
	var q StandalonePolicyReport
	if cmd.Kind != state.ModuleReport || cmd.Key != AppsKey || canonical([]byte(cmd.Value), &q) != nil || q.Schema != 1 || q.Kind != "standalone-policy" || q.Cluster != p.Cluster || q.Epoch != s.ModuleEpoch() || q.At <= 0 || q.At == math.MaxInt64 || q.Expected == 0 || !lifecycle.ValidID(q.Tenant) || !lifecycle.ValidID(q.App) || q.DisconnectedAt < 0 || q.DisconnectedAt > q.At || q.Connections > 0 && q.DisconnectedAt != 0 || q.Connections < 0 || q.Connections > 64 || !ed25519.Verify(q.Reporter[:], StandalonePolicyBytes(q), q.Signature) {
		return q, access.ErrDenied
	}
	original, err := q.Command()
	members, e := p.Members(s)
	if err != nil || original != cmd || e != nil || !members.MemberKey(q.Reporter) || !p.ownsResource(s, q.Reporter, q.resourceOwner()) {
		return q, access.ErrDenied
	}
	return q, nil
}
func standalonePolicyID(q StandalonePolicyReport) string {
	d := sha256.Sum256(StandalonePolicyBytes(q))
	return "standalone-cleanup-" + hex.EncodeToString(d[:16])
}
func standaloneOwner(e appEntry, owner [32]byte) bool {
	x, ok := e.Inventory.Execution()
	if !ok {
		return false
	}
	for _, step := range x.Blueprint().Steps() {
		if step.Kind == "task" && step.Owner == owner {
			return true
		}
	}
	return false
}
func validStandaloneCleanup(e appEntry) bool {
	if e.Standalone == nil || e.Standalone.Cleanup == nil {
		return false
	}
	q := *e.Standalone.Cleanup
	return q.Schema == 1 && q.Kind == "standalone-policy" && q.Action == "expire" && q.Cluster == e.Inventory.Scope().Cluster && q.Tenant == e.Inventory.Scope().Tenant && q.App == e.Inventory.Scope().App && q.Registration == appRegistrationDigest(e.Origin) && q.Authorization == appRegistrationDigest(e.Origin) && q.At >= e.Origin.At && q.Expected > 0 && (q.Reason == "ttl" || q.Reason == "disconnected" || q.Reason == "exited") && ed25519.Verify(q.Reporter[:], StandalonePolicyBytes(q), q.Signature)
}
func (p Policy) reduceStandalonePolicy(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	q, err := p.standalonePolicyReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	a, err := p.Apps(s)
	if err != nil {
		return nil, state.Invalid
	}
	key := appKey(q.Tenant, q.App)
	e, ok := a.entries[key]
	if !ok || e.Standalone == nil || e.Standalone.Revision != q.Expected || e.Standalone.Cleanup != nil || e.Down != nil || q.Registration != appRegistrationDigest(e.Origin) || q.Authorization != appRegistrationDigest(standalonePolicyOrigin(e)) || q.At < e.Origin.At || q.At < e.Standalone.ConnectionAt || !standaloneOwner(e, q.resourceOwner()) {
		return nil, state.ConditionFailed
	}
	if _, retiring := e.Inventory.Retirement(); retiring {
		return nil, state.ConditionFailed
	}
	m := *e.Standalone
	switch q.Action {
	case "connections":
		if q.Reason != "" {
			return nil, state.Invalid
		}
		if m.Connections == q.Connections && m.ConnectionAt == q.At {
			return nil, state.ConditionFailed
		}
		if q.Connections == 0 {
			if q.DisconnectedAt > 0 {
				m.DisconnectedAt = max(m.DisconnectedAt, q.DisconnectedAt)
			} else if m.Connections > 0 {
				m.DisconnectedAt = q.At
			}
		} else {
			m.DisconnectedAt = 0
		}
		m.Connections = q.Connections
		m.ConnectionAt = q.At
	case "expire":
		if m.Lifetime != "temp" || q.Connections != 0 {
			return nil, state.ConditionFailed
		}
		allowed := q.Reason == "ttl" && q.At >= m.ExpiresAt || q.Reason == "disconnected" && m.Connections == 0 && m.DisconnectedAt > 0 && q.At-m.DisconnectedAt >= m.GraceSeconds
		if q.Reason == "exited" {
			for _, c := range e.Inventory.Claims() {
				if c.Step.Kind == "task" && c.Step.Owner == q.resourceOwner() && c.Observation != nil && c.Observation.Exit != nil && !c.Observation.Released && q.At >= 0 && c.Observation.Live(uint64(q.At)) {
					allowed = true
				}
			}
		}
		if !allowed {
			return nil, state.ConditionFailed
		}
		// Acceptance of temp included this bounded removal policy. Revocation can
		// prevent starts, but cannot make its original native/data references leak.
		e.Inventory, err = e.Inventory.RetireAcceptedPolicy(e.Inventory.Revision(), e.Origin.Session.User, standalonePolicyID(q), cmd.Actor, cmd.Epoch)
		if err != nil {
			return nil, state.ConditionFailed
		}
		m.Cleanup = &q
		m.Desired = "stopped"
		m.Connections = 0
	case "restart":
		if m.Lifetime != "fixed" || m.Desired != "running" || m.Restart == "no" || q.Connections != 0 || q.Reason != "" {
			return nil, state.ConditionFailed
		}
		return p.beginStandalonePolicyRestart(s, a, e, q)
	default:
		return nil, state.Invalid
	}
	m.Revision++
	e.Standalone = &m
	a.entries[key] = e
	return p.appsCheckpoint(s, a, uint64(q.At))
}
func (p Policy) reduceStandaloneRemove(s state.State, a Apps, c access.Catalog, op UserOperation) (map[string][]byte, state.Code) {
	var q StandaloneChange
	if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Operation) || q.NewName != "" || q.Restart != "" {
		return nil, state.Invalid
	}
	key, e, ok := a.standalone(q.Tenant, q.Name)
	if !ok || !standaloneActor(c, e, op.Session.User) || !standaloneChangeMatches(e, op, q) || e.Standalone.Cleanup != nil || e.Down != nil {
		return nil, state.ConditionFailed
	}
	cmd, err := op.Command()
	if err != nil {
		return nil, state.Invalid
	}
	e.Inventory, err = e.Inventory.Retire(e.Inventory.Revision(), c, op.Session.User, q.Operation, cmd.Actor, cmd.Epoch, nil, true)
	if err != nil {
		return nil, state.ConditionFailed
	}
	m := *e.Standalone
	m.Revision++
	m.Desired = "stopped"
	e.Standalone = &m
	e.Down = &op
	a.entries[key] = e
	return p.appsCheckpoint(s, a, uint64(op.At))
}

// StandaloneWork reuses the Apps inventory; no second workload registry exists.
type StandaloneWork struct {
	Tenant, App   string
	Metadata      StandaloneMetadata
	Registration  [32]byte
	Authorization [32]byte
	Target        *containerops.Target
	Exited        bool
	ExitCode      int
}

func (a Apps) StandaloneWork(owner [32]byte) []StandaloneWork {
	var out []StandaloneWork
	for _, e := range a.entries {
		if e.Standalone == nil || e.Down != nil || e.Standalone.Cleanup != nil || !standaloneOwner(e, owner) {
			continue
		}
		if _, retiring := e.Inventory.Retirement(); retiring {
			continue
		}
		m := *e.Standalone
		m.LastChange = nil
		m.LastExtension = nil
		w := StandaloneWork{Tenant: e.Inventory.Scope().Tenant, App: e.Inventory.Scope().App, Metadata: m, Registration: appRegistrationDigest(e.Origin), Authorization: appRegistrationDigest(standalonePolicyOrigin(e))}
		for _, c := range e.Inventory.Claims() {
			if c.Step.Kind != "task" || c.Step.Owner != owner || c.Removed || c.Observation == nil {
				continue
			}
			bound, ok := a.Binding(deployment.ObjectRef{Key: c.Step.Key, Generation: c.Result.Generation, Revision: c.Result.Revision})
			if !ok {
				continue
			}
			u := bound.Needs().Use
			t := containerops.Target{Standalone: m.Name, Cluster: e.Inventory.Scope().Cluster, Owner: owner, Binding: bound.Digest(), Tenant: u.Tenant, App: u.App, Service: u.Service, Node: u.Node, Instance: c.Step.Key, Generation: c.Result.Generation, Revision: c.Result.Revision, NativeID: c.Observation.Native, StartedAt: time.Unix(0, c.Observation.StartedAt).UTC().Format(time.RFC3339Nano)}
			if t.Valid() && c.Observation.StartedAt > 0 {
				w.Target = &t
				if c.Observation.Exit != nil {
					w.Exited = true
					w.ExitCode = c.Observation.Exit.Code
				}
			}
		}
		out = append(out, w)
	}
	slices.SortFunc(out, func(a, b StandaloneWork) int {
		if a.Tenant+"/"+a.App < b.Tenant+"/"+b.App {
			return -1
		}
		return 1
	})
	return out
}

func (p Policy) validateStandaloneDown(e appEntry) error {
	if e.Standalone.Cleanup != nil {
		if e.Down != nil || !validStandaloneCleanup(e) {
			return ErrCatalog
		}
		if r, ok := e.Inventory.Retirement(); ok {
			q := *e.Standalone.Cleanup
			if !r.Down || r.KeepExecution || r.ID != standalonePolicyID(q) || r.Actor != e.Origin.Session.User || r.Submitter != "node/"+hex.EncodeToString(q.Reporter[:]) || r.Epoch != q.Epoch {
				return ErrCatalog
			}
		} else if _, active := e.Inventory.Execution(); active {
			return ErrCatalog
		}
		return nil
	}
	if e.Down == nil {
		return p.validateAppDown(e.Inventory, e.Origin, nil)
	}
	var q StandaloneChange
	op := *e.Down
	if op.Change.Action != "standalone-remove" || op.VerifyOriginal(p.Cluster) != nil || canonical(op.Change.Payload, &q) != nil || q.Tenant != e.Inventory.Scope().Tenant || q.Name != e.Standalone.Name || !lifecycle.ValidID(q.Operation) {
		return ErrCatalog
	}
	if r, ok := e.Inventory.Retirement(); ok {
		cmd, err := op.Command()
		if err != nil || !r.Down || r.ID != q.Operation || r.Actor != op.Session.User || r.Submitter != cmd.Actor || r.Epoch != cmd.Epoch {
			return ErrCatalog
		}
	} else if _, active := e.Inventory.Execution(); active {
		return ErrCatalog
	}
	return nil
}

func (r TaskRestartRecord) Operation() string {
	if r.Policy != nil {
		d := sha256.Sum256(StandalonePolicyBytes(*r.Policy))
		return "standalone-restart-" + hex.EncodeToString(d[:16])
	}
	var q TaskRestartChange
	_ = json.Unmarshal(r.Origin.Change.Payload, &q)
	return q.Operation
}
func (r TaskRestartRecord) RequestDigest() [32]byte {
	if r.Policy == nil {
		return taskRestartRequest(r.Origin)
	}
	raw, _ := json.Marshal(struct {
		Origin UserOperation
		Policy StandalonePolicyReport
		Target [32]byte
	}{r.Origin, *r.Policy, r.Plan.Target})
	return sha256.Sum256(append([]byte("mydc-standalone-policy-control-1\x00"), raw...))
}
func validStandalonePolicyRestart(r TaskRestartRecord, scope deployment.AppScope) bool {
	q := r.Policy
	if q == nil || q.Action != "restart" || q.Kind != "standalone-policy" || q.Schema != 1 || q.Cluster != scope.Cluster || q.Tenant != scope.Tenant || q.App != scope.App || q.At < r.Origin.At || q.Expected == 0 || q.Authorization != appRegistrationDigest(r.Origin) || (r.Origin.Change.Action != "standalone-up" && r.Origin.Change.Action != "standalone-pin") || r.Origin.VerifyOriginal(scope.Cluster) != nil || !ed25519.Verify(q.Reporter[:], StandalonePolicyBytes(*q), q.Signature) || !r.Plan.Valid() || r.Plan.Action != checker.StartContainer || r.Plan.Container.Standalone == "" || r.Plan.Container.Owner != q.resourceOwner() || r.Plan.Registration != q.Registration || r.Revision == 0 || r.At < uint64(q.At) {
		return false
	}
	initial, err := r.InitialControl()
	return err == nil && (r.Control == nil || initial.CanAdvanceTo(*r.Control))
}
func (p Policy) beginStandalonePolicyRestart(s state.State, a Apps, e appEntry, q StandalonePolicyReport) (map[string][]byte, state.Code) {
	e = pruneStandalonePolicyRestarts(e)
	if pendingTaskRestarts(e) || len(e.TaskRestarts) >= 128 {
		return nil, state.ConditionFailed
	}
	c, err := p.Catalog(s)
	if err != nil || c.OperationAllowed(standalonePolicyOrigin(e).Session, standalonePolicyOrigin(e).Change.Action) != nil || c.AuthorizeAccepted(standalonePolicyOrigin(e).Session, p.Cluster, standalonePolicyOrigin(e).At, q.Tenant, access.Deploy, e.Standalone.Node) != nil {
		return nil, state.Forbidden
	}
	var selected *containerops.Target
	for _, w := range a.StandaloneWork(q.resourceOwner()) {
		if w.Tenant == q.Tenant && w.App == q.App {
			selected = w.Target
		}
	}
	if selected == nil {
		return nil, state.ConditionFailed
	}
	t := *selected
	claim, ok := a.Claim(q.Tenant, q.App, deployment.ObjectRef{Key: t.Instance, Generation: t.Generation, Revision: t.Revision})
	if !ok || claim.Observation == nil || claim.Observation.Exit == nil || claim.Observation.Released || claim.Observation.OwnerBoot == "" || !claim.Observation.Live(uint64(q.At)) || e.Standalone.Restart == "on-failure" && claim.Observation.Exit.Code == 0 {
		return nil, state.ConditionFailed
	}
	for _, old := range e.TaskRestarts {
		if old.Policy != nil && old.Plan.Container.Instance == t.Instance && old.Plan.Container.StartedAt == t.StartedAt {
			return nil, state.ConditionFailed
		}
	}
	var goal deployment.GoalCommand
	var service deployment.ComposeService
	if canonical([]byte(claim.Command.Value), &goal) != nil || canonical(goal.Config, &service) != nil {
		return nil, state.Invalid
	}
	stop, err := engine.ParseStopPolicy(service.StopGracePeriod, service.StopSignal)
	if err != nil {
		return nil, state.Invalid
	}
	grace := 10
	if stop != nil {
		grace = stop.GraceSeconds
	}
	plan := TaskRestartPlan{Schema: 1, Tenant: q.Tenant, App: q.App, InventoryRevision: e.Inventory.Revision(), StandaloneRevision: e.Standalone.Revision, Action: checker.StartContainer, Registration: q.Registration, Container: t, OwnerBoot: claim.Observation.OwnerBoot, StopGraceSeconds: grace, PreserveNative: true, PreserveWritableLayer: true, PreserveLogs: true}
	plan.Target = taskRestartTarget(plan)
	row := TaskRestartRecord{Origin: standalonePolicyOrigin(e), Policy: &q, Plan: plan, Revision: 1, At: uint64(q.At)}
	if _, err = row.InitialControl(); err != nil {
		return nil, state.Invalid
	}
	e.TaskRestarts = append(slices.Clone(e.TaskRestarts), row)
	a.entries[appKey(q.Tenant, q.App)] = e
	return p.appsCheckpoint(s, a, uint64(q.At))
}

// CheckStandalonePolicy uses the same reducer before proposing an owner report.
// A denied current grant or already-controlled incarnation emits no new intent.
func (p Policy) CheckStandalonePolicy(s state.State, q StandalonePolicyReport) bool {
	cmd, err := q.Command()
	if err != nil {
		return false
	}
	_, code := p.reduceStandalonePolicy(s, cmd)
	return code == state.Applied
}
func standaloneActivationAllowed(e appEntry, at int64) bool {
	return e.Standalone == nil || e.Standalone.Cleanup == nil && e.Down == nil && e.Standalone.Desired == "running" && (e.Standalone.Lifetime != "temp" || at > 0 && at < e.Standalone.ExpiresAt)
}
func (a Apps) StandaloneActivationAllowed(tenant, scope string, at int64) bool {
	e, ok := a.entries[appKey(tenant, scope)]
	return ok && standaloneActivationAllowed(e, at)
}
func standaloneActor(c access.Catalog, e appEntry, user string) bool {
	return e.Standalone == nil || e.Standalone.Lifetime != "temp" || e.Standalone.Creator == user || c.Authorize(user, e.Inventory.Scope().Tenant, access.ManageMembers, "") == nil
}

// Only completed automatic controls whose evidence no claim still references
// can leave the bounded mirror. User operation/status records remain retained.
func pruneStandalonePolicyRestarts(e appEntry) appEntry {
	needed := map[string]bool{}
	current := map[string]int64{}
	for _, claim := range e.Inventory.Claims() {
		if claim.Observation == nil {
			continue
		}
		o := claim.Observation
		if o.Restart != nil && o.Restart.User != nil {
			needed[o.Restart.User.Operation] = true
		}
		if !claim.Removed && o.StartedAt > current[claim.Step.Key] {
			current[claim.Step.Key] = o.StartedAt
		}
	}
	e.TaskRestarts = slices.DeleteFunc(slices.Clone(e.TaskRestarts), func(r TaskRestartRecord) bool {
		before, err := time.Parse(time.RFC3339Nano, r.Plan.Container.StartedAt)
		return err == nil && r.Policy != nil && r.Control != nil && r.Control.Terminal() && !needed[r.Operation()] && current[r.Plan.Container.Instance] > before.UnixNano()
	})
	return e
}

func standalonePolicyOrigin(e appEntry) UserOperation {
	if e.Standalone != nil && e.Standalone.LastChange != nil {
		return *e.Standalone.LastChange
	}
	return e.Origin
}
