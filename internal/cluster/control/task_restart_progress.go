// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"math"
)

type TaskRestartPermitRequest struct {
	Tenant, App, Operation string
	At                     int64 `json:",omitempty"`
	Request                [32]byte
}
type TaskRestartPermit struct {
	Index   uint64
	Allowed bool
}

// A quorum read authorizes only the next previously unsent SDK call. Recovery
// can still inspect and settle a sent original after its grant is revoked.
func (p Policy) TaskRestartPermit(s state.State, caller [32]byte, q TaskRestartPermitRequest) (TaskRestartPermit, error) {
	var out TaskRestartPermit
	p, err := p.Current(s)
	if err != nil {
		return out, err
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return out, access.ErrDenied
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return out, err
	}
	row, ok := a.TaskRestart(q.Tenant, q.App, q.Operation)
	if !ok || !p.ownsResource(s, caller, row.Plan.Container.Owner) || row.RequestDigest() != q.Request {
		return out, access.ErrDenied
	}
	out.Index = s.Index()
	entry := a.entries[appKey(q.Tenant, q.App)]
	if !members.WorkKey(caller) || entry.Down != nil || entry.PendingSync != nil || appRegistrationDigest(entry.Origin) != row.Plan.Registration || row.Control != nil && row.Control.Terminal() {
		return out, nil
	}
	if _, retiring := entry.Inventory.Retirement(); retiring {
		return out, nil
	}
	t := row.Plan.Container
	claim, ok := a.Claim(q.Tenant, q.App, deployment.ObjectRef{Key: t.Instance, Generation: t.Generation, Revision: t.Revision})
	if !ok || claim.Removed || claim.Observation == nil || claim.Observation.Released || claim.Observation.Owner != t.Owner || !p.ownsResource(s, caller, claim.Observation.Owner) || claim.Observation.Native != t.NativeID {
		return out, nil
	}
	original := s.Object(t.Instance)
	binding, bound := a.Binding(deployment.ObjectRef{Key: t.Instance, Generation: t.Generation, Revision: t.Revision})
	if !original.Present || original.Generation != t.Generation || original.Revision != t.Revision || original.Value != claim.Command.Value || !bound || binding.Digest() != t.Binding {
		return out, nil
	}
	users, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	out.Allowed = users.OperationAllowed(row.Origin.Session, row.Origin.Change.Action) == nil && users.AuthorizeAccepted(row.Origin.Session, p.Cluster, row.Origin.At, q.Tenant, access.Deploy, t.Node) == nil
	if row.Policy != nil && (entry.Standalone == nil || entry.Standalone.Lifetime != "fixed" || entry.Standalone.Desired != "running" || entry.Standalone.Restart == "no") {
		out.Allowed = false
	}
	if entry.Standalone != nil && entry.Standalone.Lifetime == "temp" && (q.At <= 0 || q.At >= entry.Standalone.ExpiresAt) {
		out.Allowed = false
	}
	return out, nil
}

type TaskRestartReport struct {
	Schema                            uint8
	Kind                              string
	Cluster, Reporter                 [32]byte
	Tenant, App, Operation            string
	Expected, RootRevision, Epoch, At uint64
	Control                           checker.ContainerControl
	Signature                         []byte
}

func TaskRestartReportBytes(r TaskRestartReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-task-restart-report-1\x00"), raw...)
}
func (r TaskRestartReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: AppsKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func taskRestartReportValue(raw []byte) bool {
	var v struct{ Kind string }
	return json.Unmarshal(raw, &v) == nil && v.Kind == "task-restart"
}
func (p Policy) taskRestartReport(s state.State, cmd state.Command) (TaskRestartReport, error) {
	var r TaskRestartReport
	if cmd.Kind != state.ModuleReport || cmd.Key != AppsKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Kind != "task-restart" || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.Expected == 0 || r.At == 0 || r.At > math.MaxInt64 || !lifecycle.ValidID(r.Tenant) || !lifecycle.ValidID(r.App) || !lifecycle.ValidID(r.Operation) || r.Control.Validate() != nil || !ed25519.Verify(ed25519.PublicKey(r.Reporter[:]), TaskRestartReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	original, err := r.Command()
	members, me := p.Members(s)
	if err != nil || original != cmd || me != nil || !members.MemberKey(r.Reporter) {
		return r, ErrCatalog
	}
	return r, nil
}
func (p Policy) reduceTaskRestart(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.taskRestartReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	a, err := p.Apps(s)
	if err != nil {
		return nil, state.Invalid
	}
	entry, ok := a.entries[appKey(r.Tenant, r.App)]
	if !ok {
		return nil, state.ConditionFailed
	}
	for i, row := range entry.TaskRestarts {
		var q TaskRestartChange
		_ = json.Unmarshal(row.Origin.Change.Payload, &q)
		if row.Operation() != r.Operation {
			continue
		}
		initial, err := row.InitialControl()
		if err != nil || !p.ownsResource(s, r.Reporter, row.Plan.Container.Owner) || row.Revision != r.Expected || r.At < row.At {
			return nil, state.ConditionFailed
		}
		before := initial
		if row.Control != nil {
			before = *row.Control
		}
		if !before.CanAdvanceTo(r.Control) {
			return nil, state.ConditionFailed
		}
		if before == r.Control && row.Control != nil {
			return nil, state.ConditionFailed
		}
		row.Control = &r.Control
		row.Revision++
		row.At = r.At
		entry.TaskRestarts[i] = row
		a.entries[appKey(r.Tenant, r.App)] = entry
		return p.appsCheckpoint(s, a)
	}
	return nil, state.ConditionFailed
}

// A user restart proof is accepted only after the corresponding original user
// grant and the owner's completed receipt are in the same Raft state. A member
// signature alone must not manufacture a user-initiated instance transition.
func validUserRestart(entry appEntry, o deployment.Observation) bool {
	if o.Restart == nil || o.Restart.User == nil {
		return true
	}
	ref := o.Restart.User
	for _, row := range entry.TaskRestarts {
		var q TaskRestartChange
		_ = json.Unmarshal(row.Origin.Change.Payload, &q)
		if row.Operation() == ref.Operation && row.RequestDigest() == ref.Request && row.Plan.Container.Instance == o.Key && row.Plan.Container.NativeID == o.Native && row.Plan.Container.Generation == o.Generation && row.Plan.Container.Revision == o.Revision && row.Plan.Container.Owner == o.Owner && row.Control != nil && *row.Control == o.Restart.Control && row.Control.Phase == checker.ControlCompleted {
			return true
		}
	}
	return false
}
func (r TaskRestartRecord) RestartEvidence() *deployment.TaskRestart {
	if r.Control == nil || r.Control.Phase != checker.ControlCompleted || r.Control.Action == checker.StopContainer {
		return nil
	}
	var q TaskRestartChange
	_ = json.Unmarshal(r.Origin.Change.Payload, &q)
	return &deployment.TaskRestart{User: &deployment.UserRestart{Operation: r.Operation(), Request: r.RequestDigest()}, Control: *r.Control}
}
