// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
)

type AppLogClear struct {
	Standalone             string `json:",omitempty"`
	Tenant, App, Operation string
	Selection              struct{ Service, Instance string }
	Target                 [32]byte
	Recreate               bool
}

func (q AppLogClear) selection() containerops.Selection {
	if q.Standalone != "" {
		return containerops.Selection{Standalone: q.Standalone, Service: q.Selection.Service, Instance: q.Selection.Instance}
	}
	return containerops.Selection{App: q.App, Service: q.Selection.Service, Instance: q.Selection.Instance}
}

func (q AppLogClear) valid() bool {
	return lifecycle.ValidID(q.Tenant) && lifecycle.ValidID(q.App) && lifecycle.ValidID(q.Operation) && q.Target != ([32]byte{}) && q.Recreate && q.selection().Valid()
}

func AppLogClearCASAllowed(change Change) bool {
	var q AppLogClear
	return (change.Action == "clear-app-logs" || change.Action == "standalone-clear-logs") && change.Expected > 0 && canonical(change.Payload, &q) == nil && q.valid()
}

// Recreate is an explicit source variant in the existing accepted-execution
// proof. It does not attach CD to a plain app or impersonate a Git sync.
type AppRecreation struct {
	Plan         AppLogClearPlan
	OriginTarget [32]byte
	Blueprint    json.RawMessage
	Retirement   string
	Closure      [32]byte
}

type AppLogClearRecord struct {
	Origin       UserOperation
	Source       AppDeliverySync
	Status       string
	Replacements []AppLogClearImpact `json:",omitempty"`
}

type AppLogClearStatus struct {
	Operation, Status string
	Target            [32]byte
	OldContainers     []AppLogClearImpact
	NewContainers     []AppLogClearImpact `json:",omitempty"`
}

func appLogClearView(entry appEntry, operation string) *AppLogClearStatus {
	if p := entry.PendingSync; p != nil && p.Recreate != nil && (operation == "" || p.Choice.Operation == operation) {
		status := "Retiring"
		if p.Recreate.Closure != ([32]byte{}) {
			status = "Removed"
		}
		return &AppLogClearStatus{Operation: p.Choice.Operation, Status: status, Target: p.Recreate.Plan.Target, OldContainers: ownLogClearImpact(p.Recreate.Plan.Impact)}
	}
	for j := len(entry.LogClears) - 1; j >= 0; j-- {
		row := entry.LogClears[j]
		if operation != "" && row.Source.Choice.Operation != operation {
			continue
		}
		status := "Recreating"
		if row.Status == "succeeded" {
			status = "Succeeded"
		}
		out := &AppLogClearStatus{Operation: row.Source.Choice.Operation, Status: status, Target: row.Source.Recreate.Plan.Target, OldContainers: ownLogClearImpact(row.Source.Recreate.Plan.Impact)}
		out.NewContainers = ownLogClearImpact(row.Replacements)
		if e, current := entry.Inventory.Execution(); current && e.ActiveOperation() == out.Operation && row.Status != "succeeded" {
			for _, claim := range entry.Inventory.Claims() {
				if claim.Step.Kind != "task" || claim.Removed || claim.Observation == nil {
					continue
				}
				for _, old := range out.OldContainers {
					if old.Kind == "task" && old.Key == claim.Step.Key {
						out.NewContainers = append(out.NewContainers, AppLogClearImpact{Key: claim.Step.Key, Kind: "task", Node: claim.Step.Node, NativeID: claim.Observation.Native, Generation: claim.Result.Generation, Revision: claim.Result.Revision, LogDriver: claim.Observation.LogDriver})
					}
				}
			}
		}
		return out
	}
	return nil
}

func ownLogClearImpact(rows []AppLogClearImpact) []AppLogClearImpact {
	return append([]AppLogClearImpact(nil), rows...)
}

func recreatedContainers(i deployment.Inventory, impact []AppLogClearImpact) []AppLogClearImpact {
	var out []AppLogClearImpact
	for _, old := range impact {
		if old.Kind != "task" {
			continue
		}
		for _, claim := range i.Claims() {
			if claim.Step.Key != old.Key || claim.Removed || claim.Observation == nil {
				continue
			}
			o := claim.Observation
			out = append(out, AppLogClearImpact{Key: claim.Step.Key, Kind: "task", Node: claim.Step.Node, NativeID: o.Native, Generation: claim.Result.Generation, Revision: claim.Result.Revision, LogDriver: o.LogDriver})
		}
	}
	return out
}

func (a Apps) LogClearStatus(tenant, app, operation string) *AppLogClearStatus {
	return appLogClearView(a.entries[appKey(tenant, app)], operation)
}

// Scheduling metadata only; the signed continuation reducer rechecks the
// original source/closure/current accepted grants before creating any goal.
func (a Apps) LogClearContinuation(tenant, app string) (string, bool) {
	proof := a.entries[appKey(tenant, app)].PendingSync
	if proof == nil || proof.Recreate == nil || proof.Recreate.Closure == ([32]byte{}) {
		return "", false
	}
	return proof.Choice.Operation, true
}

// Use the actual continuation core to avoid proposing denied work while a
// current role/source/placement prevents restart. This read creates no receipt.
func (p Policy) LogClearContinuationReady(s state.State, caller [32]byte, tenant, app string) (bool, error) {
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(caller) {
		return false, access.ErrDenied
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return false, err
	}
	entry, exists := a.entries[appKey(tenant, app)]
	if !exists || entry.PendingSync == nil || entry.PendingSync.Recreate == nil {
		return false, nil
	}
	_, err = p.continueAppLogClear(s, entry)
	return err == nil, nil
}

func (sync AppDeliverySync) verifyRecreation(origin UserOperation, scope deployment.AppScope) error {
	r := sync.Recreate
	u := sync.User
	var q AppLogClear
	if r == nil || u == nil || sync.Member != nil || u.VerifyOriginal(scope.Cluster) != nil || (u.Change.Action != "clear-app-logs" && u.Change.Action != "standalone-clear-logs") || canonical(u.Change.Payload, &q) != nil || !q.valid() || q.Tenant != scope.Tenant || q.App != scope.App || u.At < origin.At || sync.Epoch != u.Epoch || sync.Choice.Operation != q.Operation || sync.Choice.Registration != appRegistrationDigest(origin) || u.Change.Expected != r.Plan.InventoryRevision || r.Plan.Target != q.Target || r.Plan.Target != logClearTarget(r.Plan, r.OriginTarget) || r.Plan.Tenant != scope.Tenant || r.Plan.App != scope.App || r.Retirement != deployment.RecreationRetirementID(q.Operation) {
		return ErrCatalog
	}
	b, err := deployment.DecodeBlueprint(r.Blueprint)
	if err != nil || (q.Standalone == "" && b.CheckAppInput() != nil || q.Standalone != "" && b.CheckStandaloneInput() != nil) || b.Scope().Cluster != scope.Cluster || b.Scope().Tenant != scope.Tenant || b.Scope().App != scope.App || b.Scope().Deployment != scope.Deployment || b.Scope().Actor != origin.Session.User || b.Digest() != r.Plan.SourcePlan || sync.Choice.Candidate != r.Plan.SourceCandidate || sync.Intent != b.IntentDigest() || sync.Artifact != r.Plan.SourceArtifact || sync.Plan == ([32]byte{}) || verifyLocalDocument(origin, scope, sync.Local, b) != nil {
		return ErrCatalog
	}
	return nil
}

func validateLogClearRecords(rows []AppLogClearRecord, scope deployment.AppScope) error {
	if len(rows) > 128 {
		return ErrCatalog
	}
	seen := map[string]bool{}
	for _, row := range rows {
		id := row.Source.Choice.Operation
		if seen[id] || row.Source.Recreate == nil || row.Source.Recreate.Closure == ([32]byte{}) || row.Source.verify(row.Origin, scope) != nil || row.Status != "recreating" && row.Status != "succeeded" {
			return ErrCatalog
		}
		seen[id] = true
		if row.Status == "succeeded" {
			for _, old := range row.Source.Recreate.Plan.Impact {
				if old.Kind != "task" {
					continue
				}
				found := false
				for _, replacement := range row.Replacements {
					if replacement.Key == old.Key && replacement.Kind == "task" && replacement.NativeID != "" && replacement.NativeID != old.NativeID && replacement.Generation > old.Generation {
						found = true
					}
				}
				if !found {
					return ErrCatalog
				}
			}
		}
	}
	return nil
}

func (p Policy) beginAppLogClear(s state.State, a Apps, c access.Catalog, op UserOperation) (map[string][]byte, state.Code) {
	var q AppLogClear
	if (op.Change.Action == "standalone-clear-logs") != (func() bool { var x AppLogClear; _ = canonical(op.Change.Payload, &x); return x.Standalone != "" }()) || !AppLogClearCASAllowed(op.Change) || canonical(op.Change.Payload, &q) != nil {
		return nil, state.Invalid
	}
	plan, err := p.PlanAppLogClear(s, op.Session, op.At, q.Tenant, q.selection())
	if err != nil || plan.Target != q.Target || op.Change.Expected > plan.InventoryRevision {
		return nil, state.ConditionFailed
	}
	entry := a.entries[appKey(q.Tenant, q.App)]
	if (entry.Standalone != nil) != (q.Standalone != "") || (entry.Standalone != nil && entry.Standalone.Name != q.Standalone) || len(entry.LogClears) >= 128 {
		return nil, state.ConditionFailed
	}
	if _, used := entry.Inventory.Operation(q.Operation); used {
		return nil, state.ConditionFailed
	}
	e, _ := entry.Inventory.Execution()
	b := e.Blueprint()
	raw, err := b.Encode()
	if err != nil {
		return nil, state.Invalid
	}
	origin, err := appExecutionOrigin(entry.Origin, entry.Sync, entry.Inventory.Scope())
	if err != nil {
		return nil, state.Invalid
	}
	retirementID := deployment.RecreationRetirementID(q.Operation)
	if entry.Delivery != nil {
		d, err := entry.Delivery.BeginRecreation(entry.Delivery.Revision(), c, op.Session.User, q.Operation, origin.Submitter, op.Epoch, []string{plan.Container.Instance})
		if err != nil {
			return nil, state.ConditionFailed
		}
		entry.Delivery, entry.Inventory = &d, d.Inventory()
		r, _ := entry.Inventory.Retirement()
		retirementID = r.ID
	} else {
		entry.Inventory, err = entry.Inventory.Retire(entry.Inventory.Revision(), c, op.Session.User, retirementID, origin.Submitter, op.Epoch, []string{plan.Container.Instance}, false)
		if err != nil {
			return nil, state.ConditionFailed
		}
	}
	// Record the user's ORIGINAL planning ordinal, not a fresh CAS created by
	// admission after unrelated health reports.
	plan.InventoryRevision = op.Change.Expected
	entry.PendingSync = &AppDeliverySync{Local: ownLocalGrant(acceptedLocalGrant(entry)), Choice: AppDeliveryChoice{Operation: q.Operation, Candidate: plan.SourceCandidate, Registration: appRegistrationDigest(entry.Origin)}, Plan: b.Digest(), Intent: b.IntentDigest(), Artifact: plan.SourceArtifact, Epoch: op.Epoch, User: &op, Recreate: &AppRecreation{Plan: plan, Blueprint: raw, OriginTarget: entry.downTarget(), Retirement: retirementID}}
	a.entries[appKey(q.Tenant, q.App)] = entry
	return p.appsCheckpoint(s, a)
}

func (p Policy) continueAppLogClear(s state.State, entry appEntry) (appEntry, error) {
	proof := entry.PendingSync
	if proof == nil || proof.Recreate == nil || proof.Recreate.Closure == ([32]byte{}) || proof.verify(entry.Origin, entry.Inventory.Scope()) != nil {
		return entry, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return entry, err
	}
	scope := entry.Inventory.Scope()
	b, err := deployment.DecodeBlueprint(proof.Recreate.Blueprint)
	if err != nil {
		return entry, err
	}
	if c.AuthorizeAccepted(proof.User.Session, p.Cluster, proof.User.At, scope.Tenant, access.Deploy, "") != nil || p.authorizeLocalBlueprint(s, c, entry, proof.Local, b) != nil {
		return entry, access.ErrDenied
	}
	for _, step := range b.Steps() {
		if c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, scope.Tenant, step.Action(), step.Node) != nil || c.AuthorizeAccepted(proof.User.Session, p.Cluster, proof.User.At, scope.Tenant, access.Deploy, step.Node) != nil {
			return entry, access.ErrDenied
		}
	}
	ctx, err := p.AppPlanning(s, entry.Origin.Session.User, scope.Tenant)
	if err != nil {
		return entry, err
	}
	ctx.Project, ctx.Deployment, ctx.Actor, ctx.DefaultNode = scope.App, scope.Deployment, entry.Origin.Session.User, b.CDDefaultNode()
	if entry.Delivery != nil {
		d, err := entry.Delivery.ContinueTransition(entry.Delivery.Revision(), c, ctx, proof.User.Session.User)
		if err != nil {
			return entry, err
		}
		entry.Delivery, entry.Inventory = &d, d.Inventory()
	} else {
		rebased, err := b.Rebase(c, ctx)
		if err != nil {
			return entry, err
		}
		original, err := appExecutionOrigin(entry.Origin, entry.Sync, scope)
		if err != nil {
			return entry, err
		}
		entry.Inventory, err = entry.Inventory.Begin(entry.Inventory.Revision(), c, ctx, rebased, proof.Choice.Operation, original.Submitter, proof.Epoch, false)
		if err != nil {
			return entry, err
		}
	}
	current, _ := entry.Inventory.Execution()
	accepted := *proof
	accepted.Plan = current.Blueprint().Digest()
	entry.Sync, entry.PendingSync = &accepted, nil
	entry.LogClears = append(append([]AppLogClearRecord(nil), entry.LogClears...), AppLogClearRecord{Origin: entry.Origin, Source: accepted, Status: "recreating"})
	return entry, nil
}

func validatePlainRecreation(entry appEntry) error {
	if entry.Sync == nil {
		return nil
	}
	proof := entry.Sync
	if proof.Recreate == nil || proof.Recreate.Closure == ([32]byte{}) || proof.verify(entry.Origin, entry.Inventory.Scope()) != nil {
		return ErrCatalog
	}
	if e, active := entry.Inventory.Execution(); active && (e.Blueprint().Digest() != proof.Plan || e.Blueprint().IntentDigest() != proof.Intent) {
		return ErrCatalog
	}
	if op, found := entry.Inventory.Operation(proof.Choice.Operation); !found || op.Plan != proof.Plan {
		return ErrCatalog
	}
	return nil
}

func validatePendingRecreation(entry appEntry) error {
	proof := entry.PendingSync
	if proof == nil || proof.Recreate == nil || entry.Down != nil || proof.verify(entry.Origin, entry.Inventory.Scope()) != nil {
		return ErrCatalog
	}
	r := proof.Recreate
	original, err := appExecutionOrigin(entry.Origin, entry.Sync, entry.Inventory.Scope())
	if err != nil {
		return err
	}
	if retirement, pending := entry.Inventory.Retirement(); pending {
		if r.Closure != ([32]byte{}) || retirement.Down || retirement.ID != r.Retirement || retirement.Submitter != original.Submitter || retirement.Epoch != proof.Epoch || retirement.Actor != proof.User.Session.User || len(retirement.Targets) != len(r.Plan.Impact) {
			return ErrCatalog
		}
		for _, target := range retirement.Targets {
			found := false
			for _, impact := range r.Plan.Impact {
				claim := target.Original
				if impact.Key == claim.Step.Key && impact.Kind == claim.Step.Kind && impact.Generation == claim.Result.Generation && impact.Revision == claim.Result.Revision {
					found = true
				}
			}
			if !found {
				return ErrCatalog
			}
		}
	} else {
		if _, active := entry.Inventory.Execution(); active || r.Closure == ([32]byte{}) {
			return ErrCatalog
		}
	}
	if entry.Delivery != nil {
		t, found := entry.Delivery.Transition()
		if !found || t.Mode != deployment.DeliveryRecreate || t.Selection.Operation != proof.Choice.Operation || t.Selection.Plan != proof.Plan || t.Selection.Artifact != proof.Artifact || t.Retirement != r.Retirement {
			return ErrCatalog
		}
	}
	return nil
}
