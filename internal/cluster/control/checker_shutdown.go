// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

type CheckerShutdownRequest struct {
	Schema   uint8
	Task     deployment.ObjectRef
	Binding  [32]byte
	Stop     checker.ShutdownScope
	At       int64
	Compiled *checker.CompiledFact `json:",omitempty"`
}

type CheckerShutdownPermit struct {
	Schema           uint8
	Task             deployment.ObjectRef
	Binding, Program [32]byte
	Stop             checker.ShutdownScope
	Index            uint64
}

// CheckerShutdownPermit grants only checks before the exact original Task's
// committed drain. It does not weaken AppBindingPermit's activation refusal,
// grant new source/build/fetch/Start, or make a checker a native closure proof.
func (p Policy) CheckerShutdownPermit(s state.State, caller [32]byte, q CheckerShutdownRequest) (CheckerShutdownPermit, error) {
	return p.checkerShutdownContext(s, caller, q, true)
}

// A delegated app probe may target a service without its own shutdown check.
// Only the probe grant's validated coordinator can delegate that target; the
// public shutdown method always requires a declared check on its own Task.
func (p Policy) checkerShutdownContext(s state.State, caller [32]byte, q CheckerShutdownRequest, requireCheck bool) (CheckerShutdownPermit, error) {
	deny := func() (CheckerShutdownPermit, error) { return CheckerShutdownPermit{}, access.ErrDenied }
	if q.Schema != 1 || q.At < 0 || q.Stop.Operation == "" || q.Stop.Revision == 0 {
		return deny()
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return deny()
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return CheckerShutdownPermit{}, err
	}
	b, ok := apps.Binding(q.Task)
	if !ok || b.Digest() != q.Binding || !p.ownsResource(s, caller, b.Needs().Use.NodeKey) {
		return deny()
	}
	n := b.Needs()
	entry, ok := apps.entries[appKey(n.Use.Tenant, n.Use.App)]
	if !ok {
		return deny()
	}
	retirement, ok := entry.Inventory.Retirement()
	if !ok || retirement.ID != q.Stop.Operation || retirement.Revision != q.Stop.Revision {
		return deny()
	}
	matched := false
	for _, t := range retirement.Targets {
		c := t.Original
		if c.Step.Key != q.Task.Key {
			continue
		}
		o := s.Object(c.Step.Key)
		if t.Closed || c.Step.Kind != "task" || c.Step.Owner != n.Use.NodeKey || c.Removed || c.Result.Code != state.Applied || c.Result.Generation != q.Task.Generation || c.Result.Revision != q.Task.Revision || !o.Present || o.Generation != q.Task.Generation || o.Revision != q.Task.Revision || o.Value != c.Command.Value || t.Drain == nil || t.Drain.Result != nil || t.Drain.Journal.Pending == nil || t.Drain.Journal.Pending.Phase != reconcile.Prepared {
			return deny()
		}
		matched = true
	}
	if !matched {
		return deny()
	}
	source, ok := apps.BindingSource(q.Binding)
	if !ok || source.Task != q.Task {
		return deny()
	}
	users, err := p.Catalog(s)
	execution, executing := entry.Inventory.Execution()
	if err != nil || !executing || users.AuthorizeAccepted(source.Origin.Session, p.Cluster, source.Origin.At, n.Use.Tenant, access.Deploy, n.Use.Node) != nil || p.authorizeBinding(s, entry, execution, q.Task.Key, n) != nil || p.authorizeAppRemoval(s, entry) != nil {
		return deny()
	}
	vault, err := p.Vault(s)
	if err != nil {
		return deny()
	}
	registry, err := p.Volumes(s)
	if err != nil || b.Check(apps.bindings, users, vault.Trees, vault.Approvals, volumeStates(registry), q.At) != nil {
		return deny()
	}
	var goal deployment.GoalCommand
	var service deployment.ComposeService
	if canonical([]byte(s.Object(q.Task.Key).Value), &goal) != nil {
		return deny()
	}
	if goal.Lifecycle != nil || goal.Kind != "task" || goal.Owner != n.Use.NodeKey || canonical(goal.Config, &service) != nil || service.LifecycleProgram == nil || service.CheckLifecycleNeeds(n) != nil {
		return deny()
	}
	book, err := p.Lifecycles(s)
	if err != nil || service.LifecycleProgram.ValidateCatalog(book) != nil {
		return deny()
	}
	declared := false
	for _, check := range service.LifecycleProgram.Checks {
		declared = declared || check.Phase == contract.Shutdown
	}
	for _, check := range service.LifecycleProgram.AppChecks {
		declared = declared || check.Phase == contract.Shutdown
	}
	if requireCheck && !declared {
		return deny()
	}
	current, ok := book.Policy(n.Use.Tenant, 0)
	if !ok || !current.Enabled {
		return deny()
	}
	for _, fact := range service.LifecycleProgram.Sources {
		if !current.AllowsSource(fact) {
			return deny()
		}
	}
	if q.Compiled != nil && ValidateCheckerCompiledMetadata(book, service.LifecycleProgram, current, q.Compiled.Build.Recipe.Source, *q.Compiled) != nil {
		return deny()
	}
	raw, _ := json.Marshal(service.LifecycleProgram)
	return CheckerShutdownPermit{Schema: 1, Task: q.Task, Binding: q.Binding, Program: sha256.Sum256(raw), Stop: q.Stop, Index: s.Index()}, nil
}
