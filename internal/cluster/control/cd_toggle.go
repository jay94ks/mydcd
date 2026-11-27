// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

type CDToggleQuery struct{ App, Action string }

func (q CDToggleQuery) Valid() bool {
	return lifecycle.ValidID(q.App) && (q.Action == "pause-app-cd" || q.Action == "resume-app-cd")
}

type CDTogglePlan struct {
	Schema                                uint8
	Tenant, App, Action, ActiveOperation  string
	Expected, RootRevision, Epoch         uint64
	Paused, WouldPause, PreservesOriginal bool
}

func toggleCDEntry(s state.State, entry appEntry, users access.Catalog, actor string, paused bool) (appEntry, error) {
	if entry.Delivery == nil {
		return entry, access.ErrConflict
	}
	d, err := entry.Delivery.Pause(entry.Delivery.Revision(), users, actor, paused, s)
	if err != nil {
		return entry, err
	}
	entry.Delivery, entry.Inventory = &d, d.Inventory()
	if !paused && entry.Down != nil {
		if _, busy := d.Transition(); busy || !entry.Inventory.Quiescent() {
			return entry, access.ErrConflict
		}
		entry.Down = nil
	}
	return entry, nil
}
func (p Policy) PlanCDToggle(s state.State, session access.Session, at int64, tenant string, q CDToggleQuery) (CDTogglePlan, error) {
	var out CDTogglePlan
	p, err := p.Current(s)
	if err != nil || tenant == "" || !q.Valid() {
		return out, access.ErrDenied
	}
	users, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	if users.OperationAllowed(session, q.Action) != nil {
		return out, access.ErrDenied
	}
	if q.Action == "pause-app-cd" {
		err = users.AuthorizeSessionCleanup(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageCD)
	} else {
		err = users.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageCD, "")
	}
	if err != nil {
		return out, err
	}
	apps, err := p.Apps(s)
	if err != nil {
		return out, err
	}
	entry, known := apps.entries[appKey(tenant, q.App)]
	if !known || entry.Delivery == nil {
		return out, access.ErrConflict
	}
	volumes, err := p.Volumes(s)
	if err != nil || volumes.appMovePending(tenant, q.App) {
		return out, access.ErrConflict
	}
	if _, err = p.AppPlanning(s, session.User, tenant); err != nil {
		return out, err
	}
	if _, err = toggleCDEntry(s, entry, users, session.User, q.Action == "pause-app-cd"); err != nil {
		return out, access.ErrConflict
	}
	out = CDTogglePlan{Schema: 1, Tenant: tenant, App: q.App, Action: q.Action, Expected: entry.Delivery.Revision(), RootRevision: s.Object(AppsKey).Revision, Epoch: s.ModuleEpoch(), Paused: entry.Delivery.Paused(), WouldPause: q.Action == "pause-app-cd", PreservesOriginal: true}
	if execution, ok := entry.Inventory.Execution(); ok {
		out.ActiveOperation = execution.ActiveOperation()
	}
	return out, nil
}
