// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

// AppHistorySelection selects one inventory by its existing revision. The
// command's root CAS and committed A1 epoch remain authoritative as well.
type AppHistorySelection struct{ Tenant, App string }

func validCompactedApp(i deployment.Inventory, origin UserOperation, down *UserOperation, summary deployment.OperationSummary) bool {
	return validCompactedAppSource(i, origin, down, nil, summary)
}

func validCompactedAppSource(i deployment.Inventory, origin UserOperation, down *UserOperation, sync *AppDeliverySync, summary deployment.OperationSummary) bool {
	for _, claim := range i.Claims() {
		if !claim.Removed {
			return false
		}
	}
	identity, err := appExecutionOrigin(origin, sync, i.Scope())
	_, active := i.Execution()
	return err == nil && down != nil && !active && i.Quiescent() && summary.ID == identity.Operation && summary.Submitter == identity.Submitter && summary.Epoch == identity.Epoch && summary.Plan != ([32]byte{}) && (sync == nil || summary.Plan == sync.Plan) && summary.Status == "Retired" && i.OperationExpired(identity.Submitter, identity.Epoch)
}

func (a Apps) rotateHistory(expected uint64, c access.Catalog, actor string, shared state.State, q AppHistorySelection) (Apps, error) {
	entry, ok := a.entries[appKey(q.Tenant, q.App)]
	if !ok || pendingTaskRestarts(entry) || entry.Inventory.Revision() != expected || c.AuthorizeCleanup(actor, q.Tenant, access.Deploy) != nil || entry.Down == nil || !entry.Inventory.Quiescent() {
		return a, ErrCatalog
	}
	if _, active := entry.Inventory.Execution(); active {
		return a, ErrCatalog
	}
	// An expired receipt does not close an owned effect. Even retained resources
	// stay ineligible; the collector never removes claims, recipes or proofs.
	for _, claim := range entry.Inventory.Claims() {
		if !claim.Removed {
			return a, ErrCatalog
		}
	}
	for _, binding := range a.bindings.Live() {
		use := binding.Needs().Use
		if use.Tenant == q.Tenant && use.App == q.App {
			return a, ErrCatalog
		}
	}
	identity, err := appExecutionOrigin(entry.Origin, entry.Sync, entry.Inventory.Scope())
	if err != nil {
		return a, ErrCatalog
	}
	summary, found := entry.Inventory.Operation(identity.Operation)
	if !found || entry.Compacted != nil || summary.Status != "Retired" {
		return a, ErrCatalog
	}
	var next deployment.Inventory
	if entry.Delivery != nil {
		// Rotate the same Delivery authority so compacted success/failure and
		// retired/abandoned transition IDs retain their committed epoch fence.
		d, rotateErr := entry.Delivery.RotateWindow(entry.Delivery.Revision(), c, actor, shared)
		err = rotateErr
		if err == nil {
			entry.Delivery, next = &d, d.Inventory()
		}
	} else {
		next, err = entry.Inventory.RotateWindow(expected, c, actor, shared)
	}
	if err != nil || next.Revision() == expected || !validCompactedAppSource(next, entry.Origin, entry.Down, entry.Sync, summary) {
		return a, ErrCatalog
	}
	// Keep the current signed execution anchor's result. A CD registration and
	// its current selection remain distinct; neither signature is rewritten.
	entry.Inventory, entry.Compacted = next, &summary
	// The existing all-closed/expired-window gate also protects source bytes.
	// Never reset LastVersion: a later acceptance cannot reuse a reclaimed ID.
	entry.Versions = nil
	entries := make(map[string]appEntry, len(a.entries))
	for key, old := range a.entries {
		entries[key] = old
	}
	entries[appKey(q.Tenant, q.App)] = entry
	a.entries = entries
	return a, nil
}
