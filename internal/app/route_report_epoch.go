// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// work MUST come from readRouteWork's bound latest-quorum snapshot. Receipt
// absence alone is insufficient. A closed epoch fences only its old envelope;
// an authenticated current-key call may restate the SAME original fact while
// the old delivery remains unknown in immutable local provenance. This never
// renews a native dispatch, user operation, nonce or pin.
func (r *Runtime) renewRouteReportEpoch(work control.RouteWork, record *routeOwnerRecord) error {
	ref := work.Reference
	if record == nil || r.Identity == nil || ref.Local.Owner != r.Identity.Public || work.Epoch == 0 {
		return errors.New("route report epoch has no original owner or committed fence")
	}
	if (ref.Closed == nil) != (ref.RouteClosed == nil) {
		return errors.New("route epoch has only half of its permanent closure pair")
	}
	raw, err := json.Marshal(*record)
	if err != nil {
		return err
	}
	if _, err := decodeRouteOwner(raw, ref); err != nil {
		return err
	}
	if ref.Closed != nil {
		return nil // The original shared pair must resolve through receipt comparison.
	}
	candidate, changed := *record, false
	if report := record.Report; report != nil && !record.NeverDispatched && ref.Dispatch == nil {
		if report.Epoch > work.Epoch {
			return errors.New("route dispatch report is newer than quorum work")
		}
		if report.Epoch < work.Epoch || report.Reporter != r.commandIdentity().Public {
			core, err := services.DecodeRouteRuntime(record.Core)
			pending := core.Journal().Pending
			if err != nil || record.NativeStarted || record.Bridge != (reconcile.Lease{}) || pending == nil || pending.ID != 1 || pending.Kind != reconcile.Apply || pending.Phase != reconcile.Prepared || !sameRouteDispatch(report.Dispatch, record.Dispatch) {
				return errors.New("closed epoch cannot replace an unproven native dispatch")
			}
			next := *report
			next.Reporter = r.commandIdentity().Public
			next.Epoch, next.RootRevision = work.Epoch, work.AppsRevision
			next.Signature = ed25519.Sign(r.commandIdentity().Private, control.RouteDispatchReportBytes(next))
			candidate.Report, changed = &next, true
		}
	}
	if report := record.Retirement; report != nil {
		if report.Epoch > work.Epoch {
			return errors.New("route retirement report is newer than quorum work")
		}
		if report.Epoch < work.Epoch || report.Reporter != r.commandIdentity().Public {
			if !work.Retiring || !record.BridgeReturned || !record.NeverDispatched && (ref.Dispatch == nil || !sameRouteDispatch(*ref.Dispatch, report.Dispatch)) {
				return errors.New("closed epoch lacks original unclosed retirement fact")
			}
			next := *report
			next.Reporter = r.commandIdentity().Public
			next.Epoch, next.RootRevision, next.ResourcesRevision = work.Epoch, work.AppsRevision, work.ResourcesRevision
			next.Signature = ed25519.Sign(r.commandIdentity().Private, control.RouteRetirementReportBytes(next))
			candidate.Retirement, candidate.RetirementRejected, changed = &next, false, true
		}
	}
	if !changed {
		return nil
	}
	if err := r.saveRouteOwner(candidate, ref); err != nil {
		return err
	}
	*record = candidate
	return nil
}
