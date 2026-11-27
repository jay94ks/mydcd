// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func sameRouteRetirementReceipt(ref services.ReferenceConsumer, report control.RouteRetirementReport) bool {
	if ref.Closed == nil || ref.RouteClosed == nil {
		return false
	}
	actual, _ := json.Marshal([]any{ref.Closed, ref.RouteClosed})
	original, _ := json.Marshal([]any{report.Close, report.Route})
	return bytes.Equal(actual, original)
}

func (r *Runtime) resolveRouteRetirement(ref services.ReferenceConsumer, record *routeOwnerRecord) error {
	if ref.Closed == nil || ref.RouteClosed == nil || services.ValidateRouteRetirement(ref, *ref.Closed, *ref.RouteClosed) != nil || !record.BridgeReturned {
		return errors.New("shared route closure lacks original paired receipt or local dependency closure")
	}
	if record.Retirement == nil {
		return nil
	}
	if !sameRouteRetirementReceipt(ref, *record.Retirement) {
		return errors.New("shared route closure differs from original pending retirement")
	}
	candidate := *record
	candidate.Retirement, candidate.RetirementRejected = nil, false
	if err := r.saveRouteOwner(candidate, ref); err != nil {
		return err
	}
	*record = candidate
	return nil
}

// Produces evidence only from the already synced product core and dependency
// closure. The timestamp is the original permanent fact, not a permit expiry.
func (r *Runtime) newRouteRetirement(projection control.ResourceProjection, work control.RouteWork, record routeOwnerRecord, at int64) (*control.RouteRetirementReport, error) {
	if !record.BridgeReturned {
		return nil, nil
	}
	if r.Identity == nil || r.Identity.Public != work.Reference.Local.Owner || work.Reference.Route == nil {
		return nil, errors.New("route retirement has no original local owner")
	}
	if record.Report != nil && !record.NeverDispatched || projection.NetworkAuthority == nil || record.NeverDispatched != (work.Reference.Dispatch == nil) || !record.NeverDispatched && !sameRouteDispatch(*work.Reference.Dispatch, record.Dispatch) {
		return nil, errors.New("route retirement lacks original settled dispatch")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return nil, err
	}
	journal := core.Journal()
	if journal.Desired.Present || journal.Applied.Present || journal.Pending != nil || core.FlowCount() != 0 {
		return nil, errors.New("route retirement still has native or flow work")
	}
	policy, exists := projection.Resources.Networks.Route(work.Reference.Route.Policy.Source.Tenant, work.Reference.Route.Policy.ID)
	if !exists || policy.Phase != tenancy.Revoking {
		return nil, nil // Current-grant loss alone is not a committed withdrawal.
	}
	closed, err := core.ReferenceFacts(*projection.NetworkAuthority, [32]byte{}, services.Clock{Boot: core.Boot(), Wall: at, Certain: true})
	if err != nil {
		return nil, err
	}
	route, err := core.RouteClosureFacts(projection.Resources.Networks)
	if err != nil {
		return nil, err
	}
	if record.NativeStarted {
		proof, exists := core.NativeObservation()
		if !exists || !proof.Gone || proof.Kind != reconcile.Remove || proof.Outcome != reconcile.EffectApplied {
			return nil, errors.New("route retirement has no positive original native Gone")
		}
	}
	closed.Settled = true
	closed.Signature = ed25519.Sign(r.Identity.Private, services.ReferenceCloseBytes(closed))
	route.NativeGone = true
	route.Signature = ed25519.Sign(r.Identity.Private, tenancy.RouteClosureBytes(route))
	if services.ValidateRouteRetirement(work.Reference, closed, route) != nil {
		return nil, errors.New("original route retirement facts do not match their consumer")
	}
	report := control.RouteRetirementReport{Schema: 1, Kind: "route-retirement", Cluster: work.Reference.Local.Cluster, Reporter: r.commandIdentity().Public, Epoch: work.Epoch, RootRevision: work.AppsRevision, ResourcesRevision: work.ResourcesRevision, Dispatch: record.Dispatch, Close: closed, Route: route, NeverDispatched: record.NeverDispatched}
	if record.NeverDispatched {
		report.Dispatch = services.RouteDispatch{}
	}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.RouteRetirementReportBytes(report))
	return &report, nil
}

func (r *Runtime) publishRouteRetirement(ctx context.Context, projection control.ResourceProjection, work control.RouteWork, record routeOwnerRecord) (bool, error) {
	if record.Retirement == nil {
		report, err := r.newRouteRetirement(projection, work, record, time.Now().Unix())
		if err != nil || report == nil {
			return false, err
		}
		record.Retirement = report
		if err := r.saveRouteOwner(record, work.Reference); err != nil {
			return false, err
		}
	} else if record.RetirementRejected {
		if err := r.rebaseRouteRetirementReport(work, &record); err != nil {
			return false, err
		}
	}
	raw, _ := json.Marshal(record.Retirement)
	reply, err := r.appCall(ctx, "route-retirement", raw)
	if err != nil {
		return true, err
	} // Keep the exact original unknown submission.
	if reply.Committed == nil {
		return true, errors.New("route retirement reply has no original committed result")
	}
	return r.recordRouteRetirementResult(work.Reference, record, reply.Committed.Result.Code)
}

// A coordination rejection never changes the permanent signed closure facts.
// Persist that decision before a later current-work pass can rebase its wrapper.
func (r *Runtime) recordRouteRetirementResult(ref services.ReferenceConsumer, record routeOwnerRecord, code state.Code) (bool, error) {
	switch code {
	case state.Applied:
		return true, nil
	case state.ConditionFailed, state.Expired:
		// Expired fences the old envelope, not the completed native fact.
		// A later current-work pass may re-sign only coordination fields;
		// shared paired-closure resolution still precedes this publication.
		record.RetirementRejected = true
		return true, r.saveRouteOwner(record, ref)
	default:
		return true, fmt.Errorf("original route retirement submission rejected (code=%d)", code)
	}
}

func (r *Runtime) rebaseRouteRetirementReport(work control.RouteWork, record *routeOwnerRecord) error {
	if record.Retirement == nil || !record.RetirementRejected {
		return errors.New("route retirement has no closed original report envelope")
	}
	raw, err := json.Marshal(*record)
	if err != nil {
		return err
	}
	if _, err := decodeRouteOwner(raw, work.Reference); err != nil {
		return err
	}
	report := *record.Retirement
	if report.Reporter == r.commandIdentity().Public && report.Epoch == work.Epoch && report.RootRevision == work.AppsRevision && report.ResourcesRevision == work.ResourcesRevision {
		return errors.New("original route retirement rejected under unchanged roots")
	}
	report.Reporter = r.commandIdentity().Public
	report.Epoch, report.RootRevision, report.ResourcesRevision = work.Epoch, work.AppsRevision, work.ResourcesRevision
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.RouteRetirementReportBytes(report))
	candidate := *record
	candidate.Retirement, candidate.RetirementRejected = &report, false
	if err := r.saveRouteOwner(candidate, work.Reference); err != nil {
		return err
	}
	*record = candidate
	return nil
}
