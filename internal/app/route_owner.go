// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

// The preparation record shares observations.db with other native owners.
// Core is the product RouteRuntime checkpoint, not a second route algorithm.
// No native operation is executed by this preparation path.
type routeOwnerRecord struct {
	Schema   uint8
	Nonce    [32]byte
	Core     json.RawMessage
	Dispatch services.RouteDispatch
	Report   *control.RouteDispatchReport `json:",omitempty"`
	Bridge   reconcile.Lease              `json:",omitzero"`
	// Once true, this original Apply can only be recovered, never re-executed.
	NativeStarted      bool                           `json:",omitempty"`
	NativeBoot         [32]byte                       `json:",omitzero"`
	BridgeReturned     bool                           `json:",omitempty"`
	Retirement         *control.RouteRetirementReport `json:",omitempty"`
	RetirementRejected bool                           `json:",omitempty"`
	NeverDispatched    bool                           `json:",omitempty"`
}

func routeOwnerKey(id [32]byte) string { return "route-owner/" + hex.EncodeToString(id[:]) }

func sameRouteDispatch(a, b services.RouteDispatch) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func (r *Runtime) loadRouteOwner(ref services.ReferenceConsumer) (routeOwnerRecord, bool, error) {
	if r.reports == nil || r.routeStoreFailed {
		return routeOwnerRecord{}, false, errors.New("original route owner store requires reopening")
	}
	raw, err := r.reports.GetBounded(routeOwnerKey(ref.ID), 33<<20)
	if errors.Is(err, storage.ErrMissing) && ref.Dispatch == nil {
		return routeOwnerRecord{}, false, nil
	}
	if err != nil {
		return routeOwnerRecord{}, false, err
	}
	record, err := decodeRouteOwner(raw, ref)
	return record, err == nil, err
}

func decodeRouteOwner(raw []byte, ref services.ReferenceConsumer) (routeOwnerRecord, error) {
	var record routeOwnerRecord
	if len(raw) == 0 || len(raw) > 33<<20 {
		return record, errors.New("missing or oversized original route owner record")
	}
	record, err := schema.Decode[routeOwnerRecord](raw)
	if err != nil || record.Schema != 1 {
		return record, errors.New("invalid original route owner identity")
	}
	if record.NeverDispatched {
		zero, _ := json.Marshal(services.RouteDispatch{})
		received, _ := json.Marshal(record.Dispatch)
		if !bytes.Equal(zero, received) && (record.Nonce == ([32]byte{}) || services.ValidateRouteDispatch(ref, record.Dispatch) != nil || record.Dispatch.Journal != services.RouteJournalDigest(ref, record.Nonce)) {
			return record, errors.New("never-dispatched route lost its original private proposal")
		}
		if bytes.Equal(zero, received) && (record.Nonce != ([32]byte{}) || record.Report != nil) || ref.Dispatch != nil || record.NativeStarted || record.Bridge != (reconcile.Lease{}) || !record.BridgeReturned {
			return record, errors.New("never-dispatched route acquired a grant, effect or dependency")
		}
	} else if record.Nonce == ([32]byte{}) || services.ValidateRouteDispatch(ref, record.Dispatch) != nil || record.Dispatch.Journal != services.RouteJournalDigest(ref, record.Nonce) {
		return record, errors.New("invalid original route owner identity")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return record, err
	}
	consumer := core.Consumer()
	if consumer.ID != ref.ID || consumer.Generation != ref.Generation || consumer.Lifetime != ref.Lifetime || consumer.DesiredHash != ref.DesiredHash || consumer.Local != ref.Local || consumer.Native == nil || ref.Native == nil || *consumer.Native != *ref.Native {
		return record, errors.New("route owner checkpoint changed its original consumer or Bridge")
	}
	journal := core.Journal()
	if !record.NativeStarted && record.NativeBoot != ([32]byte{}) {
		return record, errors.New("route execution boot exists before original native dispatch")
	}
	if journal.LastID < 1 || record.Bridge != (reconcile.Lease{}) && (record.Bridge.Generation != ref.Native.Generation || record.Bridge.Token == 0) || record.NativeStarted && record.Bridge == (reconcile.Lease{}) {
		return record, errors.New("route native record lost its original operation or Bridge pin")
	}
	if record.NativeStarted && journal.Pending != nil && journal.Pending.Kind == reconcile.Apply && (journal.Pending.ID != 1 || journal.Pending.Phase == reconcile.Prepared) {
		return record, errors.New("route original native dispatch was reset or replaced")
	}
	if record.NativeStarted && journal.Pending == nil && !journal.Applied.Present {
		proof, found := core.NativeObservation()
		if !found || proof.Kind != reconcile.Remove || proof.Outcome != reconcile.EffectApplied || !proof.Gone {
			return record, errors.New("route native dispatch has no original positive closure")
		}
	}
	if !record.NativeStarted && (journal.LastID != 1 || journal.Applied.Present || journal.Pending != nil && (journal.Pending.Kind != reconcile.Apply || journal.Pending.ID != 1)) || record.BridgeReturned && (journal.Desired.Present || journal.Applied.Present || journal.Pending != nil || core.FlowCount() != 0) {
		return record, errors.New("route native state contradicts its durable dispatch or Bridge return")
	}
	if ref.Dispatch != nil && !sameRouteDispatch(*ref.Dispatch, record.Dispatch) {
		return record, errors.New("shared route dispatch differs from original owner record")
	}
	if report := record.Report; report != nil {
		if report.Schema != 1 || report.Kind != "route-dispatch" || report.Cluster != ref.Local.Cluster || !sameRouteDispatch(report.Dispatch, record.Dispatch) || !ed25519.Verify(ed25519.PublicKey(report.Reporter[:]), control.RouteDispatchReportBytes(*report), report.Signature) {
			return record, errors.New("invalid original route dispatch submission")
		}
		if _, err := report.Command(); err != nil {
			return record, err
		}
	}
	if report := record.Retirement; report != nil {
		if !record.BridgeReturned || record.Report != nil && !record.NeverDispatched || report.NeverDispatched != record.NeverDispatched || report.Schema != 1 || report.Kind != "route-retirement" || report.Cluster != ref.Local.Cluster || !record.NeverDispatched && !sameRouteDispatch(report.Dispatch, record.Dispatch) || report.NeverDispatched && !sameRouteDispatch(report.Dispatch, services.RouteDispatch{}) || report.Close.Boot != core.Boot() || services.ValidateRouteRetirement(ref, report.Close, report.Route) != nil || !ed25519.Verify(ed25519.PublicKey(report.Reporter[:]), control.RouteRetirementReportBytes(*report), report.Signature) {
			return record, errors.New("invalid original route retirement submission")
		}
		if _, err := report.Command(); err != nil {
			return record, err
		}
	}
	if record.RetirementRejected && record.Retirement == nil {
		return record, errors.New("route retirement rejection lost its original submission")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, raw) {
		return record, errors.New("noncanonical original route owner record")
	}
	return record, nil
}

func (r *Runtime) saveRouteOwner(record routeOwnerRecord, ref services.ReferenceConsumer) error {
	if r.reports == nil || r.routeStoreFailed {
		return errors.New("original route owner store requires reopening")
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err = decodeRouteOwner(raw, ref); err != nil {
		return err
	}
	previous, err := r.reports.GetBounded(routeOwnerKey(ref.ID), 33<<20)
	writes := map[string][]byte{routeOwnerKey(ref.ID): raw}
	if err == nil {
		original, err := decodeRouteOwner(previous, ref)
		if err != nil {
			return err
		}
		if original.NativeStarted {
			if !record.NativeStarted || record.NativeBoot != original.NativeBoot {
				return errors.New("original route native dispatch and execution boot cannot be replaced")
			}
		} else if record.NativeStarted {
			core, err := services.DecodeRouteRuntime(record.Core)
			if err != nil {
				return err
			}
			if record.NativeBoot == ([32]byte{}) || record.NativeBoot != core.Boot() || record.Nonce != original.Nonce || !sameRouteDispatch(record.Dispatch, original.Dispatch) {
				return errors.New("route first native dispatch lost its original preparation or execution boot")
			}
		}
		traces, err := r.routeReportTraceWrites(ref, original, record)
		if err != nil {
			return err
		}
		for key, value := range traces {
			writes[key] = value
		}
	} else if !errors.Is(err, storage.ErrMissing) {
		r.failRouteStore()
		return err
	} else if record.NativeStarted {
		return errors.New("route native dispatch requires its original stored preparation")
	}
	if err = r.reports.Write(writes); err != nil {
		// Do not replace an uncertain write with a different nonce/report.
		r.failRouteStore()
	}
	return err
}

func (r *Runtime) failRouteStore() {
	r.routeStoreFailed = true
	for _, gate := range r.routeGates {
		gate.view.Store(nil)
	}
}

func (r *Runtime) prepareRouteOwners(ctx context.Context, _ cluster.View, projection control.ResourceProjection) error {
	if projection.NetworkAuthority == nil {
		return nil
	}
	for _, ref := range projection.NetworkAuthority.RouteReferences() {
		if ref.Local.Owner != r.Identity.Public || ref.Native == nil {
			continue
		}
		if closed, err := r.settleCommittedRouteClosure(ref); closed || err != nil {
			if err != nil {
				return err
			}
			continue
		}
		stop, err := r.prepareRouteOwner(ctx, ref)
		if stop || err != nil {
			return err
		}
	}
	return nil
}

// These paired receipts are permanent committed facts, not a cached permission
// for new native work. Repeated quorum reads cannot make the same closed
// lifetime live again. Keep all incomplete/missing-grant journals on recovery.
func (r *Runtime) settleCommittedRouteClosure(ref services.ReferenceConsumer) (bool, error) {
	if ref.Closed == nil || ref.RouteClosed == nil {
		return false, nil
	}
	if r.Identity == nil || ref.Local.Owner != r.Identity.Public || services.ValidateRouteRetirement(ref, *ref.Closed, *ref.RouteClosed) != nil {
		return false, errors.New("closed route lost its original owned paired receipt")
	}
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	record, known, err := r.loadRouteOwner(ref)
	if err != nil {
		return false, err
	}
	if !known {
		return true, nil // load permits absence only when no dispatch grant exists.
	}
	if !record.BridgeReturned {
		return false, nil
	}
	if err := r.resolveRouteRetirement(ref, &record); err != nil {
		return false, err
	}
	return true, nil
}

// Each original owner transition remains serialized. Releasing routeMu between
// owners prevents unrelated native/SDK work from monopolizing packet admission.
// stop preserves the scan's original early return after a report submission.
func (r *Runtime) prepareRouteOwner(ctx context.Context, ref services.ReferenceConsumer) (stop bool, err error) {
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	permitUntil := time.Now().Add(routeFlowPermitDuration)
	if r.reports == nil || r.routeStoreFailed {
		return true, errors.New("original route owner store requires reopening")
	}
	view, projection, work, err := r.readRouteWork(ctx, control.RouteWorkRequest{Reference: ref.ID, At: time.Now().Unix()})
	if err != nil {
		return true, err
	}
	record, known, err := r.loadRouteOwner(work.Reference)
	if err != nil {
		return true, err
	}
	if !known && work.Reference.Dispatch == nil && work.Reference.Closed != nil {
		if work.Reference.RouteClosed == nil || services.ValidateRouteRetirement(work.Reference, *work.Reference.Closed, *work.Reference.RouteClosed) != nil {
			return true, errors.New("closed never-dispatched route lost its paired receipt")
		}
		return false, nil // No native grant ever existed; no local recovery to invent.
	}
	if work.Reference.Dispatch == nil && work.Retiring && (!known || !record.NeverDispatched) {
		record, err = r.prepareNeverDispatchedRoute(view, projection, work, record, known)
		if err != nil {
			return true, err
		}
		known = true
	}
	if known {
		if err := r.renewRouteReportEpoch(work, &record); err != nil {
			return true, err
		}
	}
	if known && record.NeverDispatched {
		if work.Reference.Closed != nil {
			if err := r.resolveRouteRetirement(work.Reference, &record); err != nil {
				return true, err
			}
		} else if sent, err := r.publishRouteRetirement(ctx, projection, work, record); sent || err != nil {
			return true, err
		}
		return false, nil
	}
	if !known {
		if !work.PrepareAllowed {
			return false, nil
		}
		catalog, err := r.controlPolicy.Catalog(view.State)
		if err != nil {
			return true, err
		}
		boot, err := services.NativeBootID()
		if err != nil {
			return true, err
		}
		core, err := services.NewRouteRuntime(catalog, projection.Resources.Networks, *projection.NetworkAuthority, ref.ID, boot, work.MaxConsumers)
		if err != nil {
			return true, err
		}
		core, operation, err := core.Plan()
		if err != nil || operation == nil || operation.ID != 1 || operation.Kind != reconcile.Apply || operation.Phase != reconcile.Prepared {
			return true, errors.New("route preparation lost its original first Apply")
		}
		record.Schema = 1
		if _, err := rand.Read(record.Nonce[:]); err != nil {
			return true, err
		}
		record.Core, err = core.Encode()
		if err != nil {
			return true, err
		}
		native, err := services.RouteTunnelDefinition(core.Consumer())
		if err != nil {
			return true, err
		}
		nativeRaw, _ := json.Marshal(native)
		record.Dispatch = services.RouteDispatch{Cluster: r.controlPolicy.Cluster, Reference: services.ReferenceNeed{Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: r.Identity.Public}, Boot: boot, Journal: services.RouteJournalDigest(ref, record.Nonce), Spec: ref.DesiredHash, NativeSpec: sha256.Sum256(nativeRaw), Operation: operation.ID}
		record.Dispatch.Signature = ed25519.Sign(r.Identity.Private, services.RouteDispatchBytes(record.Dispatch))
	}
	if work.Reference.Dispatch != nil {
		if work.Reference.Closed != nil {
			if err := r.resolveRouteRetirement(work.Reference, &record); err != nil {
				return true, err
			}
			return false, nil
		}
		if record.Report != nil {
			record.Report = nil
			if err := r.saveRouteOwner(record, work.Reference); err != nil {
				return true, err
			}
		}
		if record.Retirement != nil {
			// Permanent signed facts retain their original boot/time across
			// restart. Do not advance or rebind the core while their exact
			// submission is unresolved; latest paired receipt settles it.
			if sent, err := r.publishRouteRetirement(ctx, projection, work, record); sent || err != nil {
				return true, err
			}
			return false, nil
		}
		if err := r.advanceRouteOwner(ctx, view, projection, work, record); err != nil {
			return true, err
		}
		record, _, err = r.loadRouteOwner(work.Reference)
		if err != nil {
			return true, err
		}
		core, err := services.DecodeRouteRuntime(record.Core)
		if err != nil {
			return true, err
		}
		core, err = r.observeActiveRouteFlows(ctx, work, &record, core)
		if err != nil {
			return true, err
		}
		r.publishRouteGate(view, projection, work, core, permitUntil)
		if sent, err := r.publishRouteRetirement(ctx, projection, work, record); sent || err != nil {
			return true, err
		}
		return false, nil // Native read-back still does not grant a packet flow.
	}
	if record.Report == nil {
		if !work.PrepareAllowed {
			return false, nil
		}
		report := control.RouteDispatchReport{Schema: 1, Kind: "route-dispatch", Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Epoch: work.Epoch, RootRevision: work.AppsRevision, Dispatch: record.Dispatch}
		report.Signature = ed25519.Sign(r.commandIdentity().Private, control.RouteDispatchReportBytes(report))
		record.Report = &report
		// Core, private nonce and exact signed report become durable together,
		// before the first submission or a later positively rejected CAS retry.
		if err := r.saveRouteOwner(record, work.Reference); err != nil {
			return true, err
		}
	}
	reportRaw, _ := json.Marshal(record.Report)
	result, err := r.appCall(ctx, "route-dispatch", reportRaw)
	if err != nil {
		return true, err // Preserve the exact unknown submission for latest resolution.
	}
	if result.Committed == nil {
		return true, errors.New("route dispatch reply has no original committed result")
	}
	if err := r.recordRouteDispatchResult(work.Reference, record, result.Committed.Result.Code); err != nil {
		return true, err
	}
	// Re-read latest before any next step; in particular CAS failure must
	// not turn preparation into permission or change the original nonce.
	return true, nil
}

// Only a positively returned result can close the original signed envelope.
// Unknown transport outcomes remain in prepareRouteOwner's earlier return.
func (r *Runtime) recordRouteDispatchResult(ref services.ReferenceConsumer, record routeOwnerRecord, code state.Code) error {
	if code != state.Applied && code != state.ConditionFailed && code != state.Expired {
		return fmt.Errorf("original route dispatch submission was rejected (code=%d)", code)
	}
	// Expired fences only this report envelope. The next latest-work pass
	// resolves any permanent shared grant first and otherwise reuses the same
	// original dispatch/nonce in a newly signed coordination envelope.
	record.Report = nil
	return r.saveRouteOwner(record, ref)
}
