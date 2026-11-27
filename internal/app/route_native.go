// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
)

func (r *Runtime) saveRouteCore(record *routeOwnerRecord, ref services.ReferenceConsumer, core services.RouteRuntime) error {
	if r.reports == nil || r.routeStoreFailed {
		return errors.New("original route owner store requires reopening")
	}
	raw, err := core.Encode()
	if err != nil {
		return err
	}
	if bytes.Equal(raw, record.Core) {
		return nil
	}
	candidate := *record
	candidate.Core = raw
	if err := r.saveRouteOwner(candidate, ref); err != nil {
		return err
	}
	*record = candidate
	return nil
}

func (r *Runtime) currentRouteNativePermit(ctx context.Context, ref services.ReferenceConsumer, record routeOwnerRecord) error {
	input, _ := json.Marshal(control.RouteNativeRequest{Reference: ref.ID, Nonce: record.Nonce, Operation: 1, At: time.Now().Unix()})
	reply, err := r.appCall(ctx, "route-native-permit", input)
	if err != nil {
		return err
	}
	permit, err := schema.Decode[control.RouteNativePermit](reply.Data)
	if err != nil || permit.Schema != 1 || permit.Reference != record.Dispatch.Reference || permit.Operation != record.Dispatch.Operation || permit.Journal != record.Dispatch.Journal || permit.NativeSpec != record.Dispatch.NativeSpec {
		return errors.New("native route permission changed the original journal or target")
	}
	return nil
}

// The caller holds routeMu. The shared dispatch marker has already been read
// through latest quorum; no native operation is inferred from that marker.
func (r *Runtime) advanceRouteOwner(ctx context.Context, view cluster.View, projection control.ResourceProjection, work control.RouteWork, record routeOwnerRecord) error {
	ref := work.Reference
	if ref.Dispatch == nil || !sameRouteDispatch(*ref.Dispatch, record.Dispatch) || record.Report != nil || r.network == nil || r.tunnel == nil {
		return errors.New("route native work requires original dispatch and enabled network/tunnel modules")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return err
	}
	catalog, err := r.controlPolicy.Catalog(view.State)
	if err != nil {
		return err
	}
	core, err = core.Sync(catalog, projection.Resources.Networks, *projection.NetworkAuthority)
	if err != nil {
		return err
	}
	boot, err := services.NativeBootID()
	if err != nil {
		return err
	}
	if core.Boot() != boot {
		core, err = core.ResumeBoot(boot)
		if err != nil {
			return err
		}
	}
	journal := core.Journal()
	if journal.Stopped && !(journal.Applied.Present && journal.Desired.Present && journal.Pending == nil) {
		core, err = core.ResumeBoot(boot)
		if err != nil {
			return err
		}
	}
	if work.MaxConsumers > 0 {
		core, err = core.Resize(work.MaxConsumers)
		if err != nil {
			return err
		}
	}
	if err := r.saveRouteCore(&record, ref, core); err != nil {
		return err
	}
	if record.BridgeReturned {
		return nil
	}
	if record.NativeStarted && (core.Journal().Pending != nil || core.Journal().Applied.Present) {
		if record.NativeBoot != ([32]byte{}) && record.NativeBoot != boot && !core.Journal().Desired.Present {
			core, err = r.retirePreviousBootRoute(ctx, ref, &record, core, boot, r.nativeRouteDriver())
			if err != nil {
				return err
			}
			return r.returnRouteBridge(ref, &record, core)
		}
		if err := record.requireNativeBoot(core.Boot()); err != nil {
			return errors.Join(err, r.saveRouteCore(&record, ref, core.Pause()))
		}
	}
	if record.NativeStarted && !core.Journal().Desired.Present {
		core, err = r.closeRoutePackets(ctx, ref, &record, core)
		if err != nil {
			return err
		}
	}
	journal = core.Journal()
	operation := journal.Pending
	if operation == nil && journal.Desired.Present && !journal.Applied.Present && record.NativeStarted {
		return errors.New("original route Apply did not succeed; explicit retirement is required")
	}
	if operation == nil && !(journal.Applied.Present && journal.Desired.Present) {
		core, operation, err = core.Plan()
		if err != nil {
			return err
		}
	}
	if err := r.saveRouteCore(&record, ref, core); err != nil {
		return err
	}
	if operation == nil {
		if !core.Journal().Applied.Present {
			return r.returnRouteBridge(ref, &record, core)
		}
		// A persistent TUN is read back after restart using the SAME first
		// Apply. Recover never creates an absent kernel object.
		if !record.NativeStarted {
			return errors.New("applied route lacks its original native dispatch")
		}
		if err := r.requireRouteBridge(ctx, ref, record); err != nil {
			return errors.Join(err, r.saveRouteCore(&record, ref, core.Pause()))
		}
		operation = &reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.Dispatched, Target: core.Journal().Applied}
		return r.runRouteDriver(ctx, ref, &record, core, *operation, r.nativeRouteDriver(), false, true)
	}
	if operation.Kind == reconcile.Apply && operation.ID != 1 {
		return errors.New("route requires explicit retirement, not a replacement Apply")
	}
	if operation.Phase == reconcile.Prepared {
		if operation.Kind == reconcile.Apply {
			if !work.PrepareAllowed {
				return nil
			}
			if err := r.currentRouteNativePermit(ctx, ref, record); err != nil {
				return err
			}
		}
		core, err = core.Dispatch(operation.ID)
		if err != nil {
			return err
		}
		if err := r.saveRouteCore(&record, ref, core); err != nil {
			return err
		}
		operation = core.Journal().Pending
	}
	if operation.Kind == reconcile.Apply && !record.NativeStarted {
		if !core.Journal().Desired.Present {
			// This is positive unsent evidence: the original durable marker
			// forbids an Execute before NativeStarted has synced.
			proof := r.routeNativeProof(ref, core.Boot(), *operation, reconcile.EffectNotApplied)
			core, err = core.ObserveNative(proof)
			if err != nil {
				return err
			}
			if err := r.saveRouteCore(&record, ref, core); err != nil {
				return err
			}
			return r.returnRouteBridge(ref, &record, core)
		}
		if !work.PrepareAllowed {
			return nil
		}
		if err := r.currentRouteNativePermit(ctx, ref, record); err != nil {
			return err
		}
		if err := r.acquireRouteBridge(ctx, ref, &record); err != nil {
			return err
		}
		// Borrow/Inspect may have waited for current policy. Take the final
		// native permission after it, then durably mark the first send.
		if err := r.currentRouteNativePermit(ctx, ref, record); err != nil {
			return err
		}
		return r.runRouteDriver(ctx, ref, &record, core, *operation, r.nativeRouteDriver(), true, false)
	}
	if operation.Kind == reconcile.Apply && !core.Journal().Desired.Present {
		core, err = core.BeginNativeRetirement()
		if err != nil {
			return err
		}
		if err := r.saveRouteCore(&record, ref, core); err != nil {
			return err
		}
		operation = core.Journal().Pending
		operation.Kind = reconcile.Remove // Compensates the SAME original target/ID.
	}
	if _, err := r.routeBridgeReceipt(ref, record); err != nil {
		return err
	}
	if operation.Kind == reconcile.Apply {
		if err := r.requireRouteBridge(ctx, ref, record); err != nil {
			return err
		}
	}
	// Removal and recovery finish original work; they cannot create an absent
	// Apply or acquire a replacement dependency after permission was revoked.
	if err := r.runRouteDriver(ctx, ref, &record, core, *operation, r.nativeRouteDriver(), false, false); err != nil {
		return err
	}
	if operation.Kind == reconcile.Remove {
		settled, err := services.DecodeRouteRuntime(record.Core)
		if err != nil {
			return err
		}
		return r.returnRouteBridge(ref, &record, settled)
	}
	return nil
}

func (r *Runtime) nativeRouteDriver() *network.TunnelDriver {
	if r.routeDriver == nil {
		r.routeDriver = &network.TunnelDriver{Owner: r.owner}
	}
	return r.routeDriver
}

type routeNativeInspector interface {
	Inspect(context.Context, string, reconcile.Operation) (reconcile.Outcome, error)
}

// inspectAppliedRoute is the read-only admission boundary. It accepts only the
// original durable Apply in this kernel boot, never pending/paused/retired work.
// The caller separately reads the original Bridge pin/native and current quorum
// authority. Inspect cannot dispatch, recover, resize, resume, or sync the owner.
func inspectAppliedRoute(ctx context.Context, ref services.ReferenceConsumer, record routeOwnerRecord, core services.RouteRuntime, boot [32]byte, driver routeNativeInspector) error {
	if driver == nil || ref.Dispatch == nil || !sameRouteDispatch(*ref.Dispatch, record.Dispatch) || ref.Native == nil || record.Bridge == (reconcile.Lease{}) || record.BridgeReturned || record.Report != nil || record.Retirement != nil || record.NeverDispatched {
		return errors.New("route inspection has no original applied owner/dependency")
	}
	if err := record.requireNativeBoot(boot); err != nil {
		return err
	}
	journal := core.Journal()
	if core.Boot() != boot || journal.Pending != nil || journal.Stopped || !journal.Desired.Present || !journal.Applied.Present || journal.Desired.Resource != journal.Applied || journal.Applied.Generation != ref.Generation || journal.Applied.Spec != hex.EncodeToString(ref.DesiredHash[:]) {
		return errors.New("route inspection cannot advance non-applied native work")
	}
	rawCore, err := core.Encode()
	if err != nil || !bytes.Equal(rawCore, record.Core) {
		return errors.New("route inspection differs from original stored core")
	}
	spec, err := services.RouteTunnelDefinition(ref)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(spec)
	if err != nil || sha256.Sum256(raw) != record.Dispatch.NativeSpec {
		return errors.New("route inspection changed its original native spec")
	}
	operation := reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.Dispatched, Target: journal.Applied}
	operation.Target.Spec = string(raw)
	outcome, err := driver.Inspect(ctx, ref.RouteNativeKey(), operation)
	if err != nil || outcome != reconcile.EffectApplied {
		return errors.Join(err, errors.New("original route native readback is unavailable"))
	}
	return ctx.Err()
}

func (r *Runtime) routeNativeProof(ref services.ReferenceConsumer, boot [32]byte, operation reconcile.Operation, outcome reconcile.Outcome) services.RouteNativeProof {
	proof := services.RouteNativeProof{Cluster: ref.Local.Cluster, Reference: services.ReferenceNeed{Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: ref.Local.Owner}, Boot: boot, Native: ref.RouteNativeKey(), Spec: operation.Target.Spec, Operation: operation.ID, Kind: operation.Kind, Outcome: outcome, JournalSynced: true, NotApplied: outcome == reconcile.EffectNotApplied, Installed: outcome == reconcile.EffectApplied && operation.Kind == reconcile.Apply, Gone: outcome == reconcile.EffectApplied && operation.Kind == reconcile.Remove}
	proof.Signature = ed25519.Sign(r.Identity.Private, services.RouteNativeBytes(proof))
	return proof
}

// Driver is the existing native execution/recovery contract. Tests inject only
// native outcomes here; the product always supplies its original TunnelDriver.
func (r *Runtime) runRouteDriver(ctx context.Context, ref services.ReferenceConsumer, record *routeOwnerRecord, core services.RouteRuntime, operation reconcile.Operation, driver reconcile.Driver, first, revalidate bool) error {
	if operation.Kind == reconcile.Remove && r.tunnel != nil && r.tunnel.routeReading(ref.ID) {
		return errors.New("route packet IO must join before original native removal")
	}
	if operation.Kind == reconcile.Remove {
		if _, closed := core.PacketClosure(); !closed {
			return errors.New("route packet closure must be durable before native removal")
		}
	}
	if r.reports == nil || r.routeStoreFailed || r.Identity == nil || r.Identity.Public != ref.Local.Owner || driver == nil {
		return errors.New("route native owner/store is unavailable")
	}
	if operation.Target.Spec != hex.EncodeToString(ref.DesiredHash[:]) || operation.Target.Generation != ref.Generation || record.BridgeReturned || ref.Dispatch == nil || !sameRouteDispatch(*ref.Dispatch, record.Dispatch) || record.Report != nil {
		return errors.New("route native operation changed its original target")
	}
	coreRaw, err := core.Encode()
	if err != nil || !bytes.Equal(coreRaw, record.Core) {
		return errors.New("route native core has not synced its original dispatch")
	}
	journal := core.Journal()
	retiring := false
	if revalidate && (journal.Pending != nil || !journal.Applied.Present || operation.Target != journal.Applied || operation.ID != 1 || operation.Kind != reconcile.Apply || operation.Phase != reconcile.Dispatched || first) {
		return errors.New("route native revalidation changed its original applied work")
	}
	if !revalidate {
		if journal.Pending == nil {
			return errors.New("route native operation has no original durable pending work")
		}
		expected := *journal.Pending
		if expected.Kind == reconcile.Apply && expected.Phase == reconcile.Retiring && operation.Kind == reconcile.Remove {
			retiring = true
			expected.Kind = reconcile.Remove
		}
		if expected != operation || !retiring && operation.Phase != reconcile.Dispatched && operation.Phase != reconcile.RecoveryRequired {
			return errors.New("route native operation is not the original durable pending work")
		}
	}
	spec, err := services.RouteTunnelDefinition(ref)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(spec)
	if sha256.Sum256(raw) != record.Dispatch.NativeSpec {
		return errors.New("route native spec differs from original dispatch")
	}
	if first {
		if record.NativeStarted || operation.Kind != reconcile.Apply || operation.ID != 1 || operation.Phase != reconcile.Dispatched || record.Bridge == (reconcile.Lease{}) || revalidate {
			return errors.New("route first native send lacks original dispatch or dependency")
		}
		candidate := *record
		candidate.NativeStarted = true
		candidate.NativeBoot = core.Boot()
		if err := r.saveRouteOwner(candidate, ref); err != nil {
			return err
		}
		*record = candidate
	} else if !record.NativeStarted {
		return errors.New("route native recovery has no original dispatch")
	}
	if err := record.requireNativeBoot(core.Boot()); err != nil {
		return err
	}
	native := operation
	native.Target.Spec = string(raw)
	var outcome reconcile.Outcome
	var effectErr error
	if first {
		outcome, effectErr = driver.Execute(ctx, ref.RouteNativeKey(), native)
	} else {
		outcome, effectErr = driver.Recover(ctx, ref.RouteNativeKey(), native)
	}
	// This TunnelDriver reports Applied or Unknown; it cannot positively prove
	// an Apply unsent. Only NativeStarted=false supplies that local evidence.
	if outcome != reconcile.EffectApplied {
		if !revalidate && !retiring {
			core, err = core.Unknown(operation.ID)
			if err != nil {
				return errors.Join(effectErr, err)
			}
			if err := r.saveRouteCore(record, ref, core); err != nil {
				return errors.Join(effectErr, err)
			}
		} else if revalidate {
			if err := r.saveRouteCore(record, ref, core.Pause()); err != nil {
				return errors.Join(effectErr, err)
			}
		} else if err := r.saveRouteCore(record, ref, core); err != nil {
			return errors.Join(effectErr, err)
		}
		return errors.Join(effectErr, errors.New("original route native outcome remains unknown"))
	}
	proof := r.routeNativeProof(ref, core.Boot(), operation, outcome)
	if retiring {
		core, err = core.FinishNativeRetirement(proof)
	} else if revalidate {
		core, err = core.RevalidateNative(proof)
		if err == nil {
			core, err = core.ResumeBoot(core.Boot())
		}
	} else {
		core, err = core.ObserveNative(proof)
	}
	if err != nil {
		return errors.Join(effectErr, err)
	}
	return errors.Join(effectErr, r.saveRouteCore(record, ref, core))
}

// Dispatch.Boot records preparation, not necessarily execution. Old schema1
// records omit NativeBoot; retain those bytes rather than inventing provenance.
func (record routeOwnerRecord) requireNativeBoot(boot [32]byte) error {
	if !record.NativeStarted || boot == ([32]byte{}) {
		return errors.New("route native execution boot is unavailable")
	}
	if record.NativeBoot != ([32]byte{}) {
		if record.NativeBoot != boot {
			return errors.New("original route native execution belongs to a previous kernel boot")
		}
	} else if record.Dispatch.Boot != boot {
		return errors.New("legacy route native execution boot cannot be established")
	}
	return nil
}

func (r *Runtime) routeBridgeReceipt(ref services.ReferenceConsumer, record routeOwnerRecord) (reconcile.Record, error) {
	if r.network == nil || ref.Native == nil || record.Bridge == (reconcile.Lease{}) || record.BridgeReturned {
		return reconcile.Record{}, errors.New("original route Bridge dependency is unavailable")
	}
	journal, err := r.network.View(ref.Native.Key)
	if err != nil || journal.State.GenerationFloor != ref.Native.Generation || journal.Consumers[ref.RouteNativeKey()] != record.Bridge {
		return reconcile.Record{}, errors.Join(err, errors.New("route Bridge lost its original source or pin"))
	}
	return journal, nil
}

func (r *Runtime) requireRouteBridge(ctx context.Context, ref services.ReferenceConsumer, record routeOwnerRecord) error {
	journal, err := r.routeBridgeReceipt(ref, record)
	if err != nil {
		return err
	}
	if journal.State.Desired.Revision != ref.Native.Revision {
		return errors.New("route Bridge source no longer has its original revision")
	}
	lease, err := r.network.InspectConsumer(ctx, ref.Native.Key, ref.RouteNativeKey(), ref.Native.Generation)
	if err != nil || lease.Pin != record.Bridge {
		return errors.Join(err, errors.New("route original Bridge is not installed"))
	}
	raw, _ := json.Marshal(lease.Spec)
	if sha256.Sum256(raw) != ref.Native.Spec {
		return errors.New("route original Bridge native hash changed")
	}
	return nil
}

func (r *Runtime) acquireRouteBridge(ctx context.Context, ref services.ReferenceConsumer, record *routeOwnerRecord) error {
	if record.Bridge != (reconcile.Lease{}) {
		return r.requireRouteBridge(ctx, ref, *record)
	}
	if r.network == nil || ref.Native == nil || record.NativeStarted || record.BridgeReturned {
		return errors.New("route may not acquire a replacement Bridge dependency")
	}
	lease, err := r.network.Acquire(ctx, ref.Native.Key, ref.RouteNativeKey(), ref.Native.Generation)
	if err != nil {
		return err // Acquire may already have synced this original consumer.
	}
	candidate := *record
	candidate.Bridge = lease.Pin
	if err := r.requireRouteBridge(ctx, ref, candidate); err != nil {
		return err
	}
	if err := r.saveRouteOwner(candidate, ref); err != nil {
		return err
	}
	*record = candidate
	return nil
}

func (r *Runtime) returnRouteBridge(ref services.ReferenceConsumer, record *routeOwnerRecord, core services.RouteRuntime) error {
	journal := core.Journal()
	if journal.Desired.Present || journal.Applied.Present || journal.Pending != nil || core.FlowCount() != 0 {
		return errors.New("route native or flow references have not closed")
	}
	if record.BridgeReturned {
		return nil
	}
	if r.network == nil || ref.Native == nil {
		return errors.New("route original Bridge journal is unavailable")
	}
	original, err := r.network.View(ref.Native.Key)
	if err != nil || original.State.GenerationFloor != ref.Native.Generation || original.Pins == nil {
		return errors.Join(err, errors.New("route original Bridge lease journal changed"))
	}
	pin, held := original.Consumers[ref.RouteNativeKey()]
	if record.Bridge == (reconcile.Lease{}) && held {
		// Acquire's own durable receipt resolves a lost Inspect/store reply.
		candidate := *record
		candidate.Bridge = pin
		if err := r.saveRouteOwner(candidate, ref); err != nil {
			return err
		}
		*record = candidate
	}
	if held {
		if pin != record.Bridge {
			return errors.New("route Bridge consumer no longer has its original token")
		}
		if err := r.network.Return(network.BridgeLease{Key: ref.Native.Key, Consumer: ref.RouteNativeKey(), Pin: record.Bridge}); err != nil {
			return err
		}
	} else if record.Bridge != (reconcile.Lease{}) && slices.Contains(original.Pins.Active, record.Bridge) {
		return errors.New("route Bridge pin is still active without its original consumer")
	}
	candidate := *record
	candidate.BridgeReturned = true
	if err := r.saveRouteOwner(candidate, ref); err != nil {
		return err
	}
	*record = candidate
	return nil
}
