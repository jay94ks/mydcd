// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
)

type routeAbsenceReader interface {
	RouteAbsent(context.Context, string, reconcile.Resource) (bool, error)
}

// Called under routeMu after syncing the current policy's permanent fence.
// observedBoot is read from the actual kernel by advanceRouteOwner. Tests
// inject it as an OS fact; no wire/request parameter supplies this evidence.
func (r *Runtime) retirePreviousBootRoute(ctx context.Context, ref services.ReferenceConsumer, record *routeOwnerRecord, core services.RouteRuntime, observedBoot [32]byte, native routeAbsenceReader) (services.RouteRuntime, error) {
	if observedBoot == ([32]byte{}) || observedBoot != core.Boot() || record.NativeBoot == ([32]byte{}) || record.NativeBoot == observedBoot || !record.NativeStarted || record.BridgeReturned || record.NeverDispatched || record.Report != nil || record.Retirement != nil || ref.Dispatch == nil || !sameRouteDispatch(*ref.Dispatch, record.Dispatch) || r.Identity == nil || r.Identity.Public != ref.Local.Owner || native == nil {
		return core, errors.New("previous kernel termination lacks original execution provenance")
	}
	if core.Journal().Desired.Present || r.tunnel == nil || r.tunnel.routeReading(ref.ID) {
		return core, errors.New("previous kernel route must be durably fenced with its reader joined")
	}
	raw, err := core.Encode()
	if err != nil || !bytes.Equal(raw, record.Core) {
		return core, errors.New("previous kernel retirement has an unsynced original core")
	}
	stored, found, err := r.loadRouteOwner(ref)
	if err != nil || !found {
		return core, errors.Join(err, errors.New("previous kernel retirement lost its original owner record"))
	}
	want, _ := json.Marshal(record)
	got, _ := json.Marshal(stored)
	if !bytes.Equal(want, got) {
		return core, errors.New("previous kernel retirement changed its stored original owner")
	}
	r.routeGate(ref.ID).view.Store(nil)
	if err := r.tunnel.routePacketBarrier(ctx, ref.ID); err != nil {
		return core, err
	}
	resource, err := originalRouteResource(ref, *record)
	if err != nil {
		return core, err
	}
	absent, err := native.RouteAbsent(ctx, ref.RouteNativeKey(), resource)
	if err != nil || !absent {
		return core, errors.Join(err, errors.New("previous kernel route has unknown or conflicting current native state"))
	}
	if err := ctx.Err(); err != nil {
		return core, err
	}
	if _, closed := core.PacketClosure(); !closed {
		proof, err := core.PacketCloseFacts()
		if err != nil {
			return core, err
		}
		core, err = r.saveRoutePacketClosure(ref, record, core, proof)
		if err != nil {
			return core, err
		}
	}
	journal := core.Journal()
	if journal.Pending == nil && !journal.Applied.Present {
		return core, nil // Keep the already synced positive terminal evidence.
	}
	if journal.Pending != nil && journal.Pending.Kind == reconcile.Apply {
		core, err = core.BeginNativeRetirement()
		if err != nil {
			return core, err
		}
	} else if journal.Pending == nil {
		core, _, err = core.Plan()
		if err != nil {
			return core, err
		}
	}
	if operation := core.Journal().Pending; operation != nil && operation.Phase == reconcile.Prepared {
		core, err = core.Dispatch(operation.ID)
		if err != nil {
			return core, err
		}
	}
	if err := r.saveRouteCore(record, ref, core); err != nil {
		return core, err
	}
	operation := core.Journal().Pending
	if operation == nil || operation.Target.Generation != ref.Generation || operation.Target.Spec != hex.EncodeToString(ref.DesiredHash[:]) {
		return core, errors.New("previous kernel retirement lost its original native operation")
	}
	removal := *operation
	removal.Kind = reconcile.Remove
	proof := r.routeNativeProof(ref, observedBoot, removal, reconcile.EffectApplied)
	if operation.Kind == reconcile.Apply {
		core, err = core.FinishNativeRetirement(proof)
	} else {
		core, err = core.ObserveNative(proof)
	}
	if err != nil {
		return core, err
	}
	if err := r.saveRouteCore(record, ref, core); err != nil {
		return core, err
	}
	return core, nil
}
