// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/jay94ks/mydcd/internal/network/services"
)

// Caller holds routeMu after the outside-lock reader stop/join. A previously
// signed closure is permanent for this fenced instance and is never replaced
// by an empty digest or a new boot's newly invented packet history.
func (r *Runtime) closeRoutePackets(ctx context.Context, ref services.ReferenceConsumer, record *routeOwnerRecord, core services.RouteRuntime) (services.RouteRuntime, error) {
	if _, closed := core.PacketClosure(); closed {
		return core, nil
	}
	if !record.NativeStarted || record.BridgeReturned || r.Identity == nil || r.Identity.Public != ref.Local.Owner || r.tunnel == nil || r.tunnel.routeReading(ref.ID) {
		return core, errors.New("original route packet reader/admissions are not closed")
	}
	if err := record.requireNativeBoot(core.Boot()); err != nil {
		return core, err
	}
	r.routeGate(ref.ID).view.Store(nil)
	proof, err := core.PacketCloseFacts()
	if err != nil {
		return core, err
	}
	// The permanent fence is already synced by advanceRouteOwner. Its A3
	// digest cannot change while this lock excludes older metadata handlers.
	if err := r.saveRouteCore(record, ref, core); err != nil {
		return core, err
	}
	resource, err := originalRouteResource(ref, *record)
	if err != nil {
		return core, err
	}
	if err := r.nativeRouteDriver().QuiesceRoute(ctx, ref.RouteNativeKey(), resource); err != nil {
		return core, err // Preserve original pins across partial fence/delete.
	}
	return r.saveRoutePacketClosure(ref, record, core, proof)
}

// Both same-boot quiescence and previous-kernel termination retain the exact
// original flow digest and use the same product ClosePackets transition.
func (r *Runtime) saveRoutePacketClosure(ref services.ReferenceConsumer, record *routeOwnerRecord, core services.RouteRuntime, proof services.RoutePacketClose) (services.RouteRuntime, error) {
	proof.JournalSynced, proof.ReadersStopped, proof.QueueEmpty = true, true, true
	proof.AdmissionsStopped, proof.ConntrackEmpty = true, true
	proof.Signature = ed25519.Sign(r.Identity.Private, services.RoutePacketCloseBytes(proof))
	candidate, err := core.ClosePackets(proof)
	if err != nil {
		return core, err
	}
	if err := r.saveRouteCore(record, ref, candidate); err != nil {
		return core, err
	}
	return candidate, nil
}
