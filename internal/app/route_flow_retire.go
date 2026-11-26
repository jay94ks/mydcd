// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network/services"
)

// Cleanup uses local committed ORIGINAL references, not a new admission
// permit. Current transport/member authentication still applies. No new
// native work, flow pin, policy or majority grant can be created here.
func (r *Runtime) routeCleanupWork(ctx context.Context, reference [32]byte) (cluster.View, control.ResourceProjection, control.RouteWork, error) {
	var projection control.ResourceProjection
	var work control.RouteWork
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return view, projection, work, err
	}
	work, err = r.controlPolicy.RouteWork(view.State, r.commandIdentity().Public, control.RouteWorkRequest{Reference: reference})
	if err != nil {
		return view, projection, work, err
	}
	projection, err = r.controlPolicy.ProjectResources(view.State)
	if err != nil || projection.NetworkAuthority == nil {
		return view, projection, work, errors.Join(err, mydcp.ErrAdmission)
	}
	return view, projection, work, nil
}

// Caller holds routeMu and has already stored/published Closing. A reader's
// new-flow callback never holds the final packet IO lock while doing control
// IO, so this barrier does not wait for another routeMu holder.
func (r *Runtime) closeLocalRouteFlow(ctx context.Context, ref services.ReferenceConsumer, record routeOwnerRecord, core services.RouteRuntime, flow services.RouteFlow) (services.RouteFlowClose, error) {
	proof, err := core.FlowCloseFacts(flow)
	if err != nil {
		return proof, err
	}
	if r.tunnel == nil || !record.NativeStarted || record.BridgeReturned {
		return proof, errors.New("original route flow has no enabled native packet owner")
	}
	if err := r.tunnel.routePacketBarrier(ctx, ref.ID); err != nil {
		return proof, err
	}
	resource, err := originalRouteResource(ref, record)
	if err != nil {
		return proof, err
	}
	if err := r.nativeRouteDriver().DrainRouteFlow(ctx, ref.RouteNativeKey(), resource, flow.Tuple().Transport()); err != nil {
		return proof, err
	}
	if err := ctx.Err(); err != nil {
		return proof, err
	}
	proof.JournalSynced, proof.Stopped, proof.NoPending = true, true, true
	proof.Signature = ed25519.Sign(r.Identity.Private, services.RouteFlowCloseBytes(proof))
	return proof, nil
}

// Caller holds routeMu. A real DB readback precedes every publication, even
// when a candidate had identical bytes and saveRouteCore needed no new write.
func (r *Runtime) storedClosingRouteClaim(ref services.ReferenceConsumer, flow services.RouteFlow) (services.RouteFlowReceipt, error) {
	if r.Identity == nil || r.Identity.Public != ref.Local.Owner {
		return services.RouteFlowReceipt{}, mydcp.ErrAdmission
	}
	record, found, err := r.loadRouteOwner(ref)
	if err != nil || !found || !record.NativeStarted || record.BridgeReturned || record.NeverDispatched {
		return services.RouteFlowReceipt{}, errors.New("source close requires its original stored pin")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return services.RouteFlowReceipt{}, err
	}
	claim, err := core.ClosingSourceClaimFacts(flow)
	if err != nil {
		return services.RouteFlowReceipt{}, err
	}
	claim.JournalSynced = true
	claim.Signature = ed25519.Sign(r.Identity.Private, services.RouteFlowReceiptBytes(claim))
	return claim, nil
}

func (r *Runtime) storedPeerRouteFlowClose(ref services.ReferenceConsumer, a services.Authority, claim services.RouteFlowReceipt, tuple services.RouteTuple) (services.RoutePeerFlowClose, error) {
	if r.Identity == nil || r.Identity.Public != ref.Local.Owner {
		return services.RoutePeerFlowClose{}, mydcp.ErrAdmission
	}
	record, found, err := r.loadRouteOwner(ref)
	if err != nil || !found {
		return services.RoutePeerFlowClose{}, errors.New("peer close requires its original durable tombstone")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return services.RoutePeerFlowClose{}, err
	}
	proof, err := core.PeerFlowCloseFacts(a, claim, tuple)
	if err != nil {
		return services.RoutePeerFlowClose{}, err
	}
	proof.JournalSynced, proof.Stopped, proof.NoPending, proof.Tombstoned = true, true, true, true
	proof.Signature = ed25519.Sign(r.Identity.Private, services.RoutePeerFlowCloseBytes(proof))
	return proof, nil
}

func (r *Runtime) closePeerRouteFlow(ctx context.Context, caller [32]byte, request routeFlowRequest) (json.RawMessage, error) {
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	view, projection, work, err := r.routeCleanupWork(ctx, request.Reference)
	if err != nil {
		return nil, err
	}
	if request.Close == nil || request.Tuple == nil {
		return nil, mydcp.ErrAdmission
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil || !members.MemberKey(caller) || !members.OwnsResource(caller, request.Close.Reference.Owner) {
		return nil, mydcp.ErrAdmission
	}
	record, found, err := r.loadRouteOwner(work.Reference)
	if err != nil || !found {
		return nil, errors.New("peer close requires the original durable route owner")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return nil, err
	}
	if request.CloseQuery {
		proof, err := r.storedPeerRouteFlowClose(work.Reference, *projection.NetworkAuthority, *request.Close, *request.Tuple)
		if err != nil {
			return nil, err
		}
		return json.Marshal(routeFlowReply{Schema: 1, Closed: &proof})
	}
	candidate, flow, err := core.BeginPeerFlowClose(*projection.NetworkAuthority, *request.Close, *request.Tuple)
	if err != nil {
		return nil, err
	}
	if err := r.saveRouteCore(&record, work.Reference, candidate); err != nil {
		return nil, err
	}
	r.publishCurrentRouteGate(ctx, candidate)
	if flow.Lease().Token != 0 {
		local, err := r.closeLocalRouteFlow(ctx, work.Reference, record, candidate, flow)
		if err != nil {
			return nil, err
		}
		candidate, err = candidate.FinishPeerFlowClose(*projection.NetworkAuthority, flow, *request.Close, local)
		if err != nil {
			return nil, err
		}
		if err := r.saveRouteCore(&record, work.Reference, candidate); err != nil {
			return nil, err
		}
	}
	// Read back the same DB before signing either a just-closed or an already
	// tombstoned source pin. Missing journal never supplies no-admission proof.
	proof, err := r.storedPeerRouteFlowClose(work.Reference, *projection.NetworkAuthority, *request.Close, *request.Tuple)
	if err != nil {
		return nil, err
	}
	r.publishCurrentRouteGate(ctx, candidate)
	return json.Marshal(routeFlowReply{Schema: 1, Closed: &proof})
}

type routeFlowCloseTask struct {
	reference [32]byte
	peer      services.ReferenceConsumer
	flow      services.RouteFlow
	claim     services.RouteFlowReceipt
}

// Build tasks from the actual checkpoint, not volatile packet/census state.
// Only the owner loop calls this collector; peer IO is outside routeMu.
func (r *Runtime) collectActiveRouteFlows(ctx context.Context, view cluster.View, projection control.ResourceProjection) error {
	if projection.NetworkAuthority == nil {
		return nil
	}
	r.routeMu.Lock()
	var tasks []routeFlowCloseTask
	for _, ref := range projection.NetworkAuthority.RouteReferences() {
		if ref.Local.Owner != r.Identity.Public || ref.Route.Side != ref.Route.Policy.Source.Tenant || ref.Native == nil || ref.Closed != nil {
			continue
		}
		work, err := r.controlPolicy.RouteWork(view.State, r.commandIdentity().Public, control.RouteWorkRequest{Reference: ref.ID})
		if err != nil || !work.PrepareAllowed {
			continue
		}
		record, found, err := r.loadRouteOwner(ref)
		if err != nil {
			r.routeMu.Unlock()
			return err
		}
		if !found || !record.NativeStarted || record.BridgeReturned || record.Retirement != nil {
			continue
		}
		core, err := services.DecodeRouteRuntime(record.Core)
		if err != nil {
			r.routeMu.Unlock()
			return err
		}
		for _, flow := range core.Flows() {
			_, closing, _ := core.FlowLifetime(flow)
			if !closing {
				continue
			}
			claim, err := r.storedClosingRouteClaim(ref, flow)
			if err != nil {
				r.routeMu.Unlock()
				return err
			}
			peer, known := projection.NetworkAuthority.ReferenceConsumer(claim.Peer.Consumer)
			if !known || peer.Generation != claim.Peer.Generation || peer.Lifetime != claim.Peer.Lifetime || peer.Local.Owner != claim.Peer.Owner {
				r.routeMu.Unlock()
				return mydcp.ErrAdmission
			}
			tasks = append(tasks, routeFlowCloseTask{ref.ID, peer, flow, claim})
		}
	}
	start := 0
	if len(tasks) > 0 {
		start = int(r.routeFlowCloseCursor % uint64(len(tasks)))
		r.routeFlowCloseCursor++
	}
	r.routeMu.Unlock()
	batch, batchCancel := context.WithTimeout(ctx, routeFlowPermitDuration)
	defer batchCancel()
	var result error
	for offset := 0; offset < len(tasks); offset++ {
		task := tasks[(start+offset)%len(tasks)]
		tuple := task.flow.Tuple()
		reply, err := r.callRouteFlow(batch, task.peer, routeFlowRequest{Schema: 1, Reference: task.peer.ID, Tuple: &tuple, Close: &task.claim})
		if err == nil {
			err = r.finishActiveRouteFlow(batch, task, reply)
		}
		result = errors.Join(result, err)
		if batch.Err() != nil {
			return errors.Join(result, batch.Err())
		}
	}
	return result
}

func (r *Runtime) finishActiveRouteFlow(ctx context.Context, task routeFlowCloseTask, reply routeFlowReply) error {
	if reply.Closed == nil {
		return mydcp.ErrAdmission
	}
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	_, _, work, err := r.routeCleanupWork(ctx, task.reference)
	if err != nil {
		return err
	}
	record, found, err := r.loadRouteOwner(work.Reference)
	if err != nil || !found {
		return errors.New("source closure lost its original route owner")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return err
	}
	flow, found := core.OriginalFlow(task.flow.Tuple())
	if !found || flow != task.flow {
		if _, bulkClosed := core.PacketClosure(); bulkClosed {
			return nil
		}
		return errors.New("original closing source pin is unavailable")
	}
	r.publishCurrentRouteGate(ctx, core)
	local, err := r.closeLocalRouteFlow(ctx, work.Reference, record, core, flow)
	if err != nil {
		return err
	}
	core, err = core.FinishSourceFlowClose(flow, local, *reply.Closed)
	if err != nil {
		return err
	}
	if err := r.saveRouteCore(&record, work.Reference, core); err != nil {
		return err
	}
	r.publishCurrentRouteGate(ctx, core)
	return nil
}
