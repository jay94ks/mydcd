// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// This is owner-local SFCP metadata, never a reliable packet fallback. Nil
// Tuple queries native proof; a tuple queries its ORIGINAL stored pin. Receipt
// confirms that pin. Native+Receipt may admit a destination pin from that exact
// source claim; missing source pins and original native state are never rebuilt.
type routeFlowRequest struct {
	Schema     uint8
	Reference  [32]byte
	Tuple      *services.RouteTuple       `json:",omitempty"`
	Receipt    *services.RouteFlowReceipt `json:",omitempty"`
	Native     *services.RouteNativeProof `json:",omitempty"`
	Close      *services.RouteFlowReceipt `json:",omitempty"`
	CloseQuery bool                       `json:",omitempty"`
}

type routeFlowReply struct {
	Schema      uint8
	Native      services.RouteNativeProof    `json:",omitzero"`
	Flow        *services.RouteFlowReceipt   `json:",omitempty"`
	Closed      *services.RoutePeerFlowClose `json:",omitempty"`
	PacketReady bool                         `json:",omitempty"`
}

// The caller holds routeMu. Reading back the original DB record precedes the
// publication signature, including when saveRouteCore had no changed bytes.
func (r *Runtime) storedRouteFlowReceipt(ref services.ReferenceConsumer, flow services.RouteFlow) (services.RouteFlowReceipt, error) {
	if r.Identity == nil || r.Identity.Public != ref.Local.Owner {
		return services.RouteFlowReceipt{}, sfcp.ErrAdmission
	}
	record, found, err := r.loadRouteOwner(ref)
	if err != nil || !found || !record.NativeStarted || record.BridgeReturned || record.Report != nil || record.Retirement != nil || record.NeverDispatched {
		return services.RouteFlowReceipt{}, errors.New("route flow has no original durable native owner")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return services.RouteFlowReceipt{}, err
	}
	proof, err := core.FlowReceiptFacts(flow)
	if err != nil {
		return services.RouteFlowReceipt{}, err
	}
	proof.JournalSynced = true
	proof.Signature = ed25519.Sign(r.Identity.Private, services.RouteFlowReceiptBytes(proof))
	return proof, nil
}

// No peer/native lock is acquired here; callers serialize their local owner.
func (r *Runtime) routeFlowAuthority(ctx context.Context, reference, caller [32]byte) (cluster.View, control.ResourceProjection, control.RouteWork, error) {
	view, projection, work, err := r.readRouteWork(ctx, control.RouteWorkRequest{Reference: reference, At: time.Now().Unix()})
	if err != nil {
		return view, projection, work, err
	}
	if err := r.validateRouteFlowCaller(view, work, caller); err != nil {
		return view, projection, work, err
	}
	return view, projection, work, r.tenantIsolationReady(view, projection)
}

func (r *Runtime) validateRouteFlowCaller(view cluster.View, work control.RouteWork, caller [32]byte) error {
	peer, peerErr := r.tunnelWireKey(view.State, work.Peer.Local.Owner)
	if peerErr != nil || peer != caller && caller != r.commandIdentity().Public || !work.PrepareAllowed || work.Tunnel.RoutePolicy == nil || work.Tunnel.RoutePolicy.Bridge == "" {
		return sfcp.ErrAdmission
	}
	return nil
}

func (r *Runtime) observeRouteFlow(ctx context.Context, caller [32]byte, input []byte) (result json.RawMessage, err error) {
	if r.Engine() == nil || r.Identity == nil {
		return nil, sfcp.ErrAdmission
	}
	// Select the exact retained native owner from this committed reference.
	request, err := schema.Decode[routeFlowRequest](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return nil, err
	}
	projection, err := r.controlPolicy.ProjectResources(view.State)
	if err != nil || projection.NetworkAuthority == nil {
		return nil, sfcp.ErrAdmission
	}
	ref, found := projection.NetworkAuthority.ReferenceConsumer(request.Reference)
	if !found || ref.Route == nil {
		return nil, sfcp.ErrAdmission
	}
	owner, local := r.nativeOwner(ref.Local.Owner)
	if !local {
		return nil, sfcp.ErrAdmission
	}
	return owner.observeRouteFlowForAdmission(ctx, caller, input, nil)
}

// A source may consume its own latest native read within this SAME admission.
// The private scope never travels on SFCP or survives the calling packet.
func (r *Runtime) observeRouteFlowForAdmission(ctx context.Context, caller [32]byte, input []byte, admission *routeAdmissionAuthority) (result json.RawMessage, err error) {
	request, err := schema.Decode[routeFlowRequest](input)
	if err != nil || request.Schema != 1 || request.Reference == ([32]byte{}) || request.Receipt != nil && request.Tuple == nil || request.Native != nil && (request.Tuple == nil || request.Receipt == nil) || r.Engine() == nil || r.Identity == nil {
		return nil, sfcp.ErrAdmission
	}
	if request.CloseQuery && request.Close == nil {
		return nil, sfcp.ErrAdmission
	}
	if request.Close != nil {
		if request.Tuple == nil || request.Receipt != nil || request.Native != nil {
			return nil, sfcp.ErrAdmission
		}
		return r.closePeerRouteFlow(ctx, caller, request)
	}
	if admission != nil && (caller != r.Identity.Public || request.Tuple != nil || !time.Now().Before(admission.until)) {
		return nil, sfcp.ErrAdmission
	}
	until := time.Now().Add(routeFlowPermitDuration)
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	// This preliminary committed snapshot authorizes no effect or response. It
	// selects the original journal/native to READ. The request obtains its own
	// fresh quorum after those reads, before any flow write/signature/gate update.
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return nil, err
	}
	projection, work, err := r.controlPolicy.ProjectRouteWork(view.State, r.commandIdentity().Public, control.RouteWorkRequest{Reference: request.Reference, At: time.Now().Unix()})
	if err != nil {
		return nil, err
	}
	if err := r.validateRouteFlowCaller(view, work, caller); err != nil {
		return nil, err
	}
	ref := work.Reference
	defer func() {
		if err != nil {
			r.routeGate(request.Reference).view.Store(nil)
		}
	}()
	record, found, err := r.loadRouteOwner(ref)
	if err != nil || !found || !record.NativeStarted || record.BridgeReturned || record.Report != nil || record.Retirement != nil || record.NeverDispatched {
		return nil, errors.New("route flow requires its original applied native owner")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil || core.Journal().Pending != nil || !core.Journal().Desired.Present || !core.Journal().Applied.Present {
		return nil, sfcp.ErrAdmission
	}
	// This metadata call observes existing native state. Recovery belongs to
	// the owner loop: it may issue link/firewall writes and invalidate packet
	// IO, even when its final installed spec is unchanged. Keep an unexpired
	// gate serving while these reads run; invalidate it on failed readback.
	if err := r.requireRouteBridge(ctx, ref, record); err != nil {
		return nil, err
	}
	boot, err := services.NativeBootID()
	if err == nil {
		err = inspectAppliedRoute(ctx, ref, record, core, boot, r.nativeRouteDriver())
	}
	if err != nil {
		return nil, err
	}
	stored, found, err := r.loadRouteOwner(ref)
	if err != nil || !found || !bytes.Equal(stored.Core, record.Core) {
		return nil, errors.New("route owner disappeared after native readback")
	}
	// Re-read current quorum after native I/O, consuming its current projection
	// too. Unrelated root advancement is allowed; changed authority is not.
	currentView, currentProjection, currentWork, err := r.routeFlowAuthority(ctx, request.Reference, caller)
	if err != nil || !sameRouteWorkPermission(work, currentWork) {
		return nil, errors.Join(err, sfcp.ErrAdmission)
	}
	permit, err := r.controlPolicy.RouteNativePermit(currentView.State, r.commandIdentity().Public, control.RouteNativeRequest{Reference: ref.ID, Nonce: record.Nonce, Operation: 1, At: time.Now().Unix()})
	if err != nil || permit.Reference != record.Dispatch.Reference || permit.Journal != record.Dispatch.Journal || permit.NativeSpec != record.Dispatch.NativeSpec || permit.Operation != record.Dispatch.Operation {
		return nil, errors.Join(err, sfcp.ErrAdmission)
	}
	view, projection, work = currentView, currentProjection, currentWork
	catalog, err := r.controlPolicy.Catalog(view.State)
	if err != nil {
		return nil, err
	}
	core, err = core.Sync(catalog, projection.Resources.Networks, *projection.NetworkAuthority)
	if err != nil {
		return nil, err
	}
	if work.MaxConsumers > 0 {
		core, err = core.Resize(work.MaxConsumers)
		if err != nil {
			return nil, err
		}
	}
	native, err := core.AppliedProof(catalog, projection.Resources.Networks, *projection.NetworkAuthority)
	if err != nil {
		return nil, err
	}
	reply := routeFlowReply{Schema: 1, Native: native}
	if request.Tuple != nil {
		flow, found := core.OriginalFlow(*request.Tuple)
		if request.Native != nil {
			core, flow, err = core.AcceptPeerFlow(catalog, projection.Resources.Networks, *projection.NetworkAuthority, *request.Native, *request.Receipt, *request.Tuple, services.Clock{Boot: core.Boot(), Wall: time.Now().Unix(), Certain: true})
			if err != nil {
				return nil, err
			}
		} else if !found {
			return nil, errors.New("original route flow pin is missing")
		} else if request.Receipt != nil {
			core, err = core.RecordPeerFlow(catalog, projection.Resources.Networks, *projection.NetworkAuthority, flow, *request.Receipt, services.Clock{Boot: core.Boot(), Wall: time.Now().Unix(), Certain: true})
			if err != nil {
				return nil, err
			}
		}
		if err := r.saveRouteCore(&record, ref, core); err != nil {
			return nil, err
		}
		proof, err := r.storedRouteFlowReceipt(ref, flow)
		if err != nil {
			return nil, err
		}
		reply.Flow = &proof
	}
	r.publishRouteGate(view, projection, work, core, until)
	if r.tunnel != nil {
		reply.PacketReady = r.tunnel.routePacketReady(ref.ID)
	}
	result, err = json.Marshal(reply)
	if err == nil && admission != nil {
		admission.work, admission.minimum = work, view.State.Index()
	}
	return result, err
}
