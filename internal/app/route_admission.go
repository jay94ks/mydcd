// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Bounded diagnostics only; neither pointer participates in authorization or
// durability. No packet bytes, credential material or alternate work is kept.
type routeAdmissionObservation struct {
	Reference     [32]byte
	Stage         string
	StartedAt     int64
	ElapsedMillis int64
	Error         string `json:",omitempty"`
	Phases        []routeAdmissionPhase
}

type routeAdmissionPhase struct {
	Stage         string
	ElapsedMillis int64
}

// Peer IO is deliberately outside routeMu. Two nodes may simultaneously read
// and confirm each other's original owner records without taking both locks.
func (r *Runtime) callRouteFlow(ctx context.Context, peer services.ReferenceConsumer, request routeFlowRequest) (routeFlowReply, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return routeFlowReply{}, err
	}
	var response json.RawMessage
	member, known := r.resourcePeerForKey(ctx, peer.Local.Owner)
	if !known || !member.Member {
		return routeFlowReply{}, sfcp.ErrAdmission
	}
	if [32]byte(member.Key) == r.commandIdentity().Public {
		owner, local := r.nativeOwner(peer.Local.Owner)
		if !local {
			return routeFlowReply{}, sfcp.ErrAdmission
		}
		response, err = owner.observeRouteFlow(ctx, r.commandIdentity().Public, raw)
	} else {
		var reply cluster.ManagementReply
		reply, err = cluster.CallManagement(ctx, r.Mesh, r.commandIdentity(), r.controlPolicy.Cluster, member, cluster.ManagementRequest{Method: "route-flow-observe", Latest: false, Input: raw})
		response = reply.Data
	}
	if err != nil {
		return routeFlowReply{}, err
	}
	reply, err := schema.Decode[routeFlowReply](response)
	if err != nil || reply.Schema != 1 {
		return routeFlowReply{}, sfcp.ErrAdmission
	}
	need := reply.Native.Reference
	if request.Close != nil {
		if reply.Closed == nil || reply.Flow != nil {
			return routeFlowReply{}, sfcp.ErrAdmission
		}
		need = reply.Closed.Reference
	} else if reply.Closed != nil {
		return routeFlowReply{}, sfcp.ErrAdmission
	}
	if need.Consumer != peer.ID || need.Generation != peer.Generation || need.Lifetime != peer.Lifetime || need.Owner != peer.Local.Owner {
		return routeFlowReply{}, sfcp.ErrAdmission
	}
	return reply, nil
}

// admitRoutePacket runs on the local plane's single admission worker. A failed/unknown peer
// reply drops this packet and preserves the same original local pin for its
// retransmission. It never retries a packet, invents a new operation, or treats
// the absent reply as proof that the destination did not store its pin.
func (r *Runtime) admitRoutePacket(ctx context.Context, reference [32]byte, packet []byte) (err error) {
	started := time.Now()
	stage := "source-view"
	phases := []routeAdmissionPhase{{Stage: stage}}
	publish := func(cause error) {
		value := &routeAdmissionObservation{Reference: reference, Stage: stage, StartedAt: started.UnixNano(), ElapsedMillis: time.Since(started).Milliseconds(), Phases: append([]routeAdmissionPhase(nil), phases...)}
		if cause != nil {
			value.Error = cause.Error()
			r.routeAdmissionError.Store(value)
		}
		r.routeAdmission.Store(value)
	}
	phase := func(name string) {
		stage = name
		phases = append(phases, routeAdmissionPhase{Stage: name, ElapsedMillis: time.Since(started).Milliseconds()})
		publish(nil)
	}
	publish(nil)
	defer func() {
		if err == nil {
			stage = "complete"
		}
		publish(err)
		if err != nil {
			// Existing admission is bounded to five seconds. No packet or receipt
			// bytes are retained; this exposes the first failed protocol stage.
			log.Printf("route admission failed: reference=%x stage=%s elapsed_ms=%d cause=%v phases=%v", reference, stage, time.Since(started).Milliseconds(), err, phases)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, routeFlowPermitDuration)
	defer cancel()
	until := time.Now().Add(routeFlowPermitDuration)
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	phase("source-work")
	work, err := r.controlPolicy.RouteWork(view.State, r.commandIdentity().Public, control.RouteWorkRequest{Reference: reference})
	peerWire, wireErr := r.tunnelWireKey(view.State, work.Peer.Local.Owner)
	if err != nil || wireErr != nil || work.Peer.Route == nil {
		return sfcp.ErrAdmission
	}
	// Expired read views of existing flows can be refreshed on either side;
	// only a source SYN/UDP packet may proceed to a NEW bilateral admission.
	authority := routeAdmissionAuthority{until: until}
	localInput, err := json.Marshal(routeFlowRequest{Schema: 1, Reference: reference})
	if err != nil {
		return err
	}
	readLocal := func(call context.Context) (routeFlowReply, error) {
		raw, err := r.observeRouteFlowForAdmission(call, r.commandIdentity().Public, localInput, &authority)
		if err != nil {
			return routeFlowReply{}, err
		}
		return schema.Decode[routeFlowReply](raw)
	}
	r.routeMu.Lock()
	gate := r.routeGate(reference)
	localFirst := gate.localRefreshFirst(r.Identity.Public, packet)
	r.routeMu.Unlock()
	sourceSide := work.Reference.Route.Side == work.Reference.Route.Policy.Source.Tenant
	var local, peer routeFlowReply
	var peerErr error
	if sourceSide && !localFirst {
		phase("native-readbacks")
		reads := parallelRouteNativeReadbacks(ctx, readLocal, func(call context.Context) (routeFlowReply, error) {
			return r.callRouteFlow(call, work.Peer, routeFlowRequest{Schema: 1, Reference: work.Peer.ID})
		})
		var localErr error
		for _, read := range reads {
			phases = append(phases, routeAdmissionPhase{Stage: read.stage + "-done", ElapsedMillis: read.completed.Sub(started).Milliseconds()})
			if read.stage == "local-native" {
				local, localErr = read.reply, read.err
			} else {
				peer, peerErr = read.reply, read.err
			}
		}
		if localErr != nil {
			for _, read := range reads {
				if read.err != nil {
					stage = read.stage
					return read.err
				}
			}
		}
		if gate.Allows(r.Identity.Public, packet) {
			return nil
		}
		if peerErr != nil {
			stage = "peer-native"
			return peerErr
		}
	} else {
		phase("local-native")
		local, err = readLocal(ctx)
		if err != nil {
			return err
		}
		if gate.Allows(r.Identity.Public, packet) {
			return nil
		}
		if !sourceSide {
			return sfcp.ErrAdmission
		}
		phase("peer-native")
		peer, err = r.callRouteFlow(ctx, work.Peer, routeFlowRequest{Schema: 1, Reference: work.Peer.ID})
		if err != nil {
			return err
		}
	}
	phase("source-prepare")
	flow, source, err := r.prepareRouteFlow(ctx, authority, peerWire, peer.Native, local.Native, packet)
	if err != nil {
		return err
	}
	tuple := flow.Tuple()
	phase("peer-admit-response")
	reply, err := r.callRouteFlow(ctx, work.Peer, routeFlowRequest{Schema: 1, Reference: work.Peer.ID, Tuple: &tuple, Receipt: &source, Native: &local.Native})
	if err != nil {
		return err // The exact source pin remains durable, including unknown B.
	}
	if reply.Flow == nil {
		return errors.New("destination omitted its original flow receipt")
	}
	phase("source-authority")
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	view, projection, current, err := r.readRouteAdmissionAuthority(ctx, authority, peerWire)
	if err != nil {
		return err
	}
	record, found, err := r.loadRouteOwner(current.Reference)
	if err != nil || !found {
		return errors.New("original source flow owner is unavailable")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return err
	}
	catalog, err := r.controlPolicy.Catalog(view.State)
	if err != nil {
		return err
	}
	phase("source-record-peer")
	core, err = core.RecordPeerFlow(catalog, projection.Resources.Networks, *projection.NetworkAuthority, flow, *reply.Flow, services.Clock{Boot: core.Boot(), Wall: time.Now().Unix(), Certain: true})
	if err != nil {
		return err
	}
	phase("source-sync-peer")
	if err := r.saveRouteCore(&record, current.Reference, core); err != nil {
		return err
	}
	phase("source-publish-gate")
	r.publishRouteGate(view, projection, current, core, until)
	if !gate.Allows(r.Identity.Public, packet) {
		return sfcp.ErrAdmission
	}
	return nil
}

func (r *Runtime) prepareRouteFlow(ctx context.Context, authority routeAdmissionAuthority, peerOwner [32]byte, peer, local services.RouteNativeProof, packet []byte) (services.RouteFlow, services.RouteFlowReceipt, error) {
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	var flow services.RouteFlow
	var receipt services.RouteFlowReceipt
	view, projection, work, err := r.readRouteAdmissionAuthority(ctx, authority, peerOwner)
	if err != nil {
		return flow, receipt, err
	}
	record, found, err := r.loadRouteOwner(work.Reference)
	if err != nil || !found || !record.NativeStarted || record.BridgeReturned || record.Report != nil || record.Retirement != nil || record.NeverDispatched {
		return flow, receipt, errors.New("source has no original applied route owner")
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		return flow, receipt, err
	}
	catalog, err := r.controlPolicy.Catalog(view.State)
	if err != nil {
		return flow, receipt, err
	}
	current, err := core.AppliedProof(catalog, projection.Resources.Networks, *projection.NetworkAuthority)
	if err != nil || current.Boot != local.Boot || current.Reference != local.Reference || peer.Reference.Consumer != work.Peer.ID {
		return flow, receipt, sfcp.ErrAdmission
	}
	now := services.Clock{Boot: core.Boot(), Wall: time.Now().Unix(), Certain: true}
	flow, err = core.ExistingPacket(catalog, projection.Resources.Networks, *projection.NetworkAuthority, peer.Boot, r.Identity.Public, packet, now)
	if err != nil {
		core, flow, err = core.BorrowPacket(catalog, projection.Resources.Networks, *projection.NetworkAuthority, peer, peer.Boot, r.Identity.Public, packet, now)
		if err != nil {
			return flow, receipt, err
		}
	}
	census, err := r.routeFlowCensus(ctx, work.Reference, record)
	if err != nil {
		return flow, receipt, err
	}
	if !census[routeTransportTuple(flow.Tuple())] {
		return flow, receipt, errors.New("source packet has no original owned conntrack tuple")
	}
	core, err = core.TrackFlow(flow)
	if err != nil {
		return flow, receipt, err
	}
	if err := r.saveRouteCore(&record, work.Reference, core); err != nil {
		return flow, receipt, err
	}
	receipt, err = r.storedRouteFlowReceipt(work.Reference, flow)
	return flow, receipt, err
}

// Fixed pair, no detached reader: both owner observations consume the SAME
// admission context and both completions are joined even on error/cancel.
type routeNativeReadback struct {
	stage     string
	reply     routeFlowReply
	err       error
	completed time.Time
}

func parallelRouteNativeReadbacks(ctx context.Context, local, peer func(context.Context) (routeFlowReply, error)) [2]routeNativeReadback {
	done := make(chan routeNativeReadback, 2)
	run := func(stage string, read func(context.Context) (routeFlowReply, error)) {
		reply, err := read(ctx)
		done <- routeNativeReadback{stage: stage, reply: reply, err: err, completed: time.Now()}
	}
	go run("local-native", local)
	go run("peer-native", peer)
	return [2]routeNativeReadback{<-done, <-done}
}
