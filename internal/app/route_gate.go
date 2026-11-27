// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
)

const routeFlowPermitDuration = 5 * time.Second

// Only the owner replaces this immutable, already-synced read view. A QUIC
// packet handler never takes routeMu or waits for control/native/store IO.
type routePacketGate struct {
	view atomic.Pointer[routePacketView]
}
type routePacketView struct {
	core      services.RouteRuntime
	catalog   access.Catalog
	networks  tenancy.Networks
	authority services.Authority
	until     time.Time
}

// The caller holds routeMu. The pointer identity survives view invalidation.
func (r *Runtime) routeGate(id [32]byte) *routePacketGate {
	if r.routeGates == nil {
		r.routeGates = map[[32]byte]*routePacketGate{}
	}
	gate := r.routeGates[id]
	if gate == nil {
		gate = &routePacketGate{}
		r.routeGates[id] = gate
	}
	return gate
}

func (r *Runtime) publishRouteGate(view cluster.View, projection control.ResourceProjection, work control.RouteWork, core services.RouteRuntime, until time.Time) {
	gate := r.routeGate(work.Reference.ID)
	catalog, err := r.controlPolicy.Catalog(view.State)
	if err != nil || !work.PrepareAllowed || projection.NetworkAuthority == nil || !time.Now().Before(until) {
		gate.view.Store(nil)
		return
	}
	if _, err := core.AppliedProof(catalog, projection.Resources.Networks, *projection.NetworkAuthority); err != nil {
		gate.view.Store(nil)
		return
	}
	gate.view.Store(&routePacketView{core, catalog, projection.Resources.Networks, *projection.NetworkAuthority, until})
}

// Cleanup must not renew an old permission view after peer/native IO. The
// original local core is combined only with the NOW committed policy/Book.
// Caller holds routeMu; failure closes this gate and retains all durable pins.
func (r *Runtime) publishCurrentRouteGate(ctx context.Context, core services.RouteRuntime) {
	ref := core.Consumer()
	view, projection, work, err := r.routeCleanupWork(ctx, ref.ID)
	if err != nil {
		r.routeGate(ref.ID).view.Store(nil)
		return
	}
	r.publishRouteGate(view, projection, work, core, time.Now().Add(routeFlowPermitDuration))
}

// Scheduling only: an absent view may hide an existing durable flow, so keep
// the original local-refresh-first path. An expired paired view also keeps
// that path. This never grants permission or renews a gate/deadline.
func (g *routePacketGate) localRefreshFirst(sender [32]byte, packet []byte) bool {
	v := g.view.Load()
	if v == nil {
		return true
	}
	_, bound := v.core.PacketBinding(v.catalog, v.networks, v.authority, sender, packet, services.Clock{Boot: v.core.Boot(), Wall: time.Now().Unix(), Certain: true})
	return bound
}

func (g *routePacketGate) Allows(sender [32]byte, packet []byte) bool {
	_, allowed := g.PacketBinding(sender, packet)
	return allowed
}

func (g *routePacketGate) PacketBinding(sender [32]byte, packet []byte) (network.PacketBinding, bool) {
	v := g.view.Load()
	if v == nil || !time.Now().Before(v.until) {
		return network.PacketBinding{}, false
	}
	now := services.Clock{Boot: v.core.Boot(), Wall: time.Now().Unix(), Certain: true}
	// A flow is immutable for one opposite native boot. Packet lookup and the
	// coordinated gate both validate that exact original boot and receipt.
	return v.core.PacketBinding(v.catalog, v.networks, v.authority, sender, packet, now)
}

// Existing bilateral flows use locally committed authority during a control
// outage. This refresh creates no flow/native work and never substitutes for
// the latest-quorum checks in the NEW source/destination admission paths.
func (r *Runtime) refreshExistingRouteGates(view cluster.View) error {
	r.routeMu.Lock()
	defer r.routeMu.Unlock()
	if len(r.routeGates) == 0 {
		return nil
	}
	projection, err := r.controlPolicy.ProjectResources(view.State)
	if err != nil || projection.NetworkAuthority == nil {
		for _, gate := range r.routeGates {
			gate.view.Store(nil)
		}
		return err
	}
	until := time.Now().Add(routeFlowPermitDuration)
	for id, gate := range r.routeGates {
		work, err := r.controlPolicy.RouteWork(view.State, r.commandIdentity().Public, control.RouteWorkRequest{Reference: id})
		if err != nil || !work.PrepareAllowed {
			gate.view.Store(nil)
			continue
		}
		record, found, err := r.loadRouteOwner(work.Reference)
		if err != nil || !found || !record.NativeStarted || record.BridgeReturned || record.Retirement != nil || record.Report != nil {
			gate.view.Store(nil)
			continue
		}
		core, err := services.DecodeRouteRuntime(record.Core)
		if err != nil {
			gate.view.Store(nil)
			continue
		}
		r.publishRouteGate(view, projection, work, core, until)
	}
	return nil
}
