// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func TestRoutePathScopeFreezesBothOriginalReferencesAndSeparatesSameNodeRelay(t *testing.T) {
	ref, _, catalog, networks, authority := routeOwnerCoreFixture(t)
	binding := services.RouteNativeBinding{Key: (tenancy.SourceIdentity{Kind: "bridge", Tenant: "second", Network: "lan", Node: "node-b"}).Key(), Generation: 8, Revision: 9, Spec: [32]byte{170}}
	_, peer, err := authority.GrantRouteInstance(catalog, networks, "admin", "first", "database", "second", 0, binding)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := services.RouteTunnelDefinition(ref)
	if err != nil {
		t.Fatal(err)
	}
	peerSpec, err := services.RouteTunnelDefinition(peer)
	if err != nil {
		t.Fatal(err)
	}
	work := control.RouteWork{Schema: 1, Reference: ref, Peer: peer, Tunnel: spec, PrepareAllowed: true}
	a, mtu, err := routePathScope(work)
	if err != nil {
		t.Fatal(err)
	}
	other := control.RouteWork{Schema: 1, Reference: peer, Peer: ref, Tunnel: peerSpec, PrepareAllowed: true}
	b, otherMTU, err := routePathScope(other)
	if err != nil || mtu != otherMTU || !bytes.Equal(a, b) {
		t.Fatal("two original owners computed different signed path scope", err)
	}
	changed := work
	changed.Peer.DesiredHash[0]++
	newScope, _, err := routePathScope(changed)
	if err != nil || bytes.Equal(a, newScope) {
		t.Fatal("path scope ignored changed original peer policy", err)
	}
	changed = work
	changed.Peer.Local.Owner = changed.Reference.Local.Owner
	if _, _, err := routePathScope(changed); err == nil {
		t.Fatal("same-node relay created an authenticated remote path")
	}
	work.PrepareAllowed = false
	if _, _, err := routePathScope(work); err == nil {
		t.Fatal("revoked owner retained a path admission scope")
	}
}

func TestRoutePacketBarrierDistinguishesNoReaderFromUnjoinedStop(t *testing.T) {
	tunnel := &tunnelRuntime{routes: map[[32]byte]*tunnelInstance{}}
	id := [32]byte{91}
	if err := tunnel.routePacketBarrier(t.Context(), id); err != nil {
		t.Fatal("exclusive owner without a reader invented pending IO", err)
	}
	instance := &tunnelInstance{}
	instance.routeReading.Store(true)
	tunnel.routes[id] = instance
	if err := tunnel.routePacketBarrier(t.Context(), id); !errors.Is(err, errTunnelPending) {
		t.Fatal("in-progress reader Stop was treated as joined", err)
	}
	instance.routeReading.Store(false)
	if err := tunnel.routePacketBarrier(t.Context(), id); err != nil {
		t.Fatal("joined reader retained phantom IO", err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := tunnel.routePacketBarrier(cancelled, id); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled barrier supplied closure", err)
	}
}

func TestRoutePacketGateExpiryDoesNotWaitForOwnerControlLock(t *testing.T) {
	r := &Runtime{}
	r.routeMu.Lock()
	gate := r.routeGate([32]byte{1})
	gate.view.Store(&routePacketView{until: time.Now().Add(-time.Second)})
	done := make(chan bool, 1)
	go func() { done <- gate.Allows([32]byte{2}, nil) }()
	select {
	case allowed := <-done:
		r.routeMu.Unlock()
		if allowed {
			t.Fatal("expired quorum read view admitted a packet")
		}
	case <-time.After(time.Second):
		r.routeMu.Unlock()
		t.Fatal("readonly packet gate waited for owner control/native IO")
	}
}

func TestRouteAndOrdinaryTunnelCannotShareWireNetworkAdmission(t *testing.T) {
	r := &Runtime{}
	r.policy.Cluster = [32]byte{71}
	name := "route/tenant/policy/1"
	ordinary := &tunnelRuntime{r: r, instances: map[[16]byte]*tunnelInstance{}}
	if _, err := ordinary.instance(name); err != nil {
		t.Fatal(err)
	}
	if _, err := ordinary.routeInstance([32]byte{72}, name); err == nil {
		t.Fatal("route reused an ordinary TUN's ungated wire namespace")
	}
	routed := &tunnelRuntime{r: r, instances: map[[16]byte]*tunnelInstance{}}
	if _, err := routed.routeInstance([32]byte{72}, name); err != nil {
		t.Fatal(err)
	}
	if _, err := routed.instance(name); err == nil {
		t.Fatal("ordinary TUN reused a route's gated wire namespace")
	}
	// Two original same-node route sides intentionally share a wire network
	// while retaining distinct private owners/pins and local relay queues.
	if _, err := routed.routeInstance([32]byte{73}, name); err != nil {
		t.Fatal("opposite route side could not join its own namespace", err)
	}
}
