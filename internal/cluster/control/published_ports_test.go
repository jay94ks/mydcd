// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload"
)

func TestPublishedPortsProjectionHoldsAcceptedOriginalBeforeNativeAndAfterCommit(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	ports, _ := workload.NormalizePublishedPorts([]workload.PublishedPort{{Target: 8080, Published: "18080", HostIP: "0.0.0.0"}, {Target: 53100, Published: "18080", Protocol: "udp", HostIP: "127.0.0.1"}})
	key := managedDNSTaskCoreBegin(t, f, "published", "10.80.1.40", "published", func(c *deployment.Compose, _ *deployment.PlanningContext) {
		s := c.Services["web"]
		s.Ports = ports
		c.Services["web"] = s
	})
	assertHeld := func() {
		t.Helper()
		projection, err := f.p.ProjectResources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		var source *deployment.HostPortUse
		for i := range projection.HostPorts {
			u := &projection.HostPorts[i]
			if u.Key == key {
				source = u
				break
			}
		}
		if source == nil || source.Node != "node-a" || source.Owner == ([32]byte{}) || !slices.Equal(source.Ports, ports) {
			t.Fatal("original accepted source not retained", source)
		}
		rival := *source
		rival.Key = deployment.ResourceKey("task", "other-tenant", "rival", "web")
		rival.Ports = slices.Clone(source.Ports)
		rival.Ports[0].HostIP = "127.0.0.1"
		if deployment.CheckHostPortUses(projection.HostPorts, rival) == nil {
			t.Fatal("accepted source allowed a competing tenant before native closure")
		}
		if deployment.CheckHostPortUses(projection.HostPorts, *source) != nil {
			t.Fatal("same exact original replacement cannot reuse listener")
		}
		// The planning API consumes this exact projection, rather than inventing a
		// different port reservation or accepting stale local Docker observations.
		planning, err := f.p.AppPlanning(f.s, "admin", "tenant")
		if err != nil {
			t.Fatal(err)
		}
		if len(planning.HostPorts) != len(projection.HostPorts) {
			t.Fatal("planning omitted accepted host-port intent")
		}
	}
	assertHeld()
	// No Task/native exists at the first assertion. Now commit the very same
	// original Task through the normal FSM dispatch/commit fixture. Receipt
	// collection/native readiness is deliberately still pending at this point.
	managedDNSTaskCoreSubmit(t, f, "published", deployment.ResourceKey("network-ref", "tenant", "published", "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	managedDNSTaskCoreSubmit(t, f, "published", key, false, state.Applied)
	assertHeld()
}
