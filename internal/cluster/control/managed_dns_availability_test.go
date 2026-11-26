// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network/services"
)

// Signed native observations are explicit fake inputs here. Membership,
// command/result/ref validation, IPAM and DNS projections are product cores.
func TestManagedDNSReplicaServingAvailabilityPreservesNameAndAddressOwnership(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	const app = "replica-app"
	managedDNSTaskCoreBegin(t, f, app, "10.80.1.2", "replicas", func(c *deployment.Compose, _ *deployment.PlanningContext) {
		service := c.Services["web"]
		service.MyDC.Node, service.MyDC.Nodes, service.MyDC.PerNode = "", []string{"node-a"}, 2
		attachment := service.Networks["lan"]
		attachment.IPv4 = ""
		service.Networks["lan"] = attachment
		c.Services["web"] = service
	})
	managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	first := deployment.ResourceKey("task", "tenant", app, "web/node-a/r1")
	second := deployment.ResourceKey("task", "tenant", app, "web/node-a/r2")
	managedDNSTaskCoreSubmit(t, f, app, first, true, state.Applied)
	managedDNSTaskCoreSubmit(t, f, app, second, true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	_, owners, known := apps.NetworkDNS([32]byte(f.node.Public().(ed25519.PublicKey)))
	if !known || len(owners) != 1 {
		t.Fatal("original logical DNS view missing")
	}
	config := owners[0].Config
	if len(config.Names) < 2 {
		t.Fatal("replica addresses were not both reserved")
	}
	before, _ := json.Marshal(apps.network.Groups)
	unavailable, err := f.p.AppDNSUnavailable(f.s, config, 10)
	if err != nil || len(unavailable) != 0 {
		t.Fatal("fresh healthy owners excluded", err, unavailable)
	}
	e, _ := apps.Execution("tenant", app)
	stage, _ := e.Stage(second)
	o := *stage.Observation
	o.Sequence++
	o.Healthy = false
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, app, "observe", second, &o)
	unavailable, err = f.p.AppDNSUnavailable(f.s, config, 10)
	if err != nil || len(unavailable) != 1 || unavailable[0].Endpoint != second+"/lan/0" {
		t.Fatal("failed replica hid the healthy peer or remained serving", err, unavailable)
	}
	apps, _ = f.p.Apps(f.s)
	after, _ := json.Marshal(apps.network.Groups)
	if !bytes.Equal(before, after) {
		t.Fatal("health observation released name, address or network reference")
	}
	catalog, _ := f.p.Catalog(f.s)
	rows, _, err := apps.ObservedPage(catalog, "admin", "tenant", "", 10)
	if err != nil || len(rows) != 1 || f.p.ObserveAppReplicaHealth(f.s, apps, &rows[0], 10) != nil || rows[0].Health != "Degraded" {
		t.Fatal("partial replica availability was hidden", err)
	}
	unavailable, err = f.p.AppDNSUnavailable(expireAll(t, f.p, f.s, f.node, 10+AppObservationMaxAge+1), config, 10+AppObservationMaxAge+1)
	if err != nil || len(unavailable) != 2 {
		t.Fatal("stale owners remained in DNS", err, unavailable)
	}
	candidates, err := acceptedTaskCandidates(f.s, apps, apps.entries[appKey("tenant", app)].Inventory.Scope(), apps.entries[appKey("tenant", app)].Inventory.Claims())
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if taskCandidateAvailable(f.s, candidate, 10, false) {
			t.Fatal("ineligible owner retained a serving grant")
		}
	}
	if _, err := f.p.AppDNSUnavailable(f.s, services.DNSConfig{}, 0); err == nil {
		t.Fatal("unknown adapter time was treated as fresh")
	}
}
