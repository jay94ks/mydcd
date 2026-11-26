// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
)

func verifyAppPlanStreamRelay(t *testing.T, ctx context.Context, leader, follower *Runtime, client userauth.Client, session access.Session, target mydcp.Peer, p control.Policy, submit func(string, string, uint64, any), wait func(string, func() bool)) {
	t.Helper()
	submit("stream-tenant", "create-tenant", 0, control.TenantID{ID: "tenant"})
	shared, err := leader.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ := p.Catalog(shared.State)
	tenant, _ := catalog.Tenant("tenant")
	submit("stream-nodes", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a"}})
	for _, scope := range []string{"", "tenant"} {
		id := "stream-global"
		if scope != "" {
			id = "stream-scoped"
		}
		submit(id, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-a", Capacity: workload.Resources{CPU: 1e9, Memory: 256 << 20}, Networks: 2, MaxConsumers: 8})
	}
	resources, err := p.Resources(shared.State)
	if err != nil {
		t.Fatal(err)
	}
	submit("stream-network", "create-tun-network", resources.Networks.Revision(), tenancy.TUNDefinition{Tenant: "tenant", Name: "existing", Members: []tenancy.TUNNode{{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.199.0.0/24"), Gateway: netip.MustParseAddr("10.199.0.1"), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix("10.199.2.1/32")}}}})
	shared, err = leader.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	wait("stream follower committed catalog/leader", func() bool {
		v, err := follower.Engine().Read(ctx, false)
		peer, known := follower.Engine().LeaderPeer()
		return err == nil && v.State.Index() >= shared.State.Index() && known && peer.ID == "node-a"
	})
	if follower.Engine().IsLeader() {
		t.Fatal("relay target must be non-leader")
	}
	document := []byte("#" + strings.Repeat("large-input", 8<<10) + "\nname: app\nservices:\n web:\n  image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n  cpus: 0.1\n  mem_limit: 16m\n  networks: {app: {ipv4_address: 10.199.0.10}}\n  x-mydc: {node: node-a}\nnetworks:\n app: {external: true, name: existing}\n")
	p, err = p.Current(shared.State)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := p.AppPlanArtifact(shared.State, session, time.Now().Unix(), "tenant", control.AppPlanRequest{Document: document})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := client.StreamAppPlan(ctx, target, session, "tenant", control.AppPlanRequest{Document: document})
	if err != nil || !bytes.Equal(expected, artifact) {
		t.Fatal("member relay changed original plan", err)
	}
	diff, err := client.StreamAppPlan(ctx, target, session, "tenant", control.AppPlanRequest{Document: document, Diff: true})
	if err != nil {
		t.Fatal(err)
	}
	comparison, err := control.DecodeAppDiff(diff)
	if err != nil || len(comparison.Changes) != 2 || comparison.InventoryRevision != 0 {
		t.Fatal("relayed diff", err)
	}
	after, err := leader.Engine().Read(ctx, true)
	if err != nil || after.State.Index() != shared.State.Index() {
		t.Fatal("read-only relay wrote durable candidates", err)
	}
	t.Log("actual dynamically admitted nonvoter receives large signed user input -> one current member relay bound to original caller/challenge/body/digest -> latest leader Compile/diff -> digest-checked result -> original connection; no local compile/temporary shared upload/management writes; no node or legacy user rights")
}
