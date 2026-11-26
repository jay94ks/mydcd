// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
)

func TestRealManagedTunnelGoalQuorumPermitAndPacketPolicy(t *testing.T) {
	testRealManagedJoin(t, true, "tunnel")
}

func verifyAppTunnelAdmission(t *testing.T, ctx context.Context, leader, follower *Runtime, c userauth.Client, session access.Session, target mydcp.Peer, p control.Policy, submit func(string, string, uint64, any)) {
	t.Helper()
	read := func() state.State {
		t.Helper()
		v, e := leader.Engine().Read(ctx, true)
		if e != nil {
			t.Fatal(e)
		}
		return v.State
	}
	submit("tunnel-tenant", "create-tenant", 0, control.TenantID{ID: "tenant"})
	catalog, _ := p.Catalog(read())
	tenant, _ := catalog.Tenant("tenant")
	submit("tunnel-nodes", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a", "node-b"}})
	for _, node := range []string{"node-a", "node-b"} {
		for _, scope := range []string{"", "tenant"} {
			submit("packet-limit/"+scope+"/"+node, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: node, Capacity: workload.Resources{CPU: 1e9, Memory: 256 << 20}, Networks: 4, MaxConsumers: 8, PacketQueuePackets: 32, PacketQueueBytes: 128 << 10})
		}
	}
	resources, e := p.Resources(read())
	if e != nil {
		t.Fatal(e)
	}
	definition := tenancy.TUNDefinition{Tenant: "tenant", Name: "existing"}
	for i, node := range []string{"node-a", "node-b"} {
		prefix, gateway, address := "10.199.0.0/24", "10.199.0.1", "10.199.2.1/32"
		if i == 1 {
			prefix, gateway, address = "10.199.1.0/24", "10.199.1.1", "10.199.2.2/32"
		}
		definition.Members = append(definition.Members, tenancy.TUNNode{Node: node, Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix(prefix), Gateway: netip.MustParseAddr(gateway), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix(address)}})
	}
	submit("managed-tunnel-network", "create-tun-network", resources.Networks.Revision(), definition)
	doc := []byte("name: app\nservices:\n web:\n  image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n  cpus: 0.1\n  mem_limit: 16m\n  networks: {app: {ipv4_address: 10.199.0.10}}\n  x-mydc: {node: node-a}\n db:\n  image: docker.io/library/mysql@sha256:" + strings.Repeat("b", 64) + "\n  cpus: 0.1\n  mem_limit: 16m\n  networks: {app: {ipv4_address: 10.199.1.10}}\n  x-mydc: {node: node-b}\nnetworks:\n app: {external: true, name: existing}\n")
	raw, e := c.StreamAppPlan(ctx, target, session, "tenant", control.AppPlanRequest{Document: doc})
	if e != nil {
		t.Fatal(e)
	}
	plan, e := deployment.DecodeBlueprint(raw)
	if e != nil {
		t.Fatal(e)
	}
	if len(plan.Steps()) != 4 {
		t.Fatal("two tasks must borrow the two managed sources", len(plan.Steps()))
	}
	for _, step := range plan.Steps() {
		if step.Kind != "task" && step.Kind != "network-ref" {
			t.Fatal("app owns a management source", step.Kind)
		}
	}
	submit("tun-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "app", ID: "tunnel-artifact", Length: len(raw), Digest: sha256.Sum256(raw)})
	submit("tun-part", "put-app-part", 1, control.AppUploadPart{Tenant: "tenant", ID: "tunnel-artifact", Data: raw})
	submit("tun-begin", "begin-app", 0, control.AppBegin{Tenant: "tenant", App: "app", Deployment: "app", Upload: "tunnel-artifact", Operation: "rollout"})
	owner := func(step deployment.Step) *Runtime {
		if step.Owner == leader.Identity.Public {
			return leader
		}
		if step.Owner == follower.Identity.Public {
			return follower
		}
		t.Fatal("unknown committed owner")
		return nil
	}
	projected, e := p.ProjectResources(read())
	if e != nil {
		t.Fatal(e)
	}
	views, e := managedTunnelViews(p.Cluster, read(), projected)
	if e != nil || len(views) != 1 {
		t.Fatal("current managed topology", e, len(views))
	}
	var topology network.TunnelTopology
	for _, view := range views {
		topology = view.Topology
	}
	var tunnels []deployment.Step
	for key, source := range projected.ManagedSources {
		if source.Tunnel != nil {
			tunnels = append(tunnels, deployment.Step{Key: key, Kind: "tunnel", Node: source.Network.Node, Owner: source.Network.Owner})
		}
	}
	if len(tunnels) != 2 {
		t.Fatal("missing bilateral managed sources", len(tunnels))
	}
	for _, step := range tunnels {
		g := projected.ManagedSources[step.Key]
		if g.Tunnel == nil {
			t.Fatal("native typed mapper absent")
		}
		o := read().Object(step.Key)
		req := control.NativeRequest{Source: deployment.ObjectRef{Key: step.Key, Generation: o.Generation, Revision: o.Revision}}
		body, _ := json.Marshal(req)
		reply, e := owner(step).appCall(ctx, "app-native-permit", body)
		if e != nil {
			t.Fatal("actual current owner permit", e)
		}
		var permit control.NativePermit
		if json.Unmarshal(reply.Data, &permit) != nil || permit.Source != req.Source || permit.Kind != "tunnel" || permit.PacketLimits == nil || permit.PacketLimits.QueuePackets != 32 || permit.PacketLimits.QueueBytes != 128<<10 || permit.MaxConsumers != 8 {
			t.Fatal("packet permit binding")
		}
		native := *g.Tunnel
		native.Lifecycle = schema.Lifecycle{}
		spec, _ := json.Marshal(native)
		if permit.Spec != sha256.Sum256(spec) {
			t.Fatal("permit changed original native spec")
		}
		other := leader
		if owner(step) == leader {
			other = follower
		}
		if _, e = other.appCall(ctx, "app-native-permit", body); e == nil {
			t.Fatal("other member acquired native owner permit")
		}
		bad := req
		bad.Source.Revision++
		badBody, _ := json.Marshal(bad)
		if _, e = owner(step).appCall(ctx, "app-native-permit", badBody); e == nil {
			t.Fatal("stale source acquired native permit")
		}
	}
	for _, step := range tunnels {
		if peers, e := topology.Peers(step.Key); e != nil || len(peers) != 1 {
			t.Fatal("opposite committed topology", e)
		}
	}
	// A runtime quota edit changes admission, never the original TUN Goal/ref.
	resources, _ = p.Resources(read())
	limit, _ := resources.Quotas.Limit("", "node-a")
	revision := limit.Revision
	limit.Revision = 0
	limit.PacketQueuePackets, limit.PacketQueueBytes = 0, 0
	submit("disable-packet-capacity", "set-node-quota", revision, limit)
	var local deployment.Step
	for _, step := range tunnels {
		if step.Node == "node-a" {
			local = step
		}
	}
	o := read().Object(local.Key)
	body, _ := json.Marshal(control.NativeRequest{Source: deployment.ObjectRef{Key: local.Key, Generation: o.Generation, Revision: o.Revision}})
	if _, e = leader.appCall(ctx, "app-native-permit", body); e == nil {
		t.Fatal("zero packet capacity admitted new native effect")
	}
	if after := read().Object(local.Key); after != o {
		t.Fatal("quota edit changed original Goal")
	}
	if e = leader.Engine().Snapshot(ctx); e != nil {
		t.Fatal(e)
	}
	t.Log("actual two Runtime/MYDCP member RPC/Raft/FSM/bbolt: named managed network -> bilateral original TUN sources/native current-owner packet permit, foreign/stale source denied, runtime quota-zero denial; management source/admission metadata only; no Docker/TUN/packet readiness claimed")
}
