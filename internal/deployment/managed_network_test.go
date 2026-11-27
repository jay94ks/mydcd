// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"maps"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

func managedNetworkFixture(t *testing.T) (*fixture, Compose, PlanningContext) {
	t.Helper()
	f := makeFixture(t)
	c := smallCompose(t)
	ctx := contextFor(t, f)
	ctx.Features["network-reference"] = true
	quotas, _ := tenancy.NewQuotas(f.cluster)
	for _, scope := range []string{"", "tenant"} {
		for _, node := range []string{"node-a", "node-b"} {
			var err error
			quotas, err = quotas.Set(f.c, "admin", 0, tenancy.NodeLimit{Tenant: scope, Node: node, Owner: ctx.Nodes[node].Key, Networks: 4, Capacity: workload.Resources{CPU: 4e9, Memory: 4 << 30}, MaxConsumers: 8, PacketQueuePackets: 8, PacketQueueBytes: 16384}, ctx.Networks)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	d := tenancy.TUNDefinition{Tenant: "tenant", Name: "shared-services", Members: []tenancy.TUNNode{}}
	for _, node := range []string{"node-a", "node-b"} {
		declared := c.Networks["app"].Sfc
		pool := declared.Pools[node]
		d.Members = append(d.Members, tenancy.TUNNode{Node: node, Owner: ctx.Nodes[node].Key, Pools: []tenancy.Subnet{{ID: "pool", Prefix: mustPrefix(pool.CIDR), Gateway: mustAddr(pool.Gateway), MTU: declared.MTU}}})
	}
	var err error
	ctx.Networks, err = ctx.Networks.CreateTUN(f.c, quotas, "alice", 0, d)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ctx.Networks.TUNSources("tenant", d.Name)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Current = map[string]state.Object{}
	for _, row := range rows {
		raw, _ := json.Marshal(row.Bridge)
		ctx.Current[row.BridgeKey] = state.Object{Present: true, Revision: 31, Generation: 17, Value: string(raw)}
		raw, _ = json.Marshal(row.Tunnel)
		ctx.Current[row.TunnelKey] = state.Object{Present: true, Revision: 32, Generation: 18, Value: string(raw)}
	}
	c.Networks = map[string]ComposeNetwork{"app": {External: true, Name: d.Name}}
	return f, c, ctx
}

func frozenManagedGoals(t *testing.T, b Blueprint, current map[string]state.Object) map[string]state.Object {
	t.Helper()
	objects := maps.Clone(current)
	if objects == nil {
		objects = map[string]state.Object{}
	}
	for i, step := range b.Steps() {
		objects[step.Key] = state.Object{Present: true, Generation: uint64(i + 100), Revision: uint64(i + 100)}
	}
	for _, step := range b.Steps() {
		g := GoalCommand{Schema: 1, Cluster: b.d.Cluster, Tenant: b.d.Tenant, App: b.d.App, Deployment: b.d.Deployment, Kind: step.Kind, Node: step.Node, Owner: step.Owner, Config: step.Goal}
		if step.Kind == "ingress" {
			g.Follow = append([]string(nil), step.Identity...)
		}
		for _, dep := range step.Dependencies {
			if ingressIdentity(step, dep.Key) {
				continue
			}
			o := objects[dep.Key]
			g.Dependencies = append(g.Dependencies, ObjectRef{Key: dep.Key, Generation: o.Generation, Revision: o.Revision})
		}
		o := objects[step.Key]
		raw, _ := json.Marshal(g)
		o.Value = string(raw)
		objects[step.Key] = o
	}
	return objects
}

func TestP0ManagedNetworkAppReferencesFreezeGroupAndGenericReturnRoutes(t *testing.T) {
	f, c, ctx := managedNetworkFixture(t)
	before, _ := ctx.Networks.Encode()
	b, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	var refs []NetworkReference
	for _, step := range b.Steps() {
		if step.Kind == "bridge" || step.Kind == "tunnel" || step.Kind == "dns" {
			t.Fatal("app took ownership of managed infrastructure")
		}
		if step.Kind == "network-ref" {
			var ref NetworkReference
			if json.Unmarshal(step.Goal, &ref) != nil || ref.Check(ctx) != nil || ref.ManagedName != "shared-services" || ref.PacketNetwork != "tenant/tenant/network/shared-services" || len(ref.ManagedSources) != 4 || len(ref.Routes) != 2 || ref.Network == ref.ManagedName {
				t.Fatal("logical/native source scope was not frozen")
			}
			refs = append(refs, ref)
			bridge, err := ReferenceBridge(f.cluster, ref, ctx.Current)
			if err != nil {
				t.Fatal(err)
			}
			service := "web"
			if ref.Node == "node-b" {
				service = "db"
			}
			declared := c.Services[service]
			spec := workload.ContainerSpec{Node: engine.Owner(f.cluster, ref.Owner)}
			material := TaskMaterial{Network: ref.Source, Bridge: bridge, Binding: Binding{d: bindingRecord{Needs: Needs{Generation: 19}}}}
			if err := b.taskNetwork(service, declared, material, &spec); err != nil || len(spec.Routes) != 2 {
				t.Fatal("remote pool/TUN-host return routes missing", err)
			}
		}
	}
	if len(refs) != 2 {
		t.Fatal("not one app reference per service node")
	}
	after, _ := ctx.Networks.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("planning changed the management reservation")
	}
	encoded, _ := b.Encode()
	restored, err := DecodeBlueprint(encoded)
	if err != nil || restored.ValidateCurrent(f.c, ctx) != nil {
		t.Fatal("artifact lost exact group references", err)
	}
	changed := ctx
	changed.Current = maps.Clone(ctx.Current)
	remote := refs[0].ManagedSources[len(refs[0].ManagedSources)-1].Source.Key
	o := changed.Current[remote]
	o.Revision++
	changed.Current[remote] = o
	if refs[0].Check(changed) == nil || b.ValidateCurrent(f.c, changed) == nil {
		t.Fatal("changed remote generation was silently rebound")
	}
	if _, err := ReferenceBridge(f.cluster, refs[0], changed.Current); err == nil {
		t.Fatal("frozen material read ignored a remote source revision")
	}
}

func TestP0ManagedNetworkRemoteIngressUsesOriginalBorrowedSources(t *testing.T) {
	f, c, ctx := managedNetworkFixture(t)
	i := &IngressDeclaration{Node: "node-b", Host: "generic.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.12:8080"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}}
	i.Backend.Service, i.Backend.Port, i.Backend.HealthPath = "web", 8080, "/readyz"
	c.Sfc.Ingress = i
	b, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	objects := frozenManagedGoals(t, b, ctx.Current)
	key := ResourceKey("ingress", "tenant", c.Name, "http")
	spec, err := ResolveIngress(f.cluster, key, objects[key], objects)
	if err != nil || spec.Services[0].Backends[0].Network != "tenant/tenant/network/shared-services" {
		t.Fatal("remote borrowed network is not an ingress dependency", err)
	}
	for source := range ctx.Current {
		bad := maps.Clone(objects)
		o := bad[source]
		o.Generation++
		bad[source] = o
		if _, err := ResolveIngress(f.cluster, key, objects[key], bad); err == nil {
			t.Fatal("changed management source accepted", source)
		}
	}
	// A node that hosts only the listener must still get its own app borrow.
	delete(c.Services, "db")
	c.Volumes = nil
	web := c.Services["web"]
	web.DependsOn = nil
	c.Services["web"] = web
	b, err = CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, step := range b.Steps() {
		found = found || step.Kind == "network-ref" && step.Node == "node-b"
	}
	if !found {
		t.Fatal("listener-only node omitted its managed network borrow")
	}
	// Rename the sample service/app and backend port through the same core.
	delete(c.Services, "web")
	c.Services["api"] = web
	c.Name, ctx.Project = "generic-app", "generic-app"
	c.Sfc.Ingress.Backend.Service, c.Sfc.Ingress.Backend.Port = "api", 9090
	b, err = CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	objects = frozenManagedGoals(t, b, ctx.Current)
	key = ResourceKey("ingress", "tenant", "generic-app", "http")
	spec, err = ResolveIngress(f.cluster, key, objects[key], objects)
	if err != nil || spec.Services[0].Backends[0].Task != ResourceKey("task", "tenant", "generic-app", "api") || spec.Services[0].Backends[0].Port != 9090 {
		t.Fatal("renamed generic app did not use the same source contract", err)
	}
}
