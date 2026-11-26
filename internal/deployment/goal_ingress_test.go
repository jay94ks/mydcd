// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestIngressGoalBindsOriginalTaskNetworkAndRemoteLifetime(t *testing.T) {
	f := makeFixture(t)
	c := smallCompose(t)
	i := &IngressDeclaration{Node: "node-b", Host: "app.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.12:8080"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}}
	i.Backend.Service = "web"
	i.Backend.Port = 8080
	i.Backend.HealthPath = "/readyz"
	c.MyDC.Ingress = i
	b, err := Compile(c, f.c, contextFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string]state.Object{}
	for n, step := range b.Steps() {
		objects[step.Key] = state.Object{Present: true, Generation: uint64(n + 10), Revision: uint64(n + 10)}
	}
	for _, step := range b.Steps() {
		g := GoalCommand{Schema: 1, Cluster: b.d.Cluster, Tenant: b.d.Tenant, App: b.d.App, Deployment: b.d.Deployment, Kind: step.Kind, Node: step.Node, Owner: step.Owner, Config: step.Goal}
		for _, dep := range step.Dependencies {
			v := objects[dep.Key]
			g.Dependencies = append(g.Dependencies, ObjectRef{Key: dep.Key, Generation: v.Generation, Revision: v.Revision})
		}
		v := objects[step.Key]
		raw, _ := json.Marshal(g)
		v.Value = string(raw)
		objects[step.Key] = v
	}
	key := ResourceKey("ingress", b.d.Tenant, b.d.App, "http")
	o := objects[key]
	spec, err := ResolveIngress(b.d.Cluster, key, o, objects)
	if err != nil || spec.Services[0].Backends[0].Task != ResourceKey("task", b.d.Tenant, b.d.App, "web") || spec.Services[0].Backends[0].Network != "tenant/php-mysql/app" || len(spec.Listeners) != 1 || spec.MaxRequests != 2 {
		t.Fatal("original remote spec", err)
	}
	var original GoalCommand
	_ = json.Unmarshal([]byte(o.Value), &original)
	if len(original.Dependencies) != 3 {
		t.Fatal("remote TUNs are not lifetime dependencies")
	}
	for _, mutate := range []func(*GoalCommand){func(g *GoalCommand) { g.Dependencies[0].Revision++ }, func(g *GoalCommand) { g.Dependencies = g.Dependencies[:1] }, func(g *GoalCommand) { g.Tenant = "foreign" }, func(g *GoalCommand) { g.Owner = [32]byte{99} }, func(g *GoalCommand) {
		var i IngressDeclaration
		_ = json.Unmarshal(g.Config, &i)
		i.Backend.Network = "foreign"
		g.Config, _ = json.Marshal(i)
	}} {
		g := original
		g.Dependencies = slices.Clone(original.Dependencies)
		mutate(&g)
		bad := o
		raw, _ := json.Marshal(g)
		bad.Value = string(raw)
		if _, err := ResolveIngress(b.d.Cluster, key, bad, objects); err == nil {
			t.Fatal("accepted foreign/stale/partial ingress source")
		}
	}
	bad := maps.Clone(objects)
	task := bad[spec.Services[0].Backends[0].Task]
	var g GoalCommand
	_ = json.Unmarshal([]byte(task.Value), &g)
	g.Dependencies[0].Revision++
	raw, _ := json.Marshal(g)
	task.Value = string(raw)
	bad[spec.Services[0].Backends[0].Task] = task
	if _, err := ResolveIngress(b.d.Cluster, key, o, bad); err == nil {
		t.Fatal("stale task network source accepted")
	}
	c.MyDC.Ingress.Runtime = IngressRuntime{}
	if _, err := Compile(c, f.c, contextFor(t, f)); err == nil {
		t.Fatal("empty runtime demand was granted")
	}
}

func TestMultipleIngressRoutesConsumeFixedSingletonAndFollowedReplicas(t *testing.T) {
	f, c, ctx := replicaFixture(t)
	i := &IngressDeclaration{Node: "node-a", Listeners: []ListenerDeclaration{{Shared: "https"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}, Routes: []IngressRouteDeclaration{{ID: "web", Host: "app.test", Prefix: "/", Service: "web", Network: "app", Port: 8080, HealthPath: "/readyz"}, {ID: "db", Host: "app.test", Prefix: "/db", Service: "db", Network: "app", Port: 3306, HealthPath: "/"}}}
	c.MyDC.Ingress = i
	b, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	objects := frozenManagedGoals(t, b, ctx.Current)
	key := ResourceKey("ingress", "tenant", "php-mysql", "http")
	spec, err := ResolveIngress(f.cluster, key, objects[key], objects)
	if err != nil || len(spec.Services) != 2 || len(spec.Services[0].Backends) != 2 || len(spec.Services[1].Backends) != 1 {
		t.Fatal("mixed fixed/followed backend union rejected", spec, err)
	}
	fixed := spec.Services[1].Backends[0]
	if fixed.Revision != objects[fixed.Task].Revision || fixed.Revision < fixed.Generation {
		t.Fatal("fixed backend lost its accepted source revision in the dynamic snapshot")
	}
	if spec.Services[0].Backends[0].ID == spec.Services[1].Backends[0].ID {
		t.Fatal("route-specific durable leases share an identity")
	}
	var command GoalCommand
	json.Unmarshal([]byte(objects[key].Value), &command)
	found := false
	for _, ref := range command.Dependencies {
		if ref.Key == spec.Services[1].Backends[0].Task {
			found = true
		}
	}
	if !found || len(command.Follow) != 2 {
		t.Fatal("singleton lifetime pin or exact replica follow set missing", command)
	}
	changed := maps.Clone(objects)
	singleton := changed[spec.Services[1].Backends[0].Task]
	singleton.Revision++
	changed[spec.Services[1].Backends[0].Task] = singleton
	if _, err := ResolveIngress(f.cluster, key, objects[key], changed); err == nil {
		t.Fatal("singleton silently followed an unaccepted revision")
	}
}
