// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
)

func replicaFixture(t *testing.T) (*fixture, Compose, PlanningContext) {
	t.Helper()
	f, c, ctx := managedNetworkFixture(t)
	web := c.Services["web"]
	web.Sfc.Node, web.Sfc.Nodes, web.Sfc.PerNode = "", []string{"node-a", "node-b"}, 1
	attachment := web.Networks["app"]
	attachment.IPv4, attachment.IPv6 = "", ""
	web.Networks["app"] = attachment
	c.Services["web"] = web
	ctx.Features["managed-dns"] = true
	source := services.ManagedDNSSource{Schema: 1, Cluster: f.cluster, Principal: "alice", Definition: services.ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: "shared-services", Policy: services.ManagedDNSPolicy{Enabled: true, Zone: "apps.sfc.test."}}}
	raw, _ := json.Marshal(source)
	ctx.Current[services.ManagedDNSKey("tenant", "shared-services")] = state.Object{Present: true, Generation: 41, Revision: 43, Value: string(raw)}
	return f, c, ctx
}

func TestReplicaPlanFreezesIndependentTasksInputsAndCapacity(t *testing.T) {
	f, c, ctx := replicaFixture(t)
	original, _ := json.Marshal(c)
	b, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	steps := stepMap(b)
	var addresses []string
	var bindings []Binding
	for _, node := range []string{"node-a", "node-b"} {
		id := (TaskInstance{Service: "web", Node: node, Ordinal: 1}).ResourceID()
		key := ResourceKey("task", "tenant", "php-mysql", id)
		step, exists := steps[key]
		if !exists || step.Node != node || step.Owner != ctx.Nodes[node].Key || step.Completion != Healthy {
			t.Fatal("instance identity or owner not frozen", step)
		}
		for _, dependency := range step.Dependencies {
			for _, other := range []string{"node-a", "node-b"} {
				otherID := (TaskInstance{Service: "web", Node: other, Ordinal: 1}).ResourceID()
				if dependency.Key == ResourceKey("task", "tenant", "php-mysql", otherID) {
					t.Fatal("rollout ordering became a replica lifetime dependency")
				}
			}
		}
		service, logical, err := b.TaskInput(id)
		if err != nil || logical != "web" || service.Sfc.Node != node || service.Sfc.Instance == nil || len(service.Sfc.Nodes) != 0 || len(service.DNS) != 1 || len(service.DNSSearch) != 2 || service.DNSSearch[0] != "php-mysql.apps.sfc.test." {
			t.Fatal("logical declaration confused with native recipe", service, err)
		}
		addresses = append(addresses, service.Networks["app"].IPv4)
		need, err := b.Inputs(id, "test-consumer", 10, public(private(30)))
		if err != nil || need.Use.Service != "web" || need.Use.Node != node || need.Instance == nil || need.Instance.ResourceID() != id {
			t.Fatal("secret use lost logical identity or exact consumer", need, err)
		}
		binding := Binding{d: bindingRecord{Needs: need}}
		if projectionTask(binding) != key || projectionKey(binding) != ResourceKey("inputs", "tenant", "php-mysql", id) {
			t.Fatal("projection aliases another replica")
		}
		bindings = append(bindings, binding)
	}
	if addresses[0] == "" || addresses[1] == "" || addresses[0] == addresses[1] || projectionKey(bindings[0]) == projectionKey(bindings[1]) {
		t.Fatal("replicas reused an address or projection")
	}
	after, _ := json.Marshal(c)
	if !bytes.Equal(original, after) {
		t.Fatal("planning changed original input")
	}
	raw, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeBlueprint(raw)
	if err != nil || restored.ValidateCurrent(f.c, ctx) != nil {
		t.Fatal("replica metadata did not survive the ordinary artifact path", err)
	}
	// Reservations include every replica's resource demand on its actual node.
	limited := ctx
	limited.Nodes = maps.Clone(ctx.Nodes)
	node := limited.Nodes["node-b"]
	node.Capacity.CPU = 1e9 // database already needs this whole capacity
	limited.Nodes["node-b"] = node
	if _, err := CompileApp(c, f.c, limited); err == nil {
		t.Fatal("replica bypassed aggregate node capacity")
	}
}

func TestReplicaPlacementRejectsWriterStaticAddressAndUnmanagedDNS(t *testing.T) {
	f, c, ctx := replicaFixture(t)
	for _, mutate := range []func(*Compose){
		func(c *Compose) {
			s := c.Services["db"]
			s.Sfc.Node = ""
			s.Sfc.Nodes = []string{"node-a", "node-b"}
			c.Services["db"] = s
		},
		func(c *Compose) {
			s := c.Services["web"]
			a := s.Networks["app"]
			a.IPv4 = "10.240.10.10"
			s.Networks["app"] = a
			c.Services["web"] = s
		},
		func(c *Compose) { s := c.Services["web"]; s.Sfc.Node = "node-a"; c.Services["web"] = s },
		func(c *Compose) {
			s := c.Services["web"]
			s.Sfc.Nodes = []string{"node-a", "node-a"}
			c.Services["web"] = s
		},
		func(c *Compose) { s := c.Services["web"]; s.Sfc.PerNode = 65; c.Services["web"] = s },
	} {
		raw, _ := json.Marshal(c)
		var changed Compose
		_ = json.Unmarshal(raw, &changed)
		mutate(&changed)
		if _, err := CompileApp(changed, f.c, ctx); err == nil {
			t.Fatal("invalid replica placement accepted")
		}
	}
	ctx.Current = maps.Clone(ctx.Current)
	delete(ctx.Current, services.ManagedDNSKey("tenant", "shared-services"))
	if _, err := CompileApp(c, f.c, ctx); err == nil {
		t.Fatal("promised cross-node alias without managed DNS")
	}
}

func TestReplicaIngressUsesEveryExactBackendAndNetworkDependency(t *testing.T) {
	f, c, ctx := replicaFixture(t)
	i := &IngressDeclaration{Node: "node-a", Host: "app.test", Listeners: []ListenerDeclaration{{Address: "192.0.2.11:8080"}}, Runtime: IngressRuntime{MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100}}
	i.Backend.Service, i.Backend.Port, i.Backend.HealthPath = "web", 8080, "/readyz"
	c.Sfc.Ingress = i
	b, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.NetworkConsumers(); err != nil {
		t.Fatal("replica consumer projection failed", err)
	}
	// This is the same dependency-closure algorithm used by real retirement,
	// with fake claims only as model inputs. Rollout order must not make the
	// second replica a lifetime consumer of the first one.
	inventory, _ := NewInventory(f.cluster, "tenant", "php-mysql", "deploy")
	for _, step := range b.Steps() {
		inventory.d.Claims = append(inventory.d.Claims, Claim{Step: step})
	}
	firstID := (TaskInstance{Service: "web", Node: "node-a", Ordinal: 1}).ResourceID()
	secondID := (TaskInstance{Service: "web", Node: "node-b", Ordinal: 1}).ResourceID()
	selected, err := inventory.retirementSelection([]string{ResourceKey("task", "tenant", "php-mysql", firstID)}, false)
	if err != nil || selected[ResourceKey("task", "tenant", "php-mysql", secondID)] || !selected[ResourceKey("inputs", "tenant", "php-mysql", firstID)] || selected[ResourceKey("ingress", "tenant", "php-mysql", "http")] {
		t.Fatal("single replacement lost its own pins or retired another replica", selected, err)
	}
	objects := frozenManagedGoals(t, b, ctx.Current)
	key := ResourceKey("ingress", "tenant", "php-mysql", "http")
	spec, err := ResolveIngress(f.cluster, key, objects[key], objects)
	if err != nil || !spec.DynamicBackends || len(spec.Services) != 1 || len(spec.Services[0].Backends) != 2 {
		t.Fatal("ingress omitted a replica", err)
	}
	backends := spec.Services[0].Backends
	if backends[0].Task == backends[1].Task || backends[0].ID == backends[1].ID || backends[0].Address == backends[1].Address {
		t.Fatal("backends share native identity")
	}
	for _, backend := range backends {
		bad := maps.Clone(objects)
		object := bad[backend.Task]
		object.Revision++
		bad[backend.Task] = object
		current, err := ResolveIngress(f.cluster, key, objects[key], bad)
		if err != nil {
			t.Fatal("current replica metadata required replacing the listener", err)
		}
		for _, bound := range current.Services[0].Backends {
			if bound.Task == backend.Task && bound.Revision != object.Revision {
				t.Fatal("backend did not follow its current exact revision")
			}
		}
	}
	missing := maps.Clone(objects)
	delete(missing, backends[0].Task)
	remaining, err := ResolveIngress(f.cluster, key, objects[key], missing)
	if err != nil || len(remaining.Services[0].Backends) != 1 || remaining.Services[0].Backends[0].Task != backends[1].Task {
		t.Fatal("one positively absent Task removed the healthy listener/peer", err)
	}
	var goal GoalCommand
	_ = json.Unmarshal([]byte(objects[key].Value), &goal)
	foreignKey := ResourceKey("task", "tenant", "php-mysql", "db")
	foreign := objects[foreignKey]
	goal.Dependencies = append(goal.Dependencies, ObjectRef{Key: foreignKey, Generation: foreign.Generation, Revision: foreign.Revision})
	object := objects[key]
	raw, _ := json.Marshal(goal)
	object.Value = string(raw)
	if _, err := ResolveIngress(f.cluster, key, object, objects); err == nil {
		t.Fatal("another service was accepted into this backend group")
	}
}

func TestTaskInstanceIdentityAndProjectionCannotBeForged(t *testing.T) {
	for _, instance := range []TaskInstance{{Service: "web", Node: "node-a"}, {Service: "web", Node: "node-a", Ordinal: 1}, {Service: "web", Node: "node-b", Ordinal: 128}} {
		service := ComposeService{Sfc: ServiceExtension{Node: instance.Node}}
		if instance.Ordinal != 0 {
			copy := instance
			service.Sfc.Instance = &copy
		}
		key := ResourceKey("task", "tenant", "sample", instance.ResourceID())
		actual, err := TaskInstanceForKey("tenant", "sample", key, service)
		if err != nil || actual != instance {
			t.Fatal("valid identity refused", instance, err)
		}
		service.Sfc.Node = "other"
		if _, err := TaskInstanceForKey("tenant", "sample", key, service); err == nil && instance.Ordinal != 0 {
			t.Fatal("replica metadata allowed owner-node substitution")
		}
		if _, err := TaskInstanceForKey("other", "sample", key, service); err == nil {
			t.Fatal("foreign tenant identity accepted")
		}
	}
	if (TaskInstance{Service: "web", Node: "node-a", Ordinal: 129}).ResourceID() != "" {
		t.Fatal("unbounded ordinal")
	}
}

func TestReplicaReadOnlyFixedVolumeIsStillRejected(t *testing.T) {
	f, c, ctx, _ := fixedAppFixture(t)
	service := c.Services["db"]
	service.Sfc.Node, service.Sfc.Nodes, service.Sfc.PerNode = "", []string{"node-b"}, 2
	for index := range service.Volumes {
		service.Volumes[index].ReadOnly = true
	}
	attachment := service.Networks["app"]
	attachment.IPv4, attachment.IPv6 = "", ""
	service.Networks["app"] = attachment
	c.Services["db"] = service
	_, err := Compile(c, f.c, ctx)
	var input *InputError
	if !errors.As(err, &input) || input.Code != "REPLICA_FIXED_VOLUME_FORBIDDEN" {
		t.Fatal("read-only mount bypassed the fixed Volume replica contract", err)
	}
}

func TestReplicaOrdinalsOnOneNodeKeepSeparateOwnedNeeds(t *testing.T) {
	f, c, ctx := replicaFixture(t)
	web := c.Services["web"]
	web.Sfc.Nodes, web.Sfc.PerNode = []string{"node-a"}, 2
	c.Services["web"] = web
	b, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := b.Inputs("web/node-a/r1", "first", 10, public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.Inputs("web/node-a/r2", "second", 11, public(private(30)))
	if err != nil || !useEqual(first.Use, second.Use) || first.Instance == nil || second.Instance == nil || first.Instance.Ordinal != 1 || second.Instance.Ordinal != 2 {
		t.Fatal("ordinal changed logical permission or reused the wrong Task", err)
	}
	copy := ownNeeds(first)
	copy.Instance.Ordinal = 2
	if first.Instance.Ordinal != 1 || !validInputMetadata(first) {
		t.Fatal("returned metadata aliases the original instance")
	}
	copy.Instance.Node = "node-b"
	if validInputMetadata(copy) {
		t.Fatal("projection instance owner differs from its authorized use")
	}
	left, _, _ := b.TaskInput("web/node-a/r1")
	right, _, _ := b.TaskInput("web/node-a/r2")
	if left.Networks["app"].IPv4 == right.Networks["app"].IPv4 {
		t.Fatal("same-node ordinals reused a static address")
	}
	uses, err := b.ApprovalUses(public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	webUses := 0
	for _, use := range uses["tenant"] {
		if use.Service == "web" && use.Node == "node-a" {
			webUses++
		}
	}
	if webUses != 1 {
		t.Fatal("same logical approval requested repeatedly for ordinals", webUses)
	}
	// Approval/password selection is shared, but reservation is per actual
	// consumer and generation in the ordinary Bindings/Approvals core.
	f.approveAll(first, second)
	reserved := f.reserve(first, second)
	if len(reserved.Bindings) != 2 || reserved.Bindings[0].Digest() == reserved.Bindings[1].Digest() || len(f.bindings.Live()) != 2 {
		t.Fatal("replica secret usage collapsed into one consumer")
	}
	if _, err := b.Inputs("web", "ambiguous", 10, public(private(30))); err == nil {
		t.Fatal("logical name silently selected one concrete replica")
	}
}
