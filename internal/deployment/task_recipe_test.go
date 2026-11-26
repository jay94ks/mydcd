// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/ed25519"
	"encoding/json"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func taskMaterialFixture(t *testing.T) (*fixture, Blueprint, TaskMaterial) {
	return taskMaterialFixtureWith(t, nil)
}

func taskMaterialFixtureWith(t *testing.T, configure func(*Compose)) (*fixture, Blueprint, TaskMaterial) {
	t.Helper()
	return taskMaterialFixtureIn(t, makeFixture(t), configure, nil)
}

func taskMaterialFixtureIn(t *testing.T, f *fixture, configure func(*Compose), plan func(*PlanningContext)) (*fixture, Blueprint, TaskMaterial) {
	t.Helper()
	old := f.v["tenant/php-mysql/mysql-data"]
	native := volumes.NativeSpec{Schema: 1, Scope: old.Scope(), Node: "node-b", NodeKey: public(f.nb), Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	raw, _ := json.Marshal(native)
	c := engine.Client{Owner: engine.Owner(f.cluster, native.NodeKey)}
	id, err := c.Identity("volume", volumes.NativeKey(native), reconcile.Resource{Present: true, Generation: 2, Spec: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	ready := volumes.NativeReady{Schema: 1, Spec: native, Generation: 2, Owner: volumes.Owner{Node: native.Node, Key: native.NodeKey, Native: id.Name}}
	ready.Signature = ed25519.Sign(f.nb, volumes.NativeReadyBytes(ready))
	core, err := volumes.New(f.c, "alice", native.Scope, ready.Owner, 2)
	if err != nil {
		t.Fatal(err)
	}
	f.v[VolumeKey(native.Scope)] = core
	input := smallCompose(t)
	s := input.Services["db"]
	s.Tmpfs = []string{"/cache:size=4m,uid=10001,gid=10001,mode=0700"}
	input.Services["db"] = s
	if configure != nil {
		configure(&input)
	}
	ctx := contextFor(t, f)
	if plan != nil {
		plan(&ctx)
	}
	b, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	needs, err := b.Inputs("db", "database", 11, public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	f.approveAll(needs)
	bound := f.reserve(needs).Bindings[0]
	ref := projectionReference(bound)
	netID := PoolID("tenant", "php-mysql", "app", "node-b")
	bridge := network.BridgeSpec{Schema: 1, Network: netID, Owner: c.Owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "pool", Network: netID, Owner: c.Owner, Prefix: netip.MustParsePrefix("10.240.20.0/24"), Gateway: netip.MustParseAddr("10.240.20.1"), MTU: 1280}}}
	return f, b, TaskMaterial{Binding: bound, Projection: &ref, Volumes: []volumes.NativeReady{ready}, Network: ObjectRef{ResourceKey("bridge", "tenant", "php-mysql", "app/node-b"), 10, 10}, Bridge: bridge}
}

func TestTaskRecipeRoutesStayInOriginalLogicalNetwork(t *testing.T) {
	_, b, material := taskMaterialFixture(t)
	_, spec, err := b.taskRecipe("db", material, material.Bridge.Owner)
	want := []workload.ContainerRoute{
		{Destination: netip.MustParsePrefix("10.240.10.0/24"), Gateway: netip.MustParseAddr("10.240.20.1")},
		{Destination: netip.MustParsePrefix("10.240.30.1/32"), Gateway: netip.MustParseAddr("10.240.20.1")},
	}
	if err != nil || !slices.Equal(spec.Routes, want) {
		t.Fatal("missing original remote overlay route", spec.Routes, err)
	}
	// Other declarations are not a route authority for this attachment.
	other := b.d.Input.Networks["app"]
	other.MyDC.Pools = maps.Clone(other.MyDC.Pools)
	remote := other.MyDC.Pools["node-a"]
	remote.CIDR, remote.Gateway = "198.18.90.0/24", "198.18.90.1"
	other.MyDC.Pools["node-a"] = remote
	b.d.Input.Networks["unattached"] = other
	_, again, err := b.taskRecipe("db", material, material.Bridge.Owner)
	if err != nil || !slices.Equal(again.Routes, want) {
		t.Fatal("unattached network injected routes", again.Routes, err)
	}
}

func cloneTaskMaterial(m TaskMaterial) TaskMaterial {
	m.Binding = Binding{ownBinding(m.Binding.d)}
	if m.Projection != nil {
		p := *m.Projection
		m.Projection = &p
	}
	m.Volumes = slices.Clone(m.Volumes)
	for i := range m.Volumes {
		m.Volumes[i].Signature = slices.Clone(m.Volumes[i].Signature)
	}
	m.Bridge.Pools = slices.Clone(m.Bridge.Pools)
	return m
}

func TestTaskRecipeOriginalBindingVolumeAndNetworkCorrespondence(t *testing.T) {
	f, b, material := taskMaterialFixture(t)
	_, spec, err := b.taskRecipe("db", material, material.Bridge.Owner)
	if err != nil || len(spec.Volumes) != 1 || spec.Volumes[0].Consumer != material.Binding.d.Pins[0].Consumer || spec.Volumes[0].NativeKey != volumes.NativeKey(material.Volumes[0].Spec) || spec.Volumes[0].Target != "/var/lib/mysql" || spec.BridgeGeneration != 10 || spec.IPv4.String() != "10.240.20.10" || len(spec.Tmpfs) != 1 || spec.Memory != 256<<20 || spec.NanoCPU != 1000000000 {
		t.Fatal("exact original recipe", spec, err)
	}
	material.Projection.Binding[0] ^= 1
	if spec.Inputs.Binding == material.Projection.Binding {
		t.Fatal("caller mutated resolved reference")
	}
	material = cloneTaskMaterial(material)
	material.Projection.Binding[0] ^= 1
	for i, mutate := range []func(*TaskMaterial){
		func(m *TaskMaterial) { m.Projection = nil },
		func(m *TaskMaterial) { m.Projection.Binding[0] ^= 1 },
		func(m *TaskMaterial) { m.Binding.d.Needs.Use.Service = "web" },
		func(m *TaskMaterial) { m.Binding.d.Needs.Generation++ },
		func(m *TaskMaterial) { m.Volumes = nil },
		func(m *TaskMaterial) { m.Volumes = append(m.Volumes, m.Volumes[0]) },
		func(m *TaskMaterial) { m.Volumes[0].Signature[0] ^= 1 },
		func(m *TaskMaterial) { m.Volumes[0].Spec.Materialization = "replacement" },
		func(m *TaskMaterial) { m.Binding.d.Pins[0].Consumer.Owner.Native = "foreign" },
		func(m *TaskMaterial) { m.Network.Key += "-other" },
		func(m *TaskMaterial) { m.Network.Generation = 0 },
		func(m *TaskMaterial) { m.Bridge.Owner = "foreign" },
		func(m *TaskMaterial) { m.Bridge.Pools[0].Gateway = netip.MustParseAddr("10.240.20.2") },
		func(m *TaskMaterial) { m.Bridge.Lifecycle.Drain = true },
	} {
		bad := cloneTaskMaterial(material)
		mutate(&bad)
		if _, _, err := b.taskRecipe("db", bad, engine.Owner(f.cluster, public(f.nb))); err == nil {
			t.Fatal("substituted recipe admitted", i)
		}
	}
}

func TestTaskRecipeExternalNetworkKeepsOriginalSource(t *testing.T) {
	f, input, ctx, source := externalFixture(t)
	input.Services["web"].MyDC.Readiness.Timeout = "3s"
	b, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	needs, err := b.Inputs("web", "web-task", 34, public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	f.approveAll(needs)
	bound := f.reserve(needs).Bindings[0]
	ref := projectionReference(bound)
	object := ctx.Current[source]
	bridge, err := network.DecodeBridge(object.Value)
	if err != nil {
		t.Fatal(err)
	}
	m := TaskMaterial{Binding: bound, Projection: &ref, Network: ObjectRef{source, object.Revision, object.Generation}, Bridge: bridge}
	_, spec, err := b.taskRecipe("web", m, bridge.Owner)
	if err != nil || spec.Bridge != source || spec.BridgeGeneration != object.Generation || spec.Readiness == nil || spec.Readiness.Path != "/readyz" || spec.Readiness.TimeoutMS != 3000 {
		t.Fatal("external source/readiness lost", err)
	}
	for _, mutate := range []func(*TaskMaterial){func(m *TaskMaterial) { m.Network.Generation++ }, func(m *TaskMaterial) { m.Network.Revision++ }, func(m *TaskMaterial) { m.Network.Key = ResourceKey("bridge", "other", "shared-app", "lan/node-a") }, func(m *TaskMaterial) { m.Bridge.Pools[0].Gateway = netip.MustParseAddr("10.240.10.2") }} {
		bad := cloneTaskMaterial(m)
		mutate(&bad)
		if _, _, err = b.taskRecipe("web", bad, bridge.Owner); err == nil {
			t.Fatal("external source changed under the original recipe")
		}
	}
	if ctx.Current[source] != object {
		t.Fatal("borrowed source changed")
	}
}

// A private registry login alone still projects inputs (the pull credential);
// the recipe must not read that projection as stray material.
func TestTaskRecipeAcceptsRegistryOnlyProjection(t *testing.T) {
	f := makeFixture(t)
	login := addRegistryInputFixture(t, f)
	_, b, material := taskMaterialFixtureIn(t, f, func(input *Compose) {
		s := input.Services["db"]
		s.Secrets, s.MyDC.Sources = nil, nil
		input.Services["db"] = s
	}, func(ctx *PlanningContext) {
		source := imagesource.Source{Tenant: "tenant", ID: "docker", Authority: "docker.io", Repository: "**", Enabled: true, Auth: "password", Credential: &imagesource.Credential{Realm: login.Realm, ID: login.Object, UsernameKey: "username", PasswordKey: "password"}}
		ctx.ExternalRegistries = []imagesource.Definition{{Spec: imagesource.Own(source)}}
	})
	needs := material.Binding.Needs()
	if len(needs.Sources) != 0 || len(needs.RegistrySources) != 1 || material.Projection == nil {
		t.Fatal("fixture is not registry-only", needs.Sources, needs.RegistrySources)
	}
	if _, spec, err := b.taskRecipe("db", material, material.Bridge.Owner); err != nil || spec.Inputs == nil {
		t.Fatal("registry-only projection rejected", err)
	}
	material.Projection = nil
	if _, _, err := b.taskRecipe("db", material, material.Bridge.Owner); err == nil || !strings.Contains(err.Error(), "db.projection") {
		t.Fatal("missing projection not named", err)
	}
}

// A Task rejected before its container existed still closes and releases its
// address; the proofs need a non-empty native ID on both sides.
func TestClosedNativeNamesNeverObservedTask(t *testing.T) {
	if got := (Claim{}).ClosedNative(); got != NeverObservedNative {
		t.Fatal("unobserved Task native", got)
	}
	if got := (Claim{Native: "abc"}).ClosedNative(); got != "abc" {
		t.Fatal("observed Task native replaced", got)
	}
}
