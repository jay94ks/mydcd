// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

func externalFixture(t *testing.T) (*fixture, Compose, PlanningContext, string) {
	t.Helper()
	f := makeFixture(t)
	c := smallCompose(t)
	s := c.Services["web"]
	s.DependsOn = nil
	c.Services = map[string]ComposeService{"web": s}
	c.Volumes = nil
	ctx := contextFor(t, f)
	ctx.Features["network-reference"] = true
	name := "shared-lan"
	source := ResourceKey("bridge", "tenant", "shared-app", "lan/node-a")
	var e error
	ctx.Networks, e = ctx.Networks.Create(f.c, "alice", ctx.Networks.Revision(), tenancy.Network{Tenant: "tenant", ID: name, Node: "node-a", Owner: public(f.na), Pools: []tenancy.Subnet{{ID: "pool", Prefix: mustPrefix("10.240.10.0/24"), Gateway: mustAddr("10.240.10.1"), MTU: 1280}}})
	if e != nil {
		t.Fatal(e)
	}
	publicKey := public(f.na)
	owner := hex.EncodeToString(f.cluster[:]) + "/" + hex.EncodeToString(publicKey[:])
	spec := network.BridgeSpec{Schema: 1, Network: name, Owner: owner, MTU: 1280, Pools: []network.Pool{{ID: "pool", Network: name, Owner: owner, Prefix: mustPrefix("10.240.10.0/24"), Gateway: mustAddr("10.240.10.1"), MTU: 1280}}}
	raw, _ := json.Marshal(spec)
	ctx.Current = map[string]state.Object{source: {Present: true, Revision: 31, Generation: 17, Value: string(raw)}}
	ctx.ExternalNetworks = map[string]map[string]NetworkBinding{"app": {"node-a": {NetworkID: name, SourceKey: source}}}
	c.Networks = map[string]ComposeNetwork{"app": {External: true, Name: name}}
	return f, c, ctx, source
}

func TestExternalNetworkDockerIPAMIsFrozenAndCannotBeStripped(t *testing.T) {
	f, c, ctx, source := externalFixture(t)
	ipam := network.PoolIPAM{Dynamic: mustPrefix("10.240.10.0/25")}
	n, _ := ctx.Networks.Network("tenant", "shared-lan")
	n.Generation, n.Revision = 0, 0
	n.Pools[0].IPAM = ipam
	ctx.Networks, _ = tenancy.New(f.cluster)
	var err error
	ctx.Networks, err = ctx.Networks.Create(f.c, "alice", 0, n)
	if err != nil {
		t.Fatal(err)
	}
	o := ctx.Current[source]
	b, err := network.DecodeBridge(o.Value)
	if err != nil {
		t.Fatal(err)
	}
	b.Pools[0].IPAM = ipam
	raw, _ := json.Marshal(b)
	o.Value = string(raw)
	ctx.Current[source] = o
	if _, err := Compile(c, f.c, ctx); err != nil {
		t.Fatal("ordinary static app cannot borrow reserved network", err)
	}
	ref, err := resolveNetworkReference(ctx, "tenant", "node-a", "shared-lan", NetworkBinding{"shared-lan", source})
	if err != nil || acceptsReferenceAddress(ref, "10.240.11.128") || !acceptsReferenceAddress(ref, "10.240.10.20") {
		t.Fatal("app reference lost reserved/static distinction", err)
	}
	b.Pools[0].IPAM = network.PoolIPAM{}
	raw, _ = json.Marshal(b)
	o.Value = string(raw)
	ctx.Current[source] = o
	if _, err := Compile(c, f.c, ctx); err == nil {
		t.Fatal("native source stripped reservation from the frozen tenant pool")
	}
}

func TestExternalNetworkBorrowsExactManagedSourceWithoutChangingIt(t *testing.T) {
	f, c, ctx, source := externalFixture(t)
	before := ctx.Current[source]
	catalog, _ := ctx.Networks.Encode()
	b, e := Compile(c, f.c, ctx)
	if e != nil {
		t.Fatal(e)
	}
	var ref NetworkReference
	var found bool
	for _, s := range b.Steps() {
		if s.Kind == "bridge" {
			t.Fatal("external bridge was recreated")
		}
		if s.Kind == "network-ref" {
			found = true
			if json.Unmarshal(s.Goal, &ref) != nil {
				t.Fatal("ref decode")
			}
		}
	}
	if !found || !ref.RetainSource || ref.Source.Generation != 17 || ref.Source.Revision != 31 {
		t.Fatal("source identity not pinned")
	}
	if e = ref.Check(ctx); e != nil {
		t.Fatal(e)
	}
	if ctx.Current[source] != before {
		t.Fatal("source changed")
	}
	after, _ := ctx.Networks.Encode()
	if !bytes.Equal(catalog, after) {
		t.Fatal("CIDR catalog changed")
	}
	for _, s := range b.ReleaseOrder() {
		if s.Key == source {
			t.Fatal("app release included borrowed source")
		}
	}
	raw, _ := b.Encode()
	decoded, e := DecodeBlueprint(raw)
	if e != nil || decoded.ValidateCurrent(f.c, ctx) != nil {
		t.Fatal("reference artifact did not restore", e)
	}
}

func TestExternalNetworkRejectsForeignDrainWrongOwnerOrChangedSource(t *testing.T) {
	for _, change := range []func(*PlanningContext, string){
		func(c *PlanningContext, k string) { delete(c.Current, k) },
		func(c *PlanningContext, k string) { v := c.Current[k]; v.Generation = 0; c.Current[k] = v },
		func(c *PlanningContext, k string) {
			c.ExternalNetworks["app"]["node-a"] = NetworkBinding{"shared-lan", ResourceKey("bridge", "other", "shared-app", "lan/node-a")}
		},
		func(c *PlanningContext, k string) {
			v := c.Current[k]
			var s network.BridgeSpec
			_ = json.Unmarshal([]byte(v.Value), &s)
			s.Lifecycle.Drain = true
			s.Lifecycle.Nonce = [16]byte{1}
			raw, _ := json.Marshal(s)
			v.Value = string(raw)
			c.Current[k] = v
		},
		func(c *PlanningContext, k string) {
			n := c.Nodes["node-a"]
			n.Key = [32]byte{55}
			c.Nodes["node-a"] = n
		},
	} {
		f, c, ctx, source := externalFixture(t)
		change(&ctx, source)
		_, e := Compile(c, f.c, ctx)
		deny(t, e)
	}
	f, c, ctx, source := externalFixture(t)
	b, e := Compile(c, f.c, ctx)
	if e != nil {
		t.Fatal(e)
	}
	var ref NetworkReference
	for _, s := range b.Steps() {
		if s.Kind == "network-ref" {
			_ = json.Unmarshal(s.Goal, &ref)
		}
	}
	v := ctx.Current[source]
	v.Revision++
	ctx.Current[source] = v
	deny(t, ref.Check(ctx))
	deny(t, b.ValidateCurrent(f.c, ctx))
}

func TestExternalNetworkAliasesCannotDoubleAllocateAddressOrMutateSourcePolicy(t *testing.T) {
	f, c, ctx, _ := externalFixture(t)
	c.Networks["alias"] = c.Networks["app"]
	ctx.ExternalNetworks["alias"] = ctx.ExternalNetworks["app"]
	s := c.Services["web"]
	s.Networks["alias"] = s.Networks["app"]
	c.Services["web"] = s
	_, e := Compile(c, f.c, ctx)
	deny(t, e)
	f, c, ctx, _ = externalFixture(t)
	n := c.Networks["app"]
	n.MyDC.RuntimeChanges = &RuntimeChanges{Authority: "authenticated-mydcp-raft-cas", Strategy: "staged", Deadlines: "preserve", Disruptive: "explicit-transition-plan"}
	c.Networks["app"] = n
	_, e = Compile(c, f.c, ctx)
	deny(t, e)
}
