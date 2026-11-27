// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
)

func TestTunnelGoalExactBridgeSourcesAndNamespace(t *testing.T) {
	f := makeFixture(t)
	plan, err := Compile(smallCompose(t), f.c, contextFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	objects := map[string]state.Object{}
	var steps []Step
	for _, step := range plan.Steps() {
		if step.Kind == "bridge" {
			steps = append(steps, step)
		}
	}
	for n, step := range steps {
		g := GoalCommand{Schema: 1, Cluster: plan.d.Cluster, Tenant: plan.d.Tenant, App: plan.d.App, Deployment: plan.d.Deployment, Kind: step.Kind, Node: step.Node, Owner: step.Owner, Config: step.Goal}
		raw, _ := json.Marshal(g)
		objects[step.Key] = state.Object{Present: true, Generation: uint64(n + 11), Revision: uint64(n + 11), Value: string(raw)}
	}
	topology := network.TunnelTopology{Tunnels: map[string]network.TunnelSpec{}}
	var original GoalCommand
	var key string
	for _, step := range plan.Steps() {
		if step.Kind != "tunnel" {
			continue
		}
		g := GoalCommand{Schema: 1, Cluster: plan.d.Cluster, Tenant: plan.d.Tenant, App: plan.d.App, Deployment: plan.d.Deployment, Kind: step.Kind, Node: step.Node, Owner: step.Owner, Config: step.Goal}
		for _, dep := range step.Dependencies {
			o := objects[dep.Key]
			g.Dependencies = append(g.Dependencies, ObjectRef{Key: dep.Key, Generation: o.Generation, Revision: o.Revision})
		}
		raw, _ := json.Marshal(g)
		o := state.Object{Present: true, Generation: 30, Revision: 30, Value: string(raw)}
		objects[step.Key] = o
		spec, e := ResolveTunnel(plan.d.Cluster, step.Key, o, objects)
		if e != nil || spec.Network != "tenant/php-mysql/app" || spec.Owner != engine.Owner(plan.d.Cluster, step.Owner) || spec.MTU != 1280 || len(spec.Addresses) != 1 || len(spec.Routes) != 2 {
			t.Fatal("exact native tunnel", e)
		}
		topology.Tunnels[step.Key] = spec
		if key == "" {
			key, original = step.Key, g
		}
	}
	for _, step := range steps {
		b, e := DecodeGoalResources(plan.d.Cluster, step.Key, objects[step.Key])
		if e != nil {
			t.Fatal(e)
		}
		topology.Pools = append(topology.Pools, network.RoutePool{Network: "tenant/php-mysql/app", Owner: b.Bridge.Owner, Prefix: b.Bridge.Pools[0].Prefix})
	}
	if peers, e := topology.Peers(key); e != nil || len(peers) != 1 {
		t.Fatal("whole remote pool and host use the same peer", e)
	}
	for _, change := range []func(*GoalCommand){func(g *GoalCommand) { g.Dependencies[0].Revision++ }, func(g *GoalCommand) { g.Dependencies = g.Dependencies[:1] }, func(g *GoalCommand) { g.Tenant = "other" }, func(g *GoalCommand) { g.Owner = [32]byte{99} }, func(g *GoalCommand) { g.Config = []byte(`{"node-a":"10.240.10.8/32","node-b":"10.240.30.2/32"}`) }, func(g *GoalCommand) { g.Config = []byte(`{"unregistered":"10.240.30.9/32"}`) }} {
		g := original
		g.Dependencies = slices.Clone(original.Dependencies)
		change(&g)
		raw, _ := json.Marshal(g)
		o := objects[key]
		o.Value = string(raw)
		if _, e := ResolveTunnel(plan.d.Cluster, key, o, objects); e == nil {
			t.Fatal("accepted foreign/stale/overlapping source")
		}
	}
	// An absent opposite TUN cannot be learned from a bridge or packet.
	for k := range topology.Tunnels {
		if k != key {
			delete(topology.Tunnels, k)
		}
	}
	if _, e := topology.Peers(key); e == nil {
		t.Fatal("missing opposite intent accepted")
	}
	if slices.Contains(topology.Tunnels[key].Routes, netip.MustParsePrefix("10.240.10.0/24")) && original.Node == "node-a" {
		t.Fatal("routed own local pool")
	}
}
