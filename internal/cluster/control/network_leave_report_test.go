// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// A drained workspace network member leaves on its own server's signed
// report, with no user operation after the drain. Only a drained member's
// own server can send it, and a member drained for a planned change cannot
// leave this way.
func TestNetworkLeaveReportFinishesADrainWithoutTheClient(t *testing.T) {
	f, b, _ := managedDNSProjectionFixture(t)
	pool := func(prefix, gateway string) []tenancy.Subnet {
		return []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix(prefix), Gateway: netip.MustParseAddr(gateway), MTU: 1280}}
	}
	lone := tenancy.TUNDefinition{Tenant: "tenant", Name: "edge", Members: []tenancy.TUNNode{{Node: "node-a", Pools: pool("10.81.1.0/24", "10.81.1.1")}}}
	r, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-create", "create-tun-network", r.Networks.Revision(), lone, state.Applied)
	r, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-join", "join-tun-network", r.Networks.Revision(), NetworkJoin{Tenant: "tenant", Name: "edge", Member: tenancy.TUNNode{Node: "node-b", Pools: pool("10.81.2.0/24", "10.81.2.1")}}, state.Applied)
	key := func(kind, node string) string {
		return (tenancy.SourceIdentity{Kind: kind, Tenant: "tenant", Network: "edge", Node: node}).Key()
	}
	member := func(node string) tenancy.Network {
		r, _ := f.p.Resources(f.s)
		m, ok := r.Networks.NamedNetwork("tenant", "edge", node)
		if !ok {
			for _, n := range r.Networks.AllNetworks() {
				if n.Logical == "edge" && n.Node == node {
					return n
				}
			}
		}
		return m
	}
	report := func(m tenancy.Network, signer ed25519.PrivateKey, reporter [32]byte) state.Code {
		closure := tenancy.NetworkClosure{Cluster: f.p.Cluster, Tenant: "tenant", Network: m.ID, Node: m.Node, Owner: m.Owner, Generation: m.Generation, Revision: m.Revision, NativeGone: true}
		closure.Signature = ed25519.Sign(signer, tenancy.NetworkClosureBytes(closure))
		rep := NetworkLeaveReport{Schema: 1, Kind: "network-leave", Cluster: f.p.Cluster, Reporter: reporter, Expected: m.Revision, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(ResourcesKey).Revision, Closure: closure}
		rep.Signature = ed25519.Sign(signer, NetworkLeaveReportBytes(rep))
		raw, _ := json.Marshal(rep)
		if _, err := f.p.ResolveNetworkLeaveReport(f.s, reporter, raw); err != nil && signer.Equal(b) && m.Draining {
			t.Fatal("resolve", err)
		}
		command, err := rep.Command()
		if err != nil {
			t.Fatal(err)
		}
		next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil {
			return state.Invalid
		}
		f.s = next
		return result.Code
	}
	leaving := member("node-b")
	// Not drained: nothing to settle.
	if code := report(leaving, b, leaving.Owner); code == state.Applied {
		t.Fatal("an undrained member left on its own report")
	}
	managedDNSChange(t, f, "edge-drain-b", "drain-network", leaving.Revision, NetworkSelection{Tenant: "tenant", ID: leaving.ID}, state.Applied)
	drained := member("node-b")
	_, forged, _ := ed25519.GenerateKey(nil)
	if code := report(drained, forged, drained.Owner); code == state.Applied {
		t.Fatal("a forged leave applied")
	}
	var other [32]byte
	copy(other[:], forged.Public().(ed25519.PublicKey))
	if code := report(drained, forged, other); code == state.Applied {
		t.Fatal("another key's leave applied")
	}
	tunA := f.s.Object(key("tun", "node-a"))
	if code := report(drained, b, drained.Owner); code != state.Applied {
		t.Fatal("leave report", code)
	}
	r, _ = f.p.Resources(f.s)
	if _, ok := r.Networks.Network("tenant", drained.ID); ok {
		t.Fatal("the drained member stayed")
	}
	if f.s.Object(key("bridge", "node-b")).Present || f.s.Object(key("tun", "node-b")).Present {
		t.Fatal("the leaving member's sources stayed")
	}
	if now := f.s.Object(key("tun", "node-a")); !now.Present || now.Generation != tunA.Generation || now.Revision <= tunA.Revision {
		t.Fatal("the staying member's TUN was not rewritten in place")
	}
	// The last member leaves the same way and deletes the network.
	last := member("node-a")
	managedDNSChange(t, f, "edge-drain-a", "drain-network", last.Revision, NetworkSelection{Tenant: "tenant", ID: last.ID}, state.Applied)
	if code := report(member("node-a"), f.node, last.Owner); code != state.Applied {
		t.Fatal("last leave report", code)
	}
	r, _ = f.p.Resources(f.s)
	for _, n := range r.Networks.AllNetworks() {
		if n.Logical == "edge" {
			t.Fatal("the network stayed after its last server left")
		}
	}
}
