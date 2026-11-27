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

// Two networks of one tenant are bridged at once; the refusals carry their
// own reasons, and no native source is written for the bridge yet.
func TestVirtualBridgeActionsOnOneTenant(t *testing.T) {
	f, b, _ := managedDNSProjectionFixture(t)
	lone := func(name, pool, gateway, tunnel string) tenancy.TUNDefinition {
		return tenancy.TUNDefinition{Tenant: "tenant", Name: name, Members: []tenancy.TUNNode{{Node: "node-b", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix(pool), Gateway: netip.MustParseAddr(gateway), MTU: 1280}}}}}
	}
	r, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-create", "create-tun-network", r.Networks.Revision(), lone("edge", "10.81.1.0/24", "10.81.1.1", "10.81.3.1/32"), state.Applied)
	r, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "core-create", "create-tun-network", r.Networks.Revision(), lone("core", "10.82.1.0/24", "10.82.1.1", "10.82.3.1/32"), state.Applied)
	before := f.s.Objects(tenancy.ManagedNetworkSourcePrefix)
	proposal := BridgeProposal{ID: "link", A: tenancy.BridgeEnd{Tenant: "tenant", Network: "edge"}, B: tenancy.BridgeEnd{Tenant: "tenant", Network: "core"}}
	r, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "bridge-create", "create-virtual-bridge", r.Networks.Revision(), proposal, state.Applied)
	r, _ = f.p.Resources(f.s)
	bridge, ok := r.Networks.Bridge("tenant", "link")
	if !ok || bridge.Phase != tenancy.BridgeOpen || bridge.Direction != tenancy.BridgeBoth || len(bridge.Approvals) != 1 {
		t.Fatal("a same-tenant bridge did not open at once", bridge)
	}
	c, _ := f.p.Catalog(f.s)
	found := false
	for after := ""; ; {
		page, next, err := r.Page(c, "admin", "tenant", after)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			found = found || e.Key == "bridge/tenant/link" && e.Bridge != nil && e.Bridge.B.Network == "core"
		}
		if after = next; next == "" {
			break
		}
	}
	if !found {
		t.Fatal("the resources page has no bridge row")
	}
	for key, old := range before {
		if f.s.Object(key) != old {
			t.Fatal("the bridge rewrote a native source", key)
		}
	}
	again := proposal
	again.ID, again.A, again.B = "back", proposal.B, proposal.A
	if _, res := managedDNSChange(t, f, "bridge-again", "create-virtual-bridge", r.Networks.Revision(), again, state.BridgeExists); res.Reason != "bridge-exists" {
		t.Fatal("reason", res)
	}
	// edge's only member cannot leave while the bridge is attached.
	leaving, _ := r.Networks.NamedNetwork("tenant", "edge", "node-b")
	managedDNSChange(t, f, "edge-drain", "drain-network", leaving.Revision, NetworkSelection{Tenant: "tenant", ID: leaving.ID}, state.Applied)
	r, _ = f.p.Resources(f.s)
	drained, _ := r.Networks.Network("tenant", leaving.ID)
	closure := tenancy.NetworkClosure{Cluster: f.p.Cluster, Tenant: "tenant", Network: leaving.ID, Node: "node-b", Owner: leaving.Owner, Generation: leaving.Generation, Revision: drained.Revision, NativeGone: true}
	closure.Signature = ed25519.Sign(b, tenancy.NetworkClosureBytes(closure))
	if _, res := managedDNSChange(t, f, "edge-leave", "leave-tun-network", drained.Revision, closure, state.BridgeAttached); res.Reason != "bridge-attached" {
		t.Fatal("reason", res)
	}
	r, _ = f.p.Resources(f.s)
	bridge, _ = r.Networks.Bridge("tenant", "link")
	managedDNSChange(t, f, "bridge-close-stale", "close-virtual-bridge", bridge.Revision+1, BridgeSelection{Tenant: "tenant", Owner: "tenant", ID: "link"}, state.ConditionFailed)
	managedDNSChange(t, f, "bridge-close", "close-virtual-bridge", bridge.Revision, BridgeSelection{Tenant: "tenant", Owner: "tenant", ID: "link"}, state.Applied)
	r, _ = f.p.Resources(f.s)
	if bridge, ok = r.Networks.Bridge("tenant", "link"); !ok || bridge.Phase != tenancy.BridgeClosing {
		t.Fatal("an open bridge did not wait for its servers' reports", bridge)
	}
	managedDNSChange(t, f, "bridge-approve-own", "approve-virtual-bridge", bridge.Revision, BridgeSelection{Tenant: "tenant", Owner: "tenant", ID: "link"}, state.ConditionFailed)

	// node-b carries both networks; its signed report removes the bridge,
	// and edge's last member may leave after it.
	owner := leaving.Owner
	report := func(signer ed25519.PrivateKey) state.Code {
		closure := tenancy.BridgeClosure{Cluster: f.p.Cluster, Owner: "tenant", ID: "link", Generation: bridge.Generation, Node: "node-b", Key: owner}
		closure.Signature = ed25519.Sign(signer, tenancy.BridgeClosureBytes(closure))
		r := BridgeClosedReport{Schema: 1, Kind: "virtual-bridge-closed", Cluster: f.p.Cluster, Reporter: owner, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(ResourcesKey).Revision, Closure: closure}
		r.Signature = ed25519.Sign(signer, BridgeClosedReportBytes(r))
		raw, _ := json.Marshal(r)
		if _, err := f.p.ResolveBridgeClosedReport(f.s, owner, raw); err != nil && signer.Equal(b) {
			t.Fatal("resolve", err)
		}
		command, err := r.Command()
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
	_, forged, _ := ed25519.GenerateKey(nil)
	if code := report(forged); code == state.Applied {
		t.Fatal("a forged bridge report applied")
	}
	if code := report(b); code != state.Applied {
		t.Fatal("bridge report", code)
	}
	r, _ = f.p.Resources(f.s)
	if _, ok = r.Networks.Bridge("tenant", "link"); ok {
		t.Fatal("the bridge stayed after every server reported")
	}
	managedDNSChange(t, f, "edge-leave-after", "leave-tun-network", drained.Revision, closure, state.Applied)
}
