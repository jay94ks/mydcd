// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// This fixture consumes the actual planner/change/FSM/Authority, with explicit
// model native/installation facts. It never starts a native candidate.
func fencedMembership(t *testing.T, f *backupCoreFixture, b ed25519.PrivateKey) ([]tenancy.Network, NetworkReconfigure) {
	t.Helper()
	r, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	original := r.Networks.AllNetworks()
	for _, n := range original {
		target := n
		target.Generation, target.Revision, target.PendingChange = 0, 0, 0
		id := fmt.Sprintf("member-plan-%d", f.s.Index())
		managedDNSChange(t, f, id, "plan-network-change", n.Revision, NetworkChangePlan{Tenant: n.Tenant, ID: n.ID, Change: id, Target: target}, state.Applied)
	}
	for _, n := range original {
		managedDNSChange(t, f, fmt.Sprintf("member-drain-%d", f.s.Index()), "drain-network", n.Revision, NetworkSelection{Tenant: n.Tenant, ID: n.ID}, state.Applied)
		r, _ = f.p.Resources(f.s)
		current, _ := r.Networks.Network(n.Tenant, n.ID)
		change, _ := r.Networks.Change(n.Tenant, n.ID)
		key := f.node
		if n.Node == "node-b" {
			key = b
		}
		close := tenancy.NetworkClosure{Cluster: f.p.Cluster, Tenant: n.Tenant, Network: n.ID, Node: n.Node, Owner: n.Owner, Generation: n.Generation, Revision: current.Revision, NativeGone: true}
		close.Signature = ed25519.Sign(key, tenancy.NetworkClosureBytes(close))
		managedDNSChange(t, f, fmt.Sprintf("member-fence-%d", f.s.Index()), "fence-network-change", change.Revision, NetworkChangeFence{Tenant: n.Tenant, ID: n.ID, Generation: change.Generation, Closed: close}, state.Applied)
	}
	r, _ = f.p.Resources(f.s)
	q := NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: "tenant", Name: "services", Members: []tenancy.TUNNode{}}}
	for _, n := range r.Networks.AllNetworks() {
		change, _ := r.Networks.Change(n.Tenant, n.ID)
		q.Members = append(q.Members, tenancy.NetworkChangeVersion{Tenant: n.Tenant, ID: n.ID, Generation: change.Generation, Revision: change.Revision})
	}
	return original, q
}

func TestNetworkMembershipRebindShrinkAndExpansionRetainExactClosedSources(t *testing.T) {
	f, b, _ := managedDNSProjectionFixture(t)
	original, q := fencedMembership(t, f, b)
	var a, oldB tenancy.Network
	for _, n := range original {
		if n.Node == "node-a" {
			a = n
		} else {
			oldB = n
		}
	}
	// Move node-a's CIDR responsibility to node-b while removing node-a. A
	// single-member result has a new TUN without routes; both old TUN
	// identities stay closed.
	q.Target.Members = []tenancy.TUNNode{{Node: "node-b", Pools: a.Pools}}
	r, _ := f.p.Resources(f.s)
	before := f.s
	managedDNSChange(t, f, "membership-rebind", "reconfigure-tun-network", r.Networks.Revision(), q, state.Applied)
	view, err := f.p.ProjectResources(f.s)
	current, found := view.Resources.Networks.NamedNetwork("tenant", "services", "node-b")
	if err != nil || !found || len(view.Resources.Networks.AllNetworks()) != 1 || current.Pools[0].Prefix != a.Pools[0].Prefix || current.Owner != oldB.Owner || current.ID != oldB.ID {
		t.Fatal("node/CIDR rebind did not replace the complete group", err)
	}
	active, closed := 0, 0
	for key, source := range view.ManagedSources {
		if source.Closed == nil {
			active++
			if source.Tunnel != nil && len(source.Tunnel.Routes) != 0 || !f.s.Object(key).Present || f.s.Object(key).Generation <= before.Object(key).Generation {
				t.Fatal("single-member target reused a source or kept a remote route", key)
			}
		} else {
			closed++
			if f.s.Object(key).Present || source.Closed.Generation != source.Network.Generation {
				t.Fatal("historical source became current admission", key)
			}
		}
	}
	// node-b's Bridge and TUN keys are current again (new generations); the
	// removed node-a's two sources stay closed.
	if active != 2 || closed != 2 {
		t.Fatal("removed node and old TUN journals lost their closed bindings", active, closed)
	}
	apps, _ := f.p.Apps(f.s)
	archived, kept := apps.network.Authority.RetiredNetwork(a.Tenant, a.ID, a.Generation)
	if !kept || archived.Change == nil || len(archived.Sources) != 2 || archived.Change.Phase != tenancy.ChangeFenced {
		t.Fatal("original change/target/native source facts were not archived")
	}
	// Owned reads cannot corrupt future same-DB or snapshot reconstruction.
	archived.Network.TunnelAddresses[0] = netip.MustParsePrefix("198.18.0.1/32")
	archived.Change.SourceClosed.Signature[0] ^= 1
	archived.Sources[0].Bridge.Pools[0].Gateway = netip.MustParseAddr("198.18.0.1")
	again, _ := apps.network.Authority.RetiredNetwork(a.Tenant, a.ID, a.Generation)
	if again.Network.TunnelAddresses[0] != a.TunnelAddresses[0] || !ed25519.Verify(a.Owner[:], tenancy.NetworkClosureBytes(again.Closed), again.Closed.Signature) || again.Sources[0].Bridge.Pools[0].Gateway != a.Pools[0].Gateway {
		t.Fatal("archive reader changed the stored original proof/spec")
	}
	retained := map[string]state.Object{}
	for key, source := range view.ManagedSources {
		if source.Closed != nil {
			retained[key] = f.s.Object(key)
		}
	}
	_, q = fencedMembership(t, f, b)
	for key, original := range retained {
		if f.s.Object(key) != original {
			t.Fatal("current member fence changed an older closed native source", key)
		}
	}
	q.Target.Members = []tenancy.TUNNode{{Node: "node-a", Pools: a.Pools, Addresses: a.TunnelAddresses}, {Node: "node-b", Pools: oldB.Pools, Addresses: oldB.TunnelAddresses}}
	r, _ = f.p.Resources(f.s)
	command, result := managedDNSChange(t, f, "membership-expand", "reconfigure-tun-network", r.Networks.Revision(), q, state.Applied)
	view, err = f.p.ProjectResources(f.s)
	if err != nil || len(view.ManagedSources) != 4 || len(view.Resources.Networks.AllNetworks()) != 2 {
		t.Fatal("expanded group lost sources or retained the old topology", err)
	}
	for key, source := range view.ManagedSources {
		if source.Closed != nil || !f.s.Object(key).Present || f.s.Object(key).Generation != result.Index {
			t.Fatal("archive shadowed the new active source", key)
		}
	}
	encoded, err := state.Encode(f.s)
	restored, decodeErr := state.Decode(encoded)
	if err != nil || decodeErr != nil {
		t.Fatal(err, decodeErr)
	}
	if _, err := f.p.ProjectResources(restored); err != nil {
		t.Fatal("membership snapshot lost native/archived bindings", err)
	}
	_, replay, err := state.ApplyTransactional(restored, restored.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || replay != result {
		t.Fatal("original membership operation changed after restore", replay, result, err)
	}
}

func TestNetworkMembershipRejectsForeignUnknownAndConflictingTargetsWithoutPartialWrite(t *testing.T) {
	f, b, _ := managedDNSProjectionFixture(t)
	original, q := fencedMembership(t, f, b)
	r, _ := f.p.Resources(f.s)
	before := f.s
	q.Target.Members = []tenancy.TUNNode{{Node: "node-c", Pools: original[0].Pools, Addresses: original[0].TunnelAddresses}}
	managedDNSChange(t, f, "members-unknown-node", "reconfigure-tun-network", r.Networks.Revision(), q, state.Forbidden)
	q.Target.Members = []tenancy.TUNNode{{Node: "node-a", Owner: [32]byte{99}, Pools: original[0].Pools, Addresses: original[0].TunnelAddresses}}
	managedDNSChange(t, f, "members-foreign-owner", "reconfigure-tun-network", r.Networks.Revision(), q, state.Forbidden)
	q.Target.Members = []tenancy.TUNNode{{Node: "node-a", Pools: original[0].Pools, Addresses: original[0].TunnelAddresses}, {Node: "node-b", Pools: original[0].Pools, Addresses: original[1].TunnelAddresses}}
	managedDNSChange(t, f, "members-overlapping-cidr", "reconfigure-tun-network", r.Networks.Revision(), q, state.ConditionFailed)
	for _, key := range []string{ResourcesKey, AppsKey} {
		if f.s.Object(key) != before.Object(key) {
			t.Fatal("rejected target partially changed shared state", key)
		}
	}
	for key, object := range before.Objects(tenancy.ManagedNetworkSourcePrefix) {
		if f.s.Object(key) != object {
			t.Fatal("rejected target changed source/native generation", key)
		}
	}
}

func TestNetworkMembershipFullRetirementRequiresExplicitDNSDisable(t *testing.T) {
	f, b, definition := managedDNSProjectionFixture(t)
	_, q := fencedMembership(t, f, b)
	r, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "members-dns-still-enabled", "reconfigure-tun-network", r.Networks.Revision(), q, state.ConditionFailed)
	// Use a fresh fixture: disable is an explicit service policy action BEFORE
	// network Drain, never an implicit permission granted by network retirement.
	f, b, definition = managedDNSProjectionFixture(t)
	definition.Policy.Enabled = false
	key := services.ManagedDNSKey("tenant", "services")
	managedDNSChange(t, f, "members-disable-dns", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
	_, q = fencedMembership(t, f, b)
	r, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "members-retire-group", "reconfigure-tun-network", r.Networks.Revision(), q, state.Applied)
	view, err := f.p.ProjectResources(f.s)
	if err != nil || len(view.Resources.Networks.AllNetworks()) != 0 || len(view.ManagedSources) != 4 {
		t.Fatal("group retirement lost original native history", err)
	}
	for key, source := range view.ManagedSources {
		if source.Closed == nil || f.s.Object(key).Present {
			t.Fatal("retirement produced an active or unbound source", key)
		}
	}
	a, _ := f.p.Apps(f.s)
	before, _ := a.network.Authority.Encode()
	copy := a.network.Authority.RetiredNetworks()
	copy[0].Closed.Signature = nil
	after, _ := a.network.Authority.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("archive list exposed mutable authority")
	}
}
