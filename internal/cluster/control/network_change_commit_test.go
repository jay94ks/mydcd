// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// Native closures/installation are explicit model inputs. All publication,
// member selection, Authority archive/floor and snapshot code is product code.
func TestNetworkChangeCommitRecreatesAllPeerSourcesAndArchivesOriginalsAtomically(t *testing.T) {
	testNetworkChangeCommit(t, false)
}

func TestNetworkChangeCommitRejectsMixedPeerTargetsWithoutPartialPublication(t *testing.T) {
	testNetworkChangeCommit(t, true)
}

func testNetworkChangeCommit(t *testing.T, mixed bool) {
	t.Helper()
	f, b, _ := managedDNSProjectionFixture(t)
	initial := f.s.Objects(tenancy.ManagedNetworkSourcePrefix)
	resources, _ := f.p.Resources(f.s)
	originals := resources.Networks.AllNetworks()
	for _, n := range originals {
		target := n
		target.Generation, target.Revision = 0, 0
		target.Pools = append([]tenancy.Subnet(nil), n.Pools...)
		for i := range target.Pools {
			if !mixed || n.Node != "node-b" {
				target.Pools[i].MTU = 1400
			}
		}
		managedDNSChange(t, f, "group-plan-"+n.Node, "plan-network-change", n.Revision, NetworkChangePlan{Tenant: n.Tenant, ID: n.ID, Change: "replace-" + n.Node, Target: target}, state.Applied)
	}
	versions := func() NetworkChangeCommit {
		t.Helper()
		r, err := f.p.Resources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		q := NetworkChangeCommit{Tenant: "tenant", Network: "services"}
		for _, n := range r.Networks.AllNetworks() {
			change, _ := r.Networks.Change(n.Tenant, n.ID)
			q.Members = append(q.Members, tenancy.NetworkChangeVersion{Tenant: n.Tenant, ID: n.ID, Generation: change.Generation, Revision: change.Revision})
		}
		return q
	}
	resources, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "group-no-source-closure", "commit-network-change", resources.Networks.Revision(), versions(), state.ConditionFailed)
	for _, n := range originals {
		managedDNSChange(t, f, "group-drain-"+n.Node, "drain-network", n.Revision, NetworkSelection{Tenant: n.Tenant, ID: n.ID}, state.Applied)
		r, _ := f.p.Resources(f.s)
		current, _ := r.Networks.Network(n.Tenant, n.ID)
		change, _ := r.Networks.Change(n.Tenant, n.ID)
		key := f.node
		if n.Node == "node-b" {
			key = b
		}
		proof := tenancy.NetworkClosure{Cluster: f.p.Cluster, Tenant: n.Tenant, Network: n.ID, Node: n.Node, Owner: n.Owner, Generation: n.Generation, Revision: current.Revision, NativeGone: true}
		proof.Signature = ed25519.Sign(key, tenancy.NetworkClosureBytes(proof))
		managedDNSChange(t, f, "group-fence-"+n.Node, "fence-network-change", change.Revision, NetworkChangeFence{Tenant: n.Tenant, ID: n.ID, Generation: change.Generation, Closed: proof}, state.Applied)
	}
	before := f.s
	q := versions()
	resources, _ = f.p.Resources(f.s)
	partial := q
	partial.Members = partial.Members[:1]
	managedDNSChange(t, f, "group-missing-peer", "commit-network-change", resources.Networks.Revision(), partial, state.ConditionFailed)
	managedDNSChange(t, f, "group-stale-network-cas", "commit-network-change", resources.Networks.Revision()+1, q, state.ConditionFailed)
	if mixed {
		managedDNSChange(t, f, "group-invalid-targets", "commit-network-change", resources.Networks.Revision(), q, state.ConditionFailed)
		for _, key := range []string{ResourcesKey, AppsKey} {
			if f.s.Object(key) != before.Object(key) {
				t.Fatal("inconsistent peer targets partially changed a checkpoint", key)
			}
		}
		for key := range initial {
			if f.s.Object(key) != before.Object(key) {
				t.Fatal("inconsistent peer targets partially recreated a source", key)
			}
		}
		return
	}
	// Members may come in any order (a client lists them by server name,
	// the server keeps them by network ID).
	reversed := q
	reversed.Members = slices.Clone(q.Members)
	slices.Reverse(reversed.Members)
	command, result := managedDNSChange(t, f, "group-commit", "commit-network-change", resources.Networks.Revision(), reversed, state.Applied)
	projection, err := f.p.ProjectResources(f.s)
	apps, appErr := f.p.Apps(f.s)
	if err != nil || appErr != nil || apps.network == nil || !projection.Compatible || len(projection.ManagedSources) != 4 {
		t.Fatal("group publication lost source or original Authority", err, appErr)
	}
	for _, n := range originals {
		current, _ := projection.Resources.Networks.Network(n.Tenant, n.ID)
		change, _ := projection.Resources.Networks.Change(n.Tenant, n.ID)
		archived, found := apps.network.Authority.RetiredNetwork(n.Tenant, n.ID, n.Generation)
		if !found || current.Generation <= n.Generation || current.Generation != projection.Resources.Networks.Revision() || current.Draining || current.PendingChange != 0 || current.Pools[0].MTU != 1400 || change.Phase != tenancy.ChangeCommitted || archived.Closed.Generation != n.Generation || archived.ChangeGeneration != change.Generation {
			t.Fatal("target or original archive changed identity", n.Node)
		}
	}
	for key, source := range projection.ManagedSources {
		old, tombstone, now := initial[key], before.Object(key), f.s.Object(key)
		if tombstone.Present || !now.Present || now.Generation != result.Index || now.Generation <= old.Generation || now.Revision != result.Index || source.Closed != nil || source.Bridge != nil && source.Bridge.MTU != 1400 || source.Tunnel != nil && source.Tunnel.MTU != 1400 {
			t.Fatal("source reused an old native generation or exposed mixed MTUs", key)
		}
		if _, err := f.p.NativePermit(f.s, source.Network.Owner, NativeRequest{Source: deployment.ObjectRef{Key: key, Generation: now.Generation, Revision: now.Revision}}); err != nil {
			t.Fatal("current exact target permission", key, err)
		}
	}
	encoded, err := state.Encode(f.s)
	restored, decodeErr := state.Decode(encoded)
	if err != nil || decodeErr != nil {
		t.Fatal(err, decodeErr)
	}
	if _, err := f.p.ProjectResources(restored); err != nil {
		t.Fatal("restored new sources/archive", err)
	}
	_, replay, err := state.ApplyTransactional(restored, restored.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || replay != result {
		t.Fatal("commit receipt changed after snapshot", replay, result, err)
	}
}
