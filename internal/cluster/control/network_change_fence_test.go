// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Native/installation facts are signed model inputs. This exercises the real
// typed reducer, current projection, shared CAS and retained snapshot only.
func TestNetworkChangeFenceRequiresExactDrainedMemberAndPreservesPeerSources(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	original, plan := networkChangeCandidate(t, f)
	managedDNSChange(t, f, "fence-reserve", "plan-network-change", original.Revision, plan, state.Applied)
	resources, _ := f.p.Resources(f.s)
	change, _ := resources.Networks.Change(original.Tenant, original.ID)
	proof := tenancy.NetworkClosure{Cluster: f.p.Cluster, Tenant: original.Tenant, Network: original.ID, Node: original.Node, Owner: original.Owner, Generation: original.Generation, Revision: original.Revision, NativeGone: true}
	proof.Signature = ed25519.Sign(f.node, tenancy.NetworkClosureBytes(proof))
	q := NetworkChangeFence{Tenant: original.Tenant, ID: original.ID, Generation: change.Generation, Closed: proof}
	managedDNSChange(t, f, "fence-without-drain", "fence-network-change", change.Revision, q, state.ConditionFailed)
	managedDNSChange(t, f, "fence-drain", "drain-network", original.Revision, NetworkSelection{Tenant: original.Tenant, ID: original.ID}, state.Applied)
	resources, _ = f.p.Resources(f.s)
	current, _ := resources.Networks.Network(original.Tenant, original.ID)
	change, _ = resources.Networks.Change(original.Tenant, original.ID)
	q.Closed.Revision = current.Revision
	q.Closed.Signature = ed25519.Sign(f.node, tenancy.NetworkClosureBytes(q.Closed))
	bad := q
	bad.Generation++
	managedDNSChange(t, f, "fence-wrong-generation", "fence-network-change", change.Revision, bad, state.ConditionFailed)
	bad = q
	bad.Closed.Signature = bytes.Repeat([]byte{1}, ed25519.SignatureSize)
	managedDNSChange(t, f, "fence-wrong-owner-proof", "fence-network-change", change.Revision, bad, state.ConditionFailed)
	managedDNSChange(t, f, "fence-stale-change", "fence-network-change", change.Revision+1, q, state.ConditionFailed)
	before := f.s
	command, result := managedDNSChange(t, f, "fence-original", "fence-network-change", change.Revision, q, state.Applied)
	resources, _ = f.p.Resources(f.s)
	change, _ = resources.Networks.Change(original.Tenant, original.ID)
	if change.Phase != tenancy.ChangeFenced || change.SourceClosed == nil || !bytes.Equal(change.SourceClosed.Signature, q.Closed.Signature) {
		t.Fatal("shared fence lost or rewrote original closure")
	}
	for key, old := range before.Objects(tenancy.ManagedNetworkSourcePrefix) {
		identity, err := tenancy.ParseSourceIdentity(key)
		if err != nil {
			t.Fatal(err)
		}
		if identity.Node == original.Node {
			now := f.s.Object(key)
			if now.Present || now.Generation != old.Generation || now.Revision != result.Index {
				t.Fatal("positive member closure did not withdraw only its original source", key)
			}
		} else if f.s.Object(key) != old {
			t.Fatal("one member's fence withdrew a peer source", key)
		}
	}
	peer, ok := resources.Networks.NamedNetwork("tenant", "services", "node-b")
	if ok || peer.ID != "" {
		t.Fatal("one member's fence reopened group admission")
	}
	encoded, err := state.Encode(f.s)
	restored, decodeErr := state.Decode(encoded)
	if err != nil || decodeErr != nil {
		t.Fatal("fence snapshot", err, decodeErr)
	}
	if _, err := f.p.ProjectResources(restored); err != nil {
		t.Fatal("fence lost original Drain/source projection", err)
	}
	_, replay, err := state.ApplyTransactional(restored, restored.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || replay != result {
		t.Fatal("fence replay changed its original receipt", replay, result, err)
	}
}
