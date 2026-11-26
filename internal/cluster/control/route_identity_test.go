// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// The same product reducers/checkpoints consume signed installation model
// facts; native transport/packet preservation is covered by the owned fixture.
func TestRouteIdentityRotationKeepsOriginalReferencesAndCurrentTransportOnly(t *testing.T) {
	f, proposal, keys := routeControlOwnersFixture(t)
	_, configuration := cleanupControlIssuer(t, f)
	d, _ := f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: d.Revision, Configuration: &configuration}, state.Applied)
	approveRouteControl(t, f, proposal)
	ref, nonce, dispatch := originalRouteDispatch(t, f)
	applyRouteDispatch(t, f, dispatch, state.Applied)
	before, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	refs := before.NetworkAuthority.RouteReferences()
	sourceBytes, _ := json.Marshal(f.s.Objects(tenancy.ManagedNetworkSourcePrefix))
	original := ref.Local.Owner
	peer := refs[0].Local.Owner
	if peer == original {
		peer = refs[1].Local.Owner
	}
	current := original
	report := func(action, operation string, proof *lifecycle.IdentityProof, private ed25519.PrivateKey) {
		t.Helper()
		d, _ := f.p.Members(f.s)
		r := MemberReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(private.Public().(ed25519.PublicKey)), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(MembersKey).Revision, RequestID: fmt.Sprintf("lineage-%s-%d", action, f.s.Index()), Action: action, Node: "node-a", Operation: operation, Expected: d.Revision, Identity: proof}
		r.Signature = ed25519.Sign(private, MemberReportBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal(action, result, err)
		}
		f.s = next
	}
	for i := 0; i < 2; i++ {
		old := current
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(178 + i)}, ed25519.SeedSize))
		current = [32]byte(private.Public().(ed25519.PublicKey))
		operation := fmt.Sprintf("rotate-route-%d", i)
		d, _ := f.p.Members(f.s)
		entry, _ := d.Entry("node-a")
		f.apply(operation, "rotate-node-identity", entry.Revision, NodeIdentityChange{ID: "node-a", Operation: operation}, state.Applied)
		proof := lifecycle.IdentityProof{Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Operation: operation, Old: old, New: current, Prepared: [32]byte{byte(i + 1)}}
		proof.OldSignature = ed25519.Sign(keys[old], lifecycle.IdentityProofBytes(proof))
		proof.NewSignature = ed25519.Sign(private, lifecycle.IdentityProofBytes(proof))
		report("identity-prepared", operation, &proof, keys[old])
		report("identity-activate", operation, nil, keys[old])
		report("identity-installed", operation, nil, private)
		keys[current] = private
		if !f.p.RouteTransportAllowed(f.s, current, peer) || f.p.RouteTransportAllowed(f.s, old, peer) || f.p.RouteTransportAllowed(f.s, [32]byte{99}, peer) {
			t.Fatal("transport did not fence old/unrelated session keys")
		}
		work, err := f.p.RouteWork(f.s, current, RouteWorkRequest{Reference: ref.ID})
		if err != nil || !work.PrepareAllowed || work.Reference.Local.Owner != original || work.Reference.ID != ref.ID {
			t.Fatal("current key lost original route preparation", err)
		}
		if _, err := f.p.RouteWork(f.s, old, RouteWorkRequest{Reference: ref.ID}); err == nil {
			t.Fatal("old key authenticated a current route call")
		}
		permit, err := f.p.RouteNativePermit(f.s, current, RouteNativeRequest{Reference: ref.ID, Nonce: nonce, Operation: 1})
		if err != nil || permit.Reference != dispatch.Dispatch.Reference || permit.Journal != dispatch.Dispatch.Journal {
			t.Fatal("rotation changed original native journal", err)
		}
		after, err := f.p.ProjectResources(f.s)
		sources, _ := json.Marshal(f.s.Objects(tenancy.ManagedNetworkSourcePrefix))
		if err != nil || !bytes.Equal(sourceBytes, sources) || !reflect.DeepEqual(refs, after.NetworkAuthority.RouteReferences()) {
			t.Fatal("rotation rewrote original sources/references", err)
		}
		limit, _ := after.Resources.Quotas.Limit(ref.Local.Tenant, ref.Local.Node)
		if limit.Owner != current || !after.Resources.Quotas.SameOwner(ref.Local.Node, current, original) {
			t.Fatal("original quota charge lost physical node lineage")
		}
		raw, err := state.Encode(f.s)
		if err != nil {
			t.Fatal(err)
		}
		f.s, err = state.Decode(raw)
		if err != nil || f.p.ResourceWorkKey(f.s, original) != current {
			t.Fatal("snapshot lost exact current mapping", err)
		}
	}
	d, _ = f.p.Members(f.s)
	topology, _ := d.Topology()
	node, _ := topology.Node("node-a")
	f.apply("isolate-rotated-route", "isolate-node", node.Revision, NodeLifecycleChange{ID: "node-a", Operation: "isolate-rotated-route", Epoch: topology.Epoch()}, state.Applied)
	if f.p.ResourceWorkKey(f.s, original) != ([32]byte{}) || f.p.RouteTransportAllowed(f.s, current, peer) {
		t.Fatal("current work isolation failed to fence retained route transport")
	}
	work, err := f.p.RouteWork(f.s, current, RouteWorkRequest{Reference: ref.ID})
	if err != nil || work.PrepareAllowed || work.Reference.ID != ref.ID {
		t.Fatal("isolation erased original cleanup reference", err)
	}
}
