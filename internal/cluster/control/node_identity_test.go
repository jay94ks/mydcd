// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Actual reducers/checkpoints and signatures, with explicitly modeled SDK
// configuration. Native installation/TLS/Volume I/O belong to the app fixture.
func TestIdentityActivationKeepsOriginalVolumeAndIssuerHistoryInOnePatch(t *testing.T) {
	f := newBackupCore(t)
	for _, tenant := range []string{"", "tenant"} {
		f.apply("identity-quota-"+tenant, "set-node-quota", 0, tenancy.NodeLimit{Tenant: tenant, Node: "node-a", Owner: f.p.TrustRoot, Capacity: workload.Resources{CPU: 100, Memory: 1 << 30}, MaxConsumers: 8}, state.Applied)
	}
	_, configuration := cleanupControlIssuer(t, f)
	d, _ := f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: d.Revision, Configuration: &configuration}, state.Applied)
	f.apply("explicit-old-issuer", "vault-set-issuer", 0, VaultIssuer{Key: f.p.TrustRoot, Enabled: true}, state.Applied)
	before, err := f.p.Vault(f.s)
	oldIssuer, found := before.Approvals.Issuer(f.p.TrustRoot)
	if err != nil || !found {
		t.Fatal(err)
	}
	beforeVolume, found := f.view().Native("tenant", "app", "data")
	if !found {
		t.Fatal("original Volume fact missing")
	}
	d, _ = f.p.Members(f.s)
	entry, _ := d.Entry("node-a")
	f.apply("replace-identity", "rotate-node-identity", entry.Revision, NodeIdentityChange{ID: "node-a", Operation: "replace-a"}, state.Applied)
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{98}, ed25519.SeedSize))
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Operation: "replace-a", Old: f.p.TrustRoot, New: [32]byte(next.Public().(ed25519.PublicKey)), Prepared: [32]byte{1}}
	proof.OldSignature = ed25519.Sign(f.node, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
	d, _ = f.p.Members(f.s)
	bad := proof
	bad.NewSignature = nil
	nodeCoreReport(t, f, MemberReport{Action: "identity-prepared", Node: "node-a", Operation: "replace-a", Expected: d.Revision, Identity: &bad}, state.ConditionFailed)
	d, _ = f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "identity-prepared", Node: "node-a", Operation: "replace-a", Expected: d.Revision, Identity: &proof}, state.Applied)
	d, _ = f.p.Members(f.s)
	priorMembers, priorResources, priorVault := f.s.Object(MembersKey), f.s.Object(ResourcesKey), f.s.Object(VaultKey)
	selection := NodeIdentityChange{ID: "node-a", Operation: "replace-a"}
	if _, err := f.p.ObserveIdentityActivation(f.s, proof.New, selection); err == nil {
		t.Fatal("prepared key observed an uncommitted activation")
	}
	nodeCoreReport(t, f, MemberReport{Action: "identity-activate", Node: "node-a", Operation: "replace-a", Expected: d.Revision}, state.Applied)
	activation, err := f.p.ObserveIdentityActivation(f.s, proof.New, selection)
	if err != nil || activation.Index == 0 || activation.Proof.New != proof.New || !bytes.Equal(activation.Proof.OldSignature, proof.OldSignature) {
		t.Fatal("new key could not recover its exact committed activation", err)
	}
	for _, attempt := range []struct {
		caller [32]byte
		q      NodeIdentityChange
	}{{proof.Old, selection}, {proof.New, NodeIdentityChange{ID: "foreign", Operation: "replace-a"}}, {proof.New, NodeIdentityChange{ID: "node-a", Operation: "foreign"}}} {
		if _, err := f.p.ObserveIdentityActivation(f.s, attempt.caller, attempt.q); err == nil {
			t.Fatal("activation observation accepted an old key or foreign original operation")
		}
	}
	if f.s.Object(MembersKey) == priorMembers || f.s.Object(ResourcesKey) == priorResources || f.s.Object(VaultKey) == priorVault {
		t.Fatal("activation did not publish membership, physical quota and issuer policy together")
	}
	after, err := f.p.Vault(f.s)
	historical, historicalFound := after.Approvals.Issuer(proof.Old)
	current, currentFound := after.Approvals.Issuer(proof.New)
	if err != nil || !historicalFound || historical != oldIssuer || !currentFound || !current.Enabled || current.Key != proof.New || current.Policy <= oldIssuer.Policy {
		t.Fatal("explicit new issuer did not preserve original approval policy history", err)
	}
	d, _ = f.p.Members(f.s)
	if d.MemberKey(proof.Old) || !d.MemberKey(proof.New) || !d.HistoricalMemberKey(proof.Old) {
		t.Fatal("historical issuer became current node authority")
	}
	resources, err := f.p.Resources(f.s)
	limit, found := resources.Quotas.Limit("tenant", "node-a")
	if err != nil || !found || limit.Owner != proof.New || !resources.Quotas.SameOwner("node-a", proof.New, proof.Old) {
		t.Fatal("physical quota lineage changed or old reservations lost", err)
	}
	afterVolume, found := f.view().Native("tenant", "app", "data")
	if !found || volumes.NativeBindingDigest(afterVolume) != volumes.NativeBindingDigest(beforeVolume) {
		t.Fatal("activation rewrote the original native owner fact")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil || f.p.ValidateManaged(f.s, f.s, state.Command{}) != nil {
		t.Fatal("activation snapshot lost cross-root invariants", err)
	}
}
