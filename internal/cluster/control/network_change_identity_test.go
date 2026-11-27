// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Preparation/install observations are explicit signed inputs. Original
// network, quota, DNS references, planning and receipt replay use product cores.
func TestNetworkChangeCurrentNodeKeepsOriginalSourceThroughTwoIdentityRotations(t *testing.T) {
	f, other, _ := managedDNSProjectionFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	_, configuration := cleanupControlIssuer(t, f)
	d, _ := f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: d.Revision, Configuration: &configuration}, state.Applied)
	original, plan := networkChangeCandidate(t, f)
	originalSources := f.s.Objects(tenancy.ManagedNetworkSourcePrefix)
	before, err := f.p.ProjectResources(f.s)
	if err != nil || before.NetworkAuthority == nil {
		t.Fatal("original reference projection", err)
	}
	originalRefs := before.NetworkAuthority.ReferenceConsumers()
	oldKey := f.node
	for i := 0; i < 2; i++ {
		operation := fmt.Sprintf("network-plan-rotation-%d", i)
		next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(211 + i)}, ed25519.SeedSize))
		d, _ = f.p.Members(f.s)
		entry, _ := d.Entry("node-a")
		f.apply(operation, "rotate-node-identity", entry.Revision, NodeIdentityChange{ID: "node-a", Operation: operation}, state.Applied)
		proof := lifecycle.IdentityProof{Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Operation: operation, Old: [32]byte(oldKey.Public().(ed25519.PublicKey)), New: [32]byte(next.Public().(ed25519.PublicKey)), Prepared: [32]byte{byte(i + 1)}}
		proof.OldSignature = ed25519.Sign(oldKey, lifecycle.IdentityProofBytes(proof))
		proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
		for _, action := range []string{"identity-prepared", "identity-activate", "identity-installed"} {
			signer := oldKey
			if action == "identity-installed" {
				signer = next
			}
			d, _ = f.p.Members(f.s)
			r := MemberReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(signer.Public().(ed25519.PublicKey)), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(MembersKey).Revision, RequestID: operation + "/" + action, Action: action, Node: "node-a", Operation: operation, Expected: d.Revision}
			if action == "identity-prepared" {
				r.Identity = &proof
			}
			r.Signature = ed25519.Sign(signer, MemberReportBytes(r))
			cmd, err := r.Command()
			if err != nil {
				t.Fatal(err)
			}
			updated, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			if err != nil || result.Code != state.Applied {
				t.Fatal(operation, action, result, err)
			}
			f.s = updated
		}
		oldKey = next
	}
	current := [32]byte(oldKey.Public().(ed25519.PublicKey))
	if current == original.Owner {
		t.Fatal("fixture did not rotate native source owner")
	}
	// A retained old SOURCE is valid. An explicitly old TARGET still cannot
	// become a future generation under a historical node key.
	bad := plan
	bad.Target.Owner = original.Owner
	managedDNSChange(t, f, "network-old-target", "plan-network-change", original.Revision, bad, state.Forbidden)
	bad.Target.Owner = [32]byte{99}
	managedDNSChange(t, f, "network-foreign-target", "plan-network-change", original.Revision, bad, state.Forbidden)
	resources, err := f.p.Resources(f.s)
	catalog, catalogErr := f.p.Catalog(f.s)
	policy, policyErr := f.p.Current(f.s)
	if err != nil || catalogErr != nil || policyErr != nil {
		t.Fatal(err, catalogErr, policyErr)
	}
	// cleanupControlIssuer reissued this session from an independent active
	// voter BEFORE rotation. Prove the same current session/scope will pass
	// the guards preceding the exact original-owner check in direct cases.
	if f.session.Issuer == original.Owner || f.session.Issuer == current || !policy.Issuer(f.session.Issuer).Enabled {
		t.Fatal("rotation fixture reused a historical/current source-node issuer")
	}
	if err := catalog.AuthorizeSession(f.session, policy.Cluster, policy.Issuer(f.session.Issuer), 2, original.Tenant, access.ManageNetwork, original.Node); err != nil {
		t.Fatal("current user admission failed before original-owner check", err)
	}
	operation := func(q NetworkChangePlan) UserOperation {
		raw, _ := json.Marshal(q)
		return UserOperation{Session: f.session, At: 2, Change: Change{Principal: "admin", Action: "plan-network-change", Expected: original.Revision, Payload: raw}}
	}
	for name, foreign := range map[string][32]byte{"unrelated-owner": {99}, "other-installed-node": [32]byte(other.Public().(ed25519.PublicKey))} {
		t.Run(name, func(t *testing.T) {
			// Inject a typed source catalog as the boundary's input, using the
			// product catalog constructor rather than changing internal maps.
			networks, _ := tenancy.New(f.p.Cluster)
			source := tenancy.Network{Tenant: "tenant", ID: "foreign-source", Node: original.Node, Owner: foreign, Pools: original.Pools}
			networks, err := networks.Create(catalog, "admin", 0, source)
			if err != nil {
				t.Fatal(err)
			}
			source, _ = networks.Network("tenant", source.ID)
			injected := resources
			injected.Networks = networks
			q := NetworkChangePlan{Tenant: source.Tenant, ID: source.ID, Change: "reject-foreign-source", Target: source}
			q.Target.Owner = [32]byte{}
			q.Target.Generation, q.Target.Revision = 0, 0
			op := operation(q)
			op.Change.Expected = source.Revision
			if _, err := policy.planNetworkChange(f.s, catalog, injected, op); !errors.Is(err, access.ErrDenied) {
				t.Fatal("same node name admitted a foreign original source")
			}
		})
	}
	// A current genesis view with the SAME node name has no retained-key
	// transition. It must not manufacture ownership over the original key.
	empty, err := state.New("anchor")
	if err != nil {
		t.Fatal(err)
	}
	withoutLineage := policy
	withoutLineage.Genesis.Key = hex.EncodeToString(current[:])
	withoutLineage.TrustRoot = current
	if err := catalog.AuthorizeSession(f.session, withoutLineage.Cluster, withoutLineage.Issuer(f.session.Issuer), 2, original.Tenant, access.ManageNetwork, original.Node); err != nil {
		t.Fatal("current user scope failed before missing-lineage test", err)
	}
	currentOnly, ownerErr := withoutLineage.nodeOwner(empty, original.Node)
	if ownerErr != nil || currentOnly != current || withoutLineage.ownsResource(empty, currentOnly, original.Owner) {
		t.Fatal("missing-lineage input did not expose only the current same-named node", ownerErr)
	}
	if _, err := withoutLineage.planNetworkChange(empty, catalog, resources, operation(plan)); !errors.Is(err, access.ErrDenied) {
		t.Fatal("missing installed lineage admitted the original source", err)
	}
	command, receipt := managedDNSChange(t, f, "network-current-plan", "plan-network-change", original.Revision, plan, state.Applied)
	resources, err = f.p.Resources(f.s)
	change, found := resources.Networks.Change(original.Tenant, original.ID)
	retained, exists := resources.Networks.Network(original.Tenant, original.ID)
	if err != nil || !found || !exists || change.Target.Owner != current || change.Original.Owner != original.Owner || retained.Owner != original.Owner || retained.Generation != original.Generation || retained.Revision != original.Revision || !reflect.DeepEqual(retained.Pools, original.Pools) {
		t.Fatal("plan conflated current candidate and original native source", err)
	}
	after, err := f.p.ProjectResources(f.s)
	if err != nil || after.NetworkAuthority == nil || !reflect.DeepEqual(originalSources, f.s.Objects(tenancy.ManagedNetworkSourcePrefix)) || !reflect.DeepEqual(originalRefs, after.NetworkAuthority.ReferenceConsumers()) {
		t.Fatal("metadata reservation rewrote original native bytes or reference lifetimes", err)
	}
	next, replay, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || replay != receipt || next.Object(ResourcesKey) != f.s.Object(ResourcesKey) || next.Object(AppsKey) != f.s.Object(AppsKey) {
		t.Fatal("original result replay replanned or changed retained sources", err, replay, receipt)
	}
}
