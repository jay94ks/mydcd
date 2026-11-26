// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"github.com/jay94ks/mydcd/internal/network/services"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

func TestManagedDNSBorrowerRetirementCoreSelectsOnlyOriginalAppAddresses(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	first := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first-alias")
	second := managedDNSTaskCoreBegin(t, f, "second", "10.80.1.11", "second-alias")
	for _, app := range []string{"first", "second"} {
		managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a"), true, state.Applied)
		task := deployment.ResourceKey("task", "tenant", app, "web")
		managedDNSTaskCoreSubmit(t, f, app, task, false, state.Applied)
		managedDNSTaskCoreProgress(t, f, app, "collect", task, nil)
	}
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	other := f.s.Object(second)
	apps, _ := f.p.Apps(f.s)
	i, _ := apps.Inventory("tenant", "first")
	managedDNSChange(t, f, "stop-first-with-held-address", "down-app", i.Revision(), AppDown{Tenant: "tenant", App: "first", Operation: "stop-first"}, state.Applied)
	apps, _ = f.p.Apps(f.s)
	key := deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a")
	allocations, err := apps.NetworkRetirementAllocations("tenant", "first", key)
	if err != nil || len(allocations) != 1 || allocations[0].Endpoint != first+"/lan/0" || allocations[0].Generation != f.s.Object(first).Generation || allocations[0].Address.String() != "10.80.1.10" {
		t.Fatal("borrower selected shared/foreign pool addresses", allocations, err)
	}
	if f.s.Object(second) != other {
		t.Fatal("one app down modified another original Task")
	}
	if _, err := apps.NetworkRetirementAllocations("tenant", "second", key); err == nil {
		t.Fatal("another app acquired the original retirement scope")
	}
	if _, err := apps.NetworkRetirementAllocations("tenant", "first", first); err == nil {
		t.Fatal("a Task was treated as authority over the shared network")
	}
	entry := apps.entries[appKey("tenant", "first")]
	if _, err := f.p.closeAppNetwork(f.s, AppProgress{Tenant: "tenant", App: "first", Key: key, Retire: &AppRetirementProgress{}}, apps, entry); err == nil {
		t.Fatal("borrower Gone bypassed original address/query/TTL settlement")
	}
}

// Original owner closure is modeled here; the E7 native DNS scenario checks
// actual Stop/join/TTL/Bridge return and retained app redeployment.
func TestManagedDNSPlacementWithdrawalKeepsPolicyAndClosesOriginalBeforeRestore(t *testing.T) {
	f, second, definition := managedDNSProjectionFixture(t)
	key := services.ManagedDNSKey(definition.Tenant, definition.Network)
	originalSource := f.s.Object(key)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	first := apps.network.Groups[0]
	catalog, _ := f.p.Catalog(f.s)
	tenant, _ := catalog.Tenant(definition.Tenant)
	f.apply("placement-withdraw", "set-nodes", tenant.Revision, NodeAssignment{Tenant: tenant.ID, Nodes: []string{"node-a"}}, state.Applied)
	// Every member is required for the logical view. One revoked member must
	// stop the whole view's original admission without editing declared policy.
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	disabled := apps.network.Groups[0]
	if managedDNSGroupEnabled(disabled) || disabled.Source <= first.Source || f.s.Object(key) != originalSource {
		t.Fatal("placement withdrawal reset policy or did not fence serving")
	}
	for _, signer := range []ed25519.PrivateKey{f.node, second} {
		owner := [32]byte(signer.Public().(ed25519.PublicKey))
		_, rows, _ := apps.NetworkDNS(owner)
		if len(rows) != 1 {
			t.Fatal("original owner disappeared")
		}
		material, _, err := f.p.AppDNSMaterial(f.s, owner, definition.Tenant, rows[0].Config.ID)
		if err != nil || material.Config.Enabled {
			t.Fatal("cleanup material required a revoked placement grant", err)
		}
		if _, err = f.p.NativePermit(f.s, owner, NativeRequest{Source: rows[0].Source, DNS: rows[0].Config.ID}); err == nil {
			t.Fatal("disabled owner acquired new native admission")
		}
	}
	catalog, _ = f.p.Catalog(f.s)
	tenant, _ = catalog.Tenant(definition.Tenant)
	f.apply("placement-restore-before-close", "set-nodes", tenant.Revision, NodeAssignment{Tenant: tenant.ID, Nodes: []string{"node-a", "node-b"}}, state.Applied)
	replacement := definition
	replacement.Policy.TTL++
	managedDNSChange(t, f, "no-replace-closing-placement", "configure-network-dns", originalSource.Revision, replacement, state.ConditionFailed)
	for _, signer := range []ed25519.PrivateKey{f.node, second} {
		updates, err := f.p.ManagedDNSUpdates(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)))
		if err != nil || len(updates) != 0 {
			t.Fatal("restored permission bypassed original close", err)
		}
		apps, _ = f.p.Apps(f.s)
		owner := [32]byte(signer.Public().(ed25519.PublicKey))
		authority, rows, _ := apps.NetworkDNS(owner)
		ref, _ := authority.ReferenceConsumer(rows[0].Reference)
		proof := services.ReferenceClose{Cluster: f.p.Cluster, Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: owner, Boot: [32]byte{8}, At: 200, Native: "modeled-original-dns", Fenced: true, Settled: true, TTLExpired: true}
		proof.Signature = ed25519.Sign(signer, services.ReferenceCloseBytes(proof))
		report, err := f.p.ManagedDNSClosure(f.s, owner, proof, 200)
		if err != nil {
			t.Fatal("original closure after permission restore", err)
		}
		report.Signature = ed25519.Sign(signer, NetworkDNSProgressBytes(report))
		applyDNSCoreReport(t, f, report, state.Applied)
	}
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	resumed := apps.network.Groups[0]
	if !managedDNSGroupEnabled(resumed) || resumed.Source <= disabled.Source || resumed.Serial <= disabled.Serial || f.s.Object(key) != originalSource {
		t.Fatal("restored placement reset lifetime/version or changed policy")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.p.Validate(restored, restored, state.Command{}); err != nil {
		t.Fatal("resumed checkpoint", err)
	}
}
