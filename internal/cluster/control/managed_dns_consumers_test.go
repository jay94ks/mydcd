// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

func TestManagedDNSConsumerCoreDesiredAndOriginalUnclosedInstances(t *testing.T) {
	f, _, definition := managedDNSProjectionFixture(t)
	bridge := func(node string) string {
		return (tenancy.SourceIdentity{Kind: "bridge", Tenant: "tenant", Network: "services", Node: node}).Key()
	}
	check := func(a, b int) {
		t.Helper()
		projection, err := f.p.ProjectResources(f.s)
		if err != nil || projection.ManagedDNSConsumers[bridge("node-a")] != a || projection.ManagedDNSConsumers[bridge("node-b")] != b {
			t.Fatal("desired/original demand", projection.ManagedDNSConsumers, a, b, err)
		}
	}
	check(1, 1) // Before any shared/native instance exists.
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	check(1, 1) // Desired + the same original reference is ONE consumer.
	key := services.ManagedDNSKey("tenant", "services")
	definition.Policy.Enabled = false
	managedDNSChange(t, f, "consumer-disable", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
	check(1, 1)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	check(1, 1) // Disabled publication is not native closure.
	apps, _ := f.p.Apps(f.s)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	authority, rows, _ := apps.NetworkDNS(owner)
	ref, _ := authority.ReferenceConsumer(rows[0].Reference)
	// Injected positive facts test budget lifetime only, not actual I/O/TTL.
	proof := services.ReferenceClose{Cluster: f.p.Cluster, Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: owner, Boot: [32]byte{8}, At: 200, Native: "mock-dns-stopped", Fenced: true, Settled: true, TTLExpired: true}
	proof.Signature = ed25519.Sign(f.node, services.ReferenceCloseBytes(proof))
	report, err := f.p.ManagedDNSClosure(f.s, owner, proof, 200)
	if err != nil {
		t.Fatal(err)
	}
	report.Signature = ed25519.Sign(f.node, NetworkDNSProgressBytes(report))
	applyDNSCoreReport(t, f, report, state.Applied)
	check(0, 1) // The other original owner retains its own native demand.
}

func TestManagedDNSConsumerCorePolicyAndTaskCannotBypassSharedBridgeBudget(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	task := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "shared")
	managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a"), true, state.Applied)
	resources, _ := f.p.Resources(f.s)
	limit, _ := resources.Quotas.Limit("", "node-a")
	set := func(id string, capacity int) {
		t.Helper()
		resources, _ := f.p.Resources(f.s)
		current, _ := resources.Quotas.Limit("", "node-a")
		limit.Revision = 0
		limit.MaxConsumers = capacity
		f.apply(id, "set-node-quota", current.Revision, limit, state.Applied)
	}
	// DNS + app borrow's separate Bridge/TUN pins + the member's packet plane
	// occupy four node-wide consumers. The next Task needs a fifth slot.
	set("consumer-exact-limit", 4)
	before := f.s.Object(task)
	managedDNSTaskCoreSubmit(t, f, "first", task, false, state.Invalid)
	if f.s.Object(task) != before {
		t.Fatal("over-budget Task was committed")
	}
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, held := projection.Addresses.Allocation(task + "/lan/0"); held {
		t.Fatal("over-budget Task leaked an address")
	}
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, _ := f.p.Apps(f.s)
	_, rows, _ := apps.NetworkDNS([32]byte(f.node.Public().(ed25519.PublicKey)))
	request := NativeRequest{Source: rows[0].Source, DNS: rows[0].Config.ID}
	if _, err := f.p.NativePermit(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), request); err != nil {
		t.Fatal("exact planned/original consumer budget", err)
	}
	set("consumer-shrink", 3)
	if _, err := f.p.NativePermit(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), request); err == nil {
		t.Fatal("new native DNS effect bypassed original app borrow")
	}
	key := services.ManagedDNSKey("tenant", "services")
	sources, _ := f.p.ManagedDNS(f.s)
	definition := sources[key].Definition
	definition.Policy.TTL++
	original := f.s.Object(key)
	managedDNSChange(t, f, "consumer-policy-denied", "configure-network-dns", original.Revision, definition, state.ConditionFailed)
	if f.s.Object(key) != original {
		t.Fatal("over-budget enabled policy replaced original source")
	}
	definition.Policy.Enabled = false
	managedDNSChange(t, f, "consumer-cleanup-allowed", "configure-network-dns", original.Revision, definition, state.Applied)
	projection, err = f.p.ProjectResources(f.s)
	bridge := (tenancy.SourceIdentity{Kind: "bridge", Tenant: "tenant", Network: "services", Node: "node-a"}).Key()
	if err != nil || projection.ManagedDNSConsumers[bridge] != 1 {
		t.Fatal("cleanup disabled metadata freed an unclosed native pin", err)
	}
}
