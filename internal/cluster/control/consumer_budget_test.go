// SPDX-License-Identifier: Apache-2.0

package control

import "testing"

// Deterministic desired-edge projection against the real tenant quota core.
// These edges are not native pin/closure facts.
func TestProjectedConsumerBudgetSumsDifferentSourcesAndTenantsOnOneNode(t *testing.T) {
	f, _, d := managedDNSProjectionFixture(t)
	resources, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	r := ResourceProjection{Resources: resources}
	limit, _ := resources.Quotas.Limit(d.Tenant, "node-a")
	owner := limit.Owner
	edges := func(n int) map[string]bool {
		out := map[string]bool{}
		for i := 0; i < n; i++ {
			out[string(rune('a'+i))] = true
		}
		return out
	}
	used := map[string]networkConsumerUsage{
		"bridge": {tenant: d.Tenant, node: "node-a", owner: owner, consumers: edges(4)},
		"tunnel": {tenant: d.Tenant, node: "node-a", owner: owner, consumers: edges(5)},
	}
	if admitConsumerUsage(r, used, d.Tenant, "node-a", owner) == nil {
		t.Fatal("two individually valid sources bypassed whole-node limit 8")
	}
	other := used["tunnel"]
	other.tenant = "another"
	used["tunnel"] = other
	if admitConsumerUsage(r, used, d.Tenant, "node-a", owner) == nil {
		t.Fatal("another tenant's demand disappeared from global sum")
	}
	other.consumers = edges(4)
	used["tunnel"] = other
	if err := admitConsumerUsage(r, used, d.Tenant, "node-a", owner); err != nil {
		t.Fatal("exact whole-node total 8 rejected", err)
	}
	// The first tenant's limit is 3, even though the other tenant's 4 edges
	// do not consume that scoped budget. Global usage remains exactly 8.
	catalog, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	revision := limit.Revision
	limit.Revision, limit.MaxConsumers = 0, 3
	r.Resources.Quotas, err = resources.Quotas.Set(catalog, "admin", revision, limit, resources.Networks)
	if err != nil {
		t.Fatal(err)
	}
	if admitConsumerUsage(r, used, d.Tenant, "node-a", owner) == nil {
		t.Fatal("node room bypassed target tenant shrink")
	}
	first := used["bridge"]
	first.consumers = edges(3)
	used["bridge"] = first
	if err := admitConsumerUsage(r, used, d.Tenant, "node-a", owner); err != nil {
		t.Fatal("another tenant was charged to scoped budget", err)
	}
	other.owner[0]++
	used["tunnel"] = other
	if admitConsumerUsage(r, used, d.Tenant, "node-a", owner) == nil {
		t.Fatal("foreign source owner entered shared node sum")
	}
}
