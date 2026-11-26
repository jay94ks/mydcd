// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/miekg/dns"
)

func managedDNSFixture(t *testing.T) (networkFixture, ManagedDNSDefinition, []DNSRegistration) {
	t.Helper()
	f := fixture(t)
	tenant, _ := f.c.Tenant("first")
	var err error
	f.c, err = f.c.SetNodes("admin", "first", tenant.Revision, []string{"node-a", "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	q, _ := tenancy.NewQuotas(f.n.Cluster())
	for _, scope := range []string{"", "first"} {
		for _, node := range []string{"node-a", "node-b"} {
			owner := pub(f.key)
			if node == "node-b" {
				owner = pub(private(32))
			}
			q, err = q.Set(f.c, "admin", 0, tenancy.NodeLimit{Tenant: scope, Node: node, Owner: owner, Networks: 4, Capacity: workload.Resources{CPU: 4e9, Memory: 4 << 30}, MaxConsumers: 8}, f.n)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	d := tenancy.TUNDefinition{Tenant: "first", Name: "shared", Members: []tenancy.TUNNode{
		{Node: "node-a", Owner: pub(f.key), Pools: []tenancy.Subnet{{ID: "four", Prefix: netip.MustParsePrefix("10.60.0.0/24"), Gateway: addr("10.60.0.1"), MTU: 1280}, {ID: "six", Prefix: netip.MustParsePrefix("2001:db8:60::/64"), Gateway: addr("2001:db8:60::1"), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix("10.62.0.1/32"), netip.MustParsePrefix("2001:db8:62::1/128")}},
		{Node: "node-b", Owner: pub(private(32)), Pools: []tenancy.Subnet{{ID: "four", Prefix: netip.MustParsePrefix("10.61.0.0/24"), Gateway: addr("10.61.0.1"), MTU: 1280}, {ID: "six", Prefix: netip.MustParsePrefix("2001:db8:61::/64"), Gateway: addr("2001:db8:61::1"), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix("10.62.0.2/32"), netip.MustParsePrefix("2001:db8:62::2/128")}},
	}}
	f.n, err = f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), d)
	if err != nil {
		t.Fatal(err)
	}
	f.a, err = f.a.SyncPools(f.n)
	if err != nil {
		t.Fatal(err)
	}
	f.a, err = f.a.ResizeAddresses(128)
	if err != nil {
		t.Fatal(err)
	}
	var registrations []DNSRegistration
	for i, item := range []struct{ node, service, alias, ipv4, ipv6 string }{
		{"node-a", "api", "public", "10.60.0.10", "2001:db8:60::10"},
		{"node-b", "database", "storage", "10.61.0.10", "2001:db8:61::10"},
	} {
		local, ok := f.n.NamedNetwork("first", "shared", item.node)
		if !ok {
			t.Fatal("managed member")
		}
		r := DNSRegistration{Tenant: "first", Network: "shared", App: "sample", Service: item.service, Aliases: []string{item.alias}}
		for family, ip := range []string{item.ipv4, item.ipv6} {
			pool, suffix := "four", "0"
			if family == 1 {
				pool, suffix = "six", "1"
			}
			endpoint := "workload/task/first/sample/" + item.service + "/app/" + suffix
			var allocation network.Allocation
			f.a, allocation, err = f.a.ReserveStatic(endpoint, poolOwner(Source{Owner: local.Owner}), "first/"+local.ID, "first/"+local.ID+"/"+pool, uint64(41+i), addr(ip))
			if err != nil {
				t.Fatal(err)
			}
			r.Addresses = append(r.Addresses, DNSAddressReference{Endpoint: allocation.Endpoint, Generation: allocation.Generation})
		}
		registrations = append(registrations, r)
	}
	return f, ManagedDNSDefinition{Schema: 1, Tenant: "first", Network: "shared", Policy: ManagedDNSPolicy{Enabled: true, Reverse: true, Zone: "apps.mydc.test.", TTL: 30, NegativeTTL: 5, Transports: []string{"udp", "tcp"}, MaxQueries: 8, MaxCacheEntries: 8, MaxResponseBytes: 4096, MaxConnections: 4, RequestTimeoutMS: 1000}}, registrations
}

func TestManagedDNSDefinitionReusesAuthorityAcrossOwnersAndPools(t *testing.T) {
	f, definition, registrations := managedDNSFixture(t)
	before := encode(t, f.a)
	plans, err := definition.Plans(f.c, f.n, f.a, "admin", 77, 4, registrations)
	if err != nil || len(plans) != 4 {
		t.Fatal("two owners/two pools", len(plans), err)
	}
	if ManagedDNSKey("first", "shared") != "control/network-services/dns/first/shared" || ManagedDNSKey("first", "../other") != "" {
		t.Fatal("managed source scope")
	}
	if !bytes.Equal(before, encode(t, f.a)) {
		t.Fatal("read-only plan allocated or changed authority")
	}
	for _, plan := range plans {
		if plan.Config.Source != 77 || plan.Config.Serial != 4 || len(plan.Config.Names) != 8 || len(plan.Config.Members) != 2 || plan.BridgeKey != (tenancy.SourceIdentity{Kind: "bridge", Tenant: "first", Network: "shared", Node: plan.Node}).Key() {
			t.Fatal("lost original management/member identity")
		}
		m, err := NewDNSManager(f.n.Cluster(), plan.Owner, []string{"mydc.test."}, 8, 8)
		if err != nil {
			t.Fatal(err)
		}
		originEndpoint := "workload/task/first/sample/api/app/0"
		if plan.Node == "node-b" {
			originEndpoint = "workload/task/first/sample/database/app/0"
		}
		if plan.Config.Pool == "six" {
			originEndpoint = originEndpoint[:len(originEndpoint)-1] + "1"
		}
		origin, _ := f.a.AddressBook().Allocation(originEndpoint)
		d := dnsFixture{f: f, m: m, cfg: plan.Config, origin: origin}
		d = publishDNS(t, d, d.cfg, 190)
		for _, q := range []struct {
			name    string
			kind    uint16
			address string
		}{
			{"storage.apps.mydc.test.", dns.TypeA, "10.61.0.10"},
			{"database.sample.apps.mydc.test.", dns.TypeAAAA, "2001:db8:61::10"},
			{"public.apps.mydc.test.", dns.TypeA, "10.60.0.10"},
		} {
			var answer DNSResult
			d, answer = askDNS(t, d, q.name, q.kind, 200)
			if answer.Response == nil || len(answer.Response.Answer) != 1 {
				t.Fatal("not an actual reusable DNS answer", q.name)
			}
			actual := ""
			switch record := answer.Response.Answer[0].(type) {
			case *dns.A:
				actual = record.A.String()
			case *dns.AAAA:
				actual = record.AAAA.String()
			}
			if actual != q.address {
				t.Fatal("wrong committed allocation", actual, q.address)
			}
		}
	}
}

func TestManagedDNSDefinitionRejectsForeignStaleAmbiguousRegistrations(t *testing.T) {
	f, definition, original := managedDNSFixture(t)
	for _, item := range []struct {
		name   string
		mutate func(*[]DNSRegistration)
	}{
		{"tenant", func(r *[]DNSRegistration) { (*r)[0].Tenant = "other" }},
		{"network", func(r *[]DNSRegistration) { (*r)[0].Network = "other" }},
		{"foreign-task", func(r *[]DNSRegistration) { (*r)[0].App = "other" }},
		{"unknown-endpoint", func(r *[]DNSRegistration) { (*r)[0].Addresses[0].Endpoint = "workload/task/first/sample/api/missing/0" }},
		{"stale-generation", func(r *[]DNSRegistration) { (*r)[0].Addresses[0].Generation++ }},
		{"duplicate-service", func(r *[]DNSRegistration) { *r = append(*r, (*r)[0]) }},
		{"duplicate-endpoint", func(r *[]DNSRegistration) { (*r)[0].Addresses[1] = (*r)[0].Addresses[0] }},
		{"alias-conflict", func(r *[]DNSRegistration) { (*r)[1].Aliases = []string{"PUBLIC"} }},
		{"default-name-conflict", func(r *[]DNSRegistration) { (*r)[1].Aliases = []string{"api.sample"} }},
		{"duplicate-alias", func(r *[]DNSRegistration) { (*r)[0].Aliases = []string{"public", "PUBLIC"} }},
		{"out-of-zone", func(r *[]DNSRegistration) { (*r)[0].Aliases = []string{"outside.invalid."} }},
		{"reserved-ns", func(r *[]DNSRegistration) { (*r)[0].Aliases = []string{"ns"} }},
		{"zone-apex", func(r *[]DNSRegistration) { (*r)[0].Aliases = []string{"apps.mydc.test."} }},
		{"empty-addresses", func(r *[]DNSRegistration) { (*r)[0].Addresses = nil }},
	} {
		t.Run(item.name, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var regs []DNSRegistration
			_ = json.Unmarshal(raw, &regs)
			item.mutate(&regs)
			plans, err := definition.Plans(f.c, f.n, f.a, "admin", 77, 4, regs)
			if err == nil || plans != nil {
				t.Fatal("invalid registration produced a partial/accepted plan")
			}
		})
	}
}

func TestManagedDNSDefinitionSettingsOrderingOwnershipAndAuthority(t *testing.T) {
	f, definition, registrations := managedDNSFixture(t)
	before, _ := json.Marshal(registrations)
	plans, err := definition.Plans(f.c, f.n, f.a, "admin", 77, 4, registrations)
	if err != nil {
		t.Fatal(err)
	}
	reversed := slices.Clone(registrations)
	slices.Reverse(reversed)
	other, err := definition.Plans(f.c, f.n, f.a, "admin", 77, 4, reversed)
	x, _ := json.Marshal(plans)
	y, _ := json.Marshal(other)
	if err != nil || !bytes.Equal(x, y) {
		t.Fatal("registration order changed committed projection", err)
	}
	plans[0].Config.Names[0].Name = "other.invalid."
	plans[0].Config.Members[0] = "other"
	after, _ := json.Marshal(registrations)
	if !bytes.Equal(before, after) || other[0].Config.Names[0].Name == "other.invalid." || other[0].Config.Members[0] == "other" {
		t.Fatal("returned plan aliases input/another plan")
	}
	for _, mutate := range []func(*ManagedDNSDefinition){
		func(d *ManagedDNSDefinition) { d.Schema = 2 }, func(d *ManagedDNSDefinition) { d.Network = "lan" },
		func(d *ManagedDNSDefinition) { d.Policy.TTL = 0 }, func(d *ManagedDNSDefinition) { d.Policy.NegativeTTL = 31 },
		func(d *ManagedDNSDefinition) { d.Policy.MaxQueries = 0 }, func(d *ManagedDNSDefinition) { d.Policy.MaxConnections = 0 },
		func(d *ManagedDNSDefinition) { d.Policy.Transports = []string{"udp", "udp"} }, func(d *ManagedDNSDefinition) { d.Policy.RequestTimeoutMS = 60001 },
		func(d *ManagedDNSDefinition) {
			d.Policy.Upstreams = []netip.AddrPort{netip.MustParseAddrPort("10.60.0.1:53")}
		},
		func(d *ManagedDNSDefinition) { d.Policy.ClientZone = "apps.mydc.test." },
	} {
		d := definition
		mutate(&d)
		if plans, err := d.Plans(f.c, f.n, f.a, "admin", 77, 4, registrations); err == nil || plans != nil {
			t.Fatal("invalid server policy accepted")
		}
	}
	tenant, _ := f.c.Tenant("first")
	restricted, err := f.c.SetNodes("admin", "first", tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if plans, err := definition.Plans(restricted, f.n, f.a, "admin", 77, 4, registrations); err == nil || plans != nil {
		t.Fatal("partial member authority accepted")
	}
	emptyBook, err := f.n.AddressPlan(128)
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := NewAuthority(f.n.Cluster(), emptyBook)
	if plans, err := definition.Plans(f.c, f.n, empty, "admin", 77, 4, registrations); err == nil || plans != nil {
		t.Fatal("invented generation/address readiness")
	}
	if plans, err := definition.Plans(f.c, f.n, f.a, "admin", 0, 4, nil); err == nil || plans != nil {
		t.Fatal("missing shared source accepted")
	}
	definition.Policy.Enabled = false
	if _, err := definition.Plans(f.c, f.n, f.a, "admin", 78, 5, registrations); err != nil {
		t.Fatal("explicit disable lost original names", err)
	}
}
