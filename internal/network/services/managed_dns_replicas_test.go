// SPDX-License-Identifier: Apache-2.0

package services

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestManagedDNSReplicaNamesShareLogicalOwnerButKeepExactTaskEndpoints(t *testing.T) {
	d := ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: "services"}
	registrations := []DNSRegistration{
		{Tenant: "tenant", Network: "services", App: "shop", Service: "web", Task: "workload/task/tenant/shop/web/node-a/r1", Aliases: []string{"public"}, Addresses: []DNSAddressReference{{Endpoint: "workload/task/tenant/shop/web/node-a/r1/app/0", Generation: 7}}},
		{Tenant: "tenant", Network: "services", App: "shop", Service: "web", Task: "workload/task/tenant/shop/web/node-b/r1", Aliases: []string{"public"}, Addresses: []DNSAddressReference{{Endpoint: "workload/task/tenant/shop/web/node-b/r1/app/0", Generation: 12}}},
	}
	names, err := d.registrationNames("apps.sfc.test.", registrations)
	if err != nil || len(names) != 4 {
		t.Fatal("logical service replicas cannot share their default and explicit names", names, err)
	}
	for _, label := range []string{"web.shop.apps.sfc.test.", "public.apps.sfc.test."} {
		var endpoints []string
		for _, name := range names {
			if name.Name == label {
				endpoints = append(endpoints, name.Endpoint)
			}
		}
		if len(endpoints) != 2 || endpoints[0] == endpoints[1] {
			t.Fatal("name lost an exact replica address", label, endpoints)
		}
	}
	slices.Reverse(registrations)
	reversed, err := d.registrationNames("apps.sfc.test.", registrations)
	originalJSON, _ := json.Marshal(names)
	reversedJSON, _ := json.Marshal(reversed)
	if err != nil || string(originalJSON) != string(reversedJSON) {
		t.Fatal("registration input order changed the DNS projection")
	}
	for _, mutate := range []func(*[]DNSRegistration){
		func(r *[]DNSRegistration) { *r = append(*r, (*r)[0]) },
		func(r *[]DNSRegistration) { (*r)[0].Task = "workload/task/tenant/foreign/web/node-b/r1" },
		func(r *[]DNSRegistration) { (*r)[0].Task = "workload/task/tenant/shop/web/node-b/r01" },
		func(r *[]DNSRegistration) { (*r)[0].Task = "workload/task/tenant/shop/web/node-b/r129" },
		func(r *[]DNSRegistration) { (*r)[0].Addresses[0].Endpoint = (*r)[1].Addresses[0].Endpoint },
		func(r *[]DNSRegistration) { (*r)[0].Aliases = []string{"PUBLIC", "public"} },
		func(r *[]DNSRegistration) {
			(*r)[0].Service = "api"
			(*r)[0].Task = "workload/task/tenant/shop/api/node-b/r1"
			(*r)[0].Addresses[0].Endpoint = "workload/task/tenant/shop/api/node-b/r1/app/0"
		},
	} {
		raw, _ := json.Marshal(registrations)
		var bad []DNSRegistration
		_ = json.Unmarshal(raw, &bad)
		mutate(&bad)
		if _, err := d.registrationNames("apps.sfc.test.", bad); err == nil {
			t.Fatal("foreign, duplicate, or mismatched replica registration accepted", bad)
		}
	}
}
