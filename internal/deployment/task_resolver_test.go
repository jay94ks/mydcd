// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/workload"
)

func TestTaskRecipeResolverPreservesExplicitEmptyAndManagedInputs(t *testing.T) {
	f, baseline, material := taskMaterialFixture(t)
	for _, test := range []struct {
		name            string
		servers, search []string
		managed         bool
		want            *workload.Resolver
	}{
		{name: "unspecified"},
		{name: "explicit", servers: []string{"10.240.20.2"}, search: []string{"explicit.mydc.test"}, want: &workload.Resolver{Servers: []netip.Addr{netip.MustParseAddr("10.240.20.2")}, Search: []string{"explicit.mydc.test"}}},
		{name: "explicit-empty", servers: []string{}, search: []string{}, managed: true, want: &workload.Resolver{Search: []string{}}},
		{name: "managed", managed: true, want: &workload.Resolver{Servers: []netip.Addr{netip.MustParseAddr("10.240.20.1")}, Search: []string{"app.mydc.test"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, _ := json.Marshal(baseline.d.Input)
			var input Compose
			_ = json.Unmarshal(raw, &input)
			s := input.Services["db"]
			s.DNS, s.DNSSearch = test.servers, test.search
			input.Services["db"] = s
			ctx := contextFor(t, f)
			if test.managed {
				n := input.Networks["app"]
				n.MyDC.DNS = &DNSDeclaration{Enabled: true, Zone: "app.mydc.test", TTL: 30, NegativeTTL: 5, Transports: []string{"tcp", "udp"}}
				n.MyDC.DNS.Limits.Cache, n.MyDC.DNS.Limits.Inflight, n.MyDC.DNS.Limits.TCP, n.MyDC.DNS.Limits.Timeout = 4, 8, 4, 1000
				input.Networks["app"] = n
				ctx.Features["network-services"] = true
			}
			b, err := Compile(input, f.c, ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, spec, err := b.taskRecipe("db", material, material.Bridge.Owner)
			if err != nil || !reflect.DeepEqual(spec.Resolver, test.want) {
				t.Fatal("resolver lost or overwritten", spec.Resolver, test.want, err)
			}
			if test.servers != nil && len(test.servers) > 0 {
				spec.Resolver.Servers[0] = netip.MustParseAddr("192.0.2.1")
				if b.d.Input.Services["db"].DNS[0] != "10.240.20.2" {
					t.Fatal("native result aliased immutable input")
				}
			}
		})
	}
}
