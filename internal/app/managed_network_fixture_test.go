// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"gopkg.in/yaml.v3"
)

// Fixture preparation separates the old sample's management inputs. It never
// runs a second allocator or turns omitted/unsupported policy into defaults.
func managedSampleNetworkInputs(t *testing.T, raw []byte, names map[string]string) ([]byte, []byte) {
	t.Helper()
	c, err := deployment.ParseCompose(raw)
	if err != nil {
		t.Fatal(err)
	}
	type change struct {
		ID       string `yaml:"id"`
		Action   string `yaml:"action"`
		Expected uint64 `yaml:"expected"`
		Payload  any    `yaml:"payload"`
	}
	partial := struct {
		Schema  uint8    `yaml:"schema"`
		Tenant  string   `yaml:"tenant"`
		Changes []change `yaml:"changes"`
	}{Schema: 1, Tenant: c.MyDC.Tenant}
	if partial.Tenant == "" {
		// app.yaml no longer names its tenant; these fixtures all use "tenant".
		partial.Tenant = "tenant"
	}
	aliases := make([]string, 0, len(c.Networks))
	for alias := range c.Networks {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)
	for i, alias := range aliases {
		n := c.Networks[alias]
		if n.External || n.MyDC.RuntimeChanges != nil || names[alias] == "" {
			t.Fatal("sample needs explicit management-service preparation", alias)
		}
		d := tenancy.TUNDefinition{Tenant: partial.Tenant, Name: names[alias]}
		nodes := make([]string, 0, len(n.MyDC.Pools))
		for node := range n.MyDC.Pools {
			nodes = append(nodes, node)
		}
		slices.Sort(nodes)
		for _, node := range nodes {
			pool := n.MyDC.Pools[node]
			prefix, e := netip.ParsePrefix(pool.CIDR)
			if e != nil {
				t.Fatal(e)
			}
			gateway, e := netip.ParseAddr(pool.Gateway)
			if e != nil {
				t.Fatal(e)
			}
			address, e := netip.ParsePrefix(n.MyDC.TunnelAddresses[node])
			if e != nil {
				t.Fatal(e)
			}
			d.Members = append(d.Members, tenancy.TUNNode{Node: node, Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefix, Gateway: gateway, MTU: n.MyDC.MTU}}, Addresses: []netip.Prefix{address}})
		}
		encoded, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err = json.Unmarshal(encoded, &payload); err != nil {
			t.Fatal(err)
		}
		partial.Changes = append(partial.Changes, change{ID: alias, Action: "create-tun-network", Expected: uint64(i), Payload: payload})
		if dns := n.MyDC.DNS; dns != nil {
			if len(dns.Records) != 0 {
				t.Fatal("explicit DNS records need an explicit app alias mapping", alias)
			}
			policy := services.ManagedDNSPolicy{Enabled: dns.Enabled, Reverse: dns.Reverse, Zone: dns.Zone, TTL: dns.TTL, NegativeTTL: dns.NegativeTTL, Transports: slices.Clone(dns.Transports), Upstreams: []netip.AddrPort{}, MaxQueries: dns.Limits.Inflight, MaxCacheEntries: dns.Limits.Cache, MaxResponseBytes: 4096, MaxConnections: dns.Limits.TCP, RequestTimeoutMS: dns.Limits.Timeout}
			if !dns.Forward.Enabled && len(dns.Forward.Upstreams) != 0 {
				t.Fatal("disabled forward cannot discard explicit upstreams", alias)
			}
			for _, raw := range dns.Forward.Upstreams {
				upstream, err := netip.ParseAddrPort(raw)
				if err != nil {
					t.Fatal(err)
				}
				policy.Upstreams = append(policy.Upstreams, upstream)
			}
			definition := services.ManagedDNSDefinition{Schema: 1, Tenant: partial.Tenant, Network: names[alias], Policy: policy}
			encoded, err := json.Marshal(definition)
			if err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			if err = json.Unmarshal(encoded, &payload); err != nil {
				t.Fatal(err)
			}
			partial.Changes = append(partial.Changes, change{ID: "dns-" + alias, Action: "configure-network-dns", Expected: 0, Payload: payload})
			if dns.Enabled {
				for name, service := range c.Services {
					attachment, attached := service.Networks[alias]
					if !attached {
						continue
					}
					if !slices.ContainsFunc(attachment.Aliases, func(current string) bool { return strings.EqualFold(current, name) }) {
						attachment.Aliases = append(attachment.Aliases, name)
					}
					service.Networks[alias] = attachment
					pool, exists := n.MyDC.Pools[service.MyDC.Node]
					if !exists {
						t.Fatal("explicit node resolver is required", name)
					}
					if service.DNS == nil {
						service.DNS = []string{pool.Gateway}
					}
					if service.DNSSearch == nil {
						service.DNSSearch = []string{strings.TrimSuffix(dns.Zone, ".")}
					}
					c.Services[name] = service
				}
			}
		}
		c.Networks[alias] = deployment.ComposeNetwork{External: true, Name: names[alias]}
	}
	if err = c.ValidateApp(); err != nil {
		t.Fatal(err)
	}
	app, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return app, mustFixtureYAML(t, partial)
}

func mustFixtureYAML(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
