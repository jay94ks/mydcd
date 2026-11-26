// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/workload"
	"net/netip"
	"slices"
)

func (s ComposeService) resolverSpec() (*workload.Resolver, error) {
	if s.DNS == nil && s.DNSSearch == nil {
		return nil, nil
	}
	r := &workload.Resolver{Search: slices.Clone(s.DNSSearch)}
	for _, ip := range s.DNS {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, ErrInputs
		}
		r.Servers = append(r.Servers, a)
	}
	if r.Validate() != nil {
		return nil, ErrInputs
	}
	return r, nil
}

// Replicas share the managed DNS registration of their logical service. Use
// the node-local gateway and app-qualified search zone from that same current
// managed policy, rather than Docker's node-local name registry.
func resolveReplicaDNS(b Blueprint, ctx PlanningContext, instance TaskInstance, service ComposeService, networks map[string]ComposeNetwork, borrowed map[string]NetworkReference) (ComposeService, error) {
	if instance.Ordinal == 0 {
		return service, nil
	}
	var servers, search []string
	for _, alias := range mapKeys(service.Networks) {
		definition := networks[alias]
		if !definition.External {
			if definition.MyDC.DNS == nil || !definition.MyDC.DNS.Enabled {
				return service, inputError("REPLICA_DNS_REQUIRED", alias)
			}
			continue
		}
		reference, ok := borrowed[ResourceKey("network-ref", b.d.Tenant, b.d.App, alias+"/"+instance.Node)]
		key := services.ManagedDNSKey(b.d.Tenant, reference.ManagedName)
		object := ctx.Current[key]
		var source services.ManagedDNSSource
		if !ok || !ctx.Features["managed-dns"] || !object.Present || object.Generation == 0 || object.Revision < object.Generation || json.Unmarshal([]byte(object.Value), &source) != nil || source.Schema != 1 || source.Cluster != b.d.Cluster || !identifier(source.Principal) || source.Definition.Schema != 1 || services.ManagedDNSKey(source.Definition.Tenant, source.Definition.Network) != key || !source.Definition.Policy.Enabled {
			return service, inputError("REPLICA_DNS_REQUIRED", alias)
		}
		zone, err := services.Domain(source.Definition.Policy.Zone)
		if err != nil {
			return service, err
		}
		for _, pool := range reference.Pools {
			if !slices.Contains(servers, pool.Gateway.String()) {
				servers = append(servers, pool.Gateway.String())
			}
		}
		for _, domain := range []string{b.d.App + "." + zone, zone} {
			if !slices.Contains(search, domain) {
				search = append(search, domain)
			}
		}
	}
	if service.DNS == nil && len(servers) != 0 {
		service.DNS = servers
	}
	if service.DNSSearch == nil && len(search) != 0 {
		service.DNSSearch = search
	}
	_, err := service.resolverSpec()
	return service, err
}

// Resolve only omitted native resolver inputs from the declared managed network.
// The same helper is used for planning and source/snapshot correspondence. A
// changed zone/gateway changes the task spec; TTL/cache changes do not.
func resolveServiceDNS(service ComposeService, networks map[string]ComposeNetwork) ComposeService {
	var servers, search []string
	for _, id := range mapKeys(service.Networks) {
		network := networks[id]
		if network.External || network.MyDC.DNS == nil || !network.MyDC.DNS.Enabled {
			continue
		}
		pool, ok := network.MyDC.Pools[service.MyDC.Node]
		if !ok {
			continue
		}
		if !slices.Contains(servers, pool.Gateway) {
			servers = append(servers, pool.Gateway)
		}
		if !slices.Contains(search, network.MyDC.DNS.Zone) {
			search = append(search, network.MyDC.DNS.Zone)
		}
	}
	if service.DNS == nil {
		service.DNS = servers
	}
	if service.DNSSearch == nil {
		service.DNSSearch = search
	}
	return service
}
