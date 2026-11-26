// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// Desired definitions and original live instances reserve the same consumer.
// Disabled metadata never proves that the corresponding native pin is gone.
func managedDNSConsumerDemand(projection ResourceProjection, apps Apps, sources map[string]ManagedDNSSource) map[string]int {
	instances := map[string]map[string]bool{}
	add := func(bridge, service string) {
		if instances[bridge] == nil {
			instances[bridge] = map[string]bool{}
		}
		instances[bridge][service] = true
	}
	for _, network := range projection.Resources.Networks.AllNetworks() {
		policy, found := sources[services.ManagedDNSKey(network.Tenant, network.Logical)]
		if !found || !policy.Definition.Policy.Enabled {
			continue
		}
		bridge := (tenancy.SourceIdentity{Kind: "bridge", Tenant: network.Tenant, Network: network.Logical, Node: network.Node}).Key()
		for _, pool := range network.Pools {
			add(bridge, services.ManagedDNSServiceID(network.Tenant, network.Logical, pool.ID))
		}
	}
	if apps.network != nil {
		for _, group := range apps.network.Groups {
			for _, row := range group.Owners {
				if row.Managed == nil {
					continue
				}
				ref, exists := apps.network.Authority.ReferenceConsumer(row.Reference)
				if !exists || ref.Closed == nil {
					add(row.Managed.Bridge.Key, row.Config.ID)
				}
			}
		}
	}
	out := make(map[string]int, len(instances))
	for bridge, ids := range instances {
		out[bridge] = len(ids)
	}
	return out
}

func admitManagedDNSConsumers(projection ResourceProjection, definition services.ManagedDNSDefinition) error {
	for _, network := range projection.Resources.Networks.AllNetworks() {
		if network.Tenant != definition.Tenant || network.Logical != definition.Network {
			continue
		}
		target := deployment.GoalResources{Goal: deployment.GoalCommand{Tenant: network.Tenant, Node: network.Node, Owner: network.Owner}}
		if err := admitIngressConsumers(projection, target); err != nil {
			return err
		}
	}
	return nil
}
