// SPDX-License-Identifier: Apache-2.0

package control

import (
	"time"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
)

func (p Policy) managedDNSMaterial(s state.State, apps Apps, owner [32]byte, row AppDNSOwner) (services.DNSOwnerPolicy, error) {
	if row.Managed == nil || apps.network == nil {
		return services.DNSOwnerPolicy{}, ErrCatalog
	}
	object := s.Object(row.Source.Key)
	if !object.Present || object.Generation != row.Source.Generation || object.Revision != row.Source.Revision {
		return services.DNSOwnerPolicy{}, ErrCatalog
	}
	projection, err := p.projectResourcesFromApps(s, apps)
	if err != nil {
		return services.DNSOwnerPolicy{}, err
	}
	current, source, err := p.managedDNSProjectionFromApps(s, apps, projection, row.Source.Key)
	if err != nil {
		return services.DNSOwnerPolicy{}, err
	}
	published := false
	for _, group := range apps.network.Groups {
		if dnsGroupKey(group) == dnsGroupKey(current) && group.Digest == current.Digest {
			published = true
			break
		}
	}
	if !published {
		return services.DNSOwnerPolicy{}, ErrCatalog
	}
	local, err := p.nodeOwner(s, row.Managed.Node)
	bridge := s.Object(row.Managed.Bridge.Key)
	ref, known := apps.network.Authority.ReferenceConsumer(row.Reference)
	managed := projection.ManagedSources[row.Managed.Bridge.Key]
	bridgeRevisionMatches := bridge.Revision == row.Managed.Bridge.Revision
	if !bridgeRevisionMatches && source.Definition.RetainReserved && !source.Definition.Policy.Enabled && !row.Config.Enabled && bridge.Revision > row.Managed.Bridge.Revision && managed.Network.Draining && managed.Network.Generation == ref.Local.NetworkGeneration && managed.Network.Tenant == ref.Local.Tenant && managed.Network.ID == ref.Local.Network && managed.Network.Node == ref.Local.Node && managed.Network.Owner == ref.Local.Owner {
		// Drain advances source metadata while the ORIGINAL DNS pin still
		// owes closure. It cannot replace its owner, generation or pool.
		for _, pool := range managed.Network.Pools {
			if pool.ID == ref.Local.Pool && pool.Prefix == ref.Local.Prefix && pool.Gateway == ref.Local.Gateway && pool.MTU == ref.Local.MTU {
				bridgeRevisionMatches = true
			}
		}
	}
	if err != nil || !p.ownsResource(s, local, owner) || !known || ref.Local.Owner != owner || ref.Local.Node != row.Managed.Node || !bridge.Present || bridge.Generation != row.Managed.Bridge.Generation || !bridgeRevisionMatches || managed.Bridge == nil {
		return services.DNSOwnerPolicy{}, ErrCatalog
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return services.DNSOwnerPolicy{}, err
	}
	material := services.DNSOwnerPolicy{Catalog: catalog, Networks: projection.Resources.Networks, Authority: apps.network.Authority, Actor: source.Principal, Config: row.Config, Bridge: row.Managed.Bridge.Key, BridgeGeneration: row.Managed.Bridge.Generation, MaxConnections: row.Managed.MaxConnections, RequestTimeout: time.Duration(row.Managed.RequestTimeoutMS) * time.Millisecond}
	for _, group := range apps.network.Groups {
		for _, other := range group.Owners {
			material.ProtectedZones = append(material.ProtectedZones, other.Config.Zone)
			if other.Config.ClientZone != "" {
				material.ProtectedZones = append(material.ProtectedZones, other.Config.ClientZone)
			}
		}
	}
	return material, nil
}

func (p Policy) managedDNSNativePermit(s state.State, caller [32]byte, r NativeRequest) (NativePermit, error) {
	if r.DNS == "" {
		return NativePermit{}, ErrCatalog
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return NativePermit{}, err
	}
	if apps.network == nil {
		return NativePermit{}, ErrCatalog
	}
	for _, group := range apps.network.Groups {
		for _, row := range group.Owners {
			if row.Managed == nil || row.Source != r.Source || row.Config.ID != r.DNS {
				continue
			}
			ref, known := apps.network.Authority.ReferenceConsumer(row.Reference)
			if !known || !p.ownsResource(s, caller, ref.Local.Owner) {
				continue
			}
			nativeOwner := ref.Local.Owner
			material, err := p.managedDNSMaterial(s, apps, nativeOwner, row)
			if err != nil || !row.Config.Enabled {
				return NativePermit{}, ErrCatalog
			}
			resources, err := p.Resources(s)
			if err != nil {
				return NativePermit{}, err
			}
			global, gok := resources.Quotas.Limit("", row.Managed.Node)
			scoped, sok := resources.Quotas.Limit(row.Config.Tenant, row.Managed.Node)
			capacity := min(global.MaxConsumers, scoped.MaxConsumers)
			if !gok || !sok || !resources.Quotas.SameOwner(row.Managed.Node, global.Owner, nativeOwner) || !resources.Quotas.SameOwner(row.Managed.Node, scoped.Owner, nativeOwner) || capacity < 1 || material.BridgeGeneration != row.Managed.Bridge.Generation {
				return NativePermit{}, ErrCatalog
			}
			projection, err := p.projectResourcesFromApps(s, apps)
			if err != nil {
				return NativePermit{}, err
			}
			target := deployment.GoalResources{Goal: deployment.GoalCommand{Tenant: row.Config.Tenant, Node: row.Managed.Node, Owner: nativeOwner}}
			if err := admitIngressConsumers(projection, target); err != nil {
				return NativePermit{}, err
			}
			return NativePermit{Source: r.Source, Owner: nativeOwner, Kind: "dns", DNS: r.DNS, Spec: AppDNSNativeDigest(row), MaxConsumers: capacity}, nil
		}
	}
	return NativePermit{}, ErrCatalog
}
