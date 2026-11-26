// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// ResourceProjection is an owned read-only view of the one committed state.
// Base management CAS stays in Resources; native goals are never copied into
// that checkpoint or given a second reservation/cleanup receipt.
type ResourceProjection struct {
	HostPorts      []deployment.HostPortUse `json:"-"`
	MoveHolds      []deployment.PlannedResource
	MoveConsumers  []deployment.NetworkConsumerDemand
	Resources      Resources
	Goals          map[string]deployment.GoalResources
	Addresses      network.Book
	Compatible     bool
	AddressSources map[string]deployment.ObjectRef
	ManagedSources map[string]ManagedNetworkSource
	// Planned and original unclosed managed DNS instances share the existing
	// Bridge consumer budget. This is a derived view, not another reservation.
	ManagedDNSConsumers map[string]int
	RouteConsumers      []deployment.NetworkConsumerDemand
	// Owned read-only projection of the SAME stored Authority plus committed
	// static holds. It is not another checkpoint or a native permission.
	NetworkAuthority *services.Authority `json:"-"`
}

func (p Policy) ProjectResources(s state.State) (ResourceProjection, error) {
	base, err := p.Resources(s)
	if err != nil {
		return ResourceProjection{}, err
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return ResourceProjection{}, err
	}
	volumes, err := p.Volumes(s)
	if err != nil {
		return ResourceProjection{}, err
	}
	return p.projectResources(s, base, apps, volumes)
}

// DNS validation preserves the same committed address Book, reference and
// generation floors instead of constructing an independent allocator.
func (p ResourceProjection) addressAuthority(cluster [32]byte) (services.Authority, error) {
	if p.NetworkAuthority == nil {
		return services.NewAuthority(cluster, p.Addresses)
	}
	if p.NetworkAuthority.Cluster() != cluster {
		return services.Authority{}, ErrCatalog
	}
	return *p.NetworkAuthority, nil
}

// Callers have already validated Apps from this same immutable state.
// Keep all resource/volume checks without decoding the full inventory again.
func (p Policy) projectResourcesFromApps(s state.State, apps Apps) (ResourceProjection, error) {
	base, err := p.Resources(s)
	if err != nil {
		return ResourceProjection{}, err
	}
	volumes, err := p.Volumes(s)
	if err != nil {
		return ResourceProjection{}, err
	}
	return p.projectResources(s, base, apps, volumes)
}

// The inputs are decoded from s by the caller and never retained. This also
// lets full candidate validation reuse its checked views for each invariant.
func (p Policy) projectResources(s state.State, base Resources, apps Apps, volumes Volumes) (ResourceProjection, error) {
	result := ResourceProjection{Resources: base, Goals: map[string]deployment.GoalResources{}, Compatible: true, AddressSources: map[string]deployment.ObjectRef{}}
	var err error
	var retired []services.RetiredNetwork
	if apps.network != nil {
		retired = apps.network.Authority.RetiredNetworks()
	}
	result.ManagedSources, err = projectManagedNetworkSources(s, base.Networks, retired)
	if err != nil {
		return result, err
	}
	objects := s.Objects("")
	keys := make([]string, 0, len(objects))
	for k, o := range objects {
		if o.Present {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var networks []tenancy.Network
	var reservations []tenancy.Reservation
	for _, key := range keys {
		if !strings.HasPrefix(key, "network/") && !strings.HasPrefix(key, "workload/") && !strings.HasPrefix(key, "ingress/") {
			continue
		}
		var head struct{ Kind string }
		if json.Unmarshal([]byte(objects[key].Value), &head) != nil || head.Kind == "" {
			// Management-owned TUN/Bridge rows also use native specs. Their
			// exact authority was already checked against the typed catalog;
			// absence of an app Goal does not make them legacy/unmapped.
			if _, managed := result.ManagedSources[key]; managed {
				continue
			}
			// A native spec outside an app Goal or a managed source has no
			// owner in managed mode.
			result.Compatible = false
			continue
		}
		g, err := deployment.DecodeGoalResources(p.Cluster, key, objects[key])
		if err != nil {
			return result, err
		}
		result.Goals[key] = g
		if g.Network != nil {
			networks = append(networks, *g.Network)
		}
		if g.Reservation != nil {
			reservations = append(reservations, *g.Reservation)
		}
	}
	result.Resources.Networks, err = base.Networks.WithCommittedNetworks(networks)
	if err != nil {
		return result, err
	}
	builds, err := p.imageBuildReservations(s)
	if err != nil {
		return result, err
	}
	reservations = append(reservations, builds...)
	result.Resources.Quotas, err = base.Quotas.WithCommittedReservations(reservations)
	if err != nil {
		return result, err
	}
	if err = checkProjectedNetworkReferences(p.Cluster, s, result); err != nil {
		return result, err
	}

	if result.Resources.Quotas.ValidateNetworks(result.Resources.Networks) != nil {
		return result, ErrCatalog
	}
	addressCount := 0
	for key, o := range objects {
		if !o.Present {
			continue
		}
		if g, ok := result.Goals[key]; ok {
			if g.Goal.Kind == "task" {
				var service deployment.ComposeService
				if json.Unmarshal(g.Goal.Config, &service) != nil {
					return result, ErrCatalog
				}
				for _, a := range service.Networks {
					if a.IPv4 != "" {
						addressCount++
					}
					if a.IPv6 != "" {
						addressCount++
					}
				}
			}
		} else if strings.HasPrefix(key, "workload/task/") {
			addressCount += 2
		}
	}
	result.Addresses, err = result.Resources.Networks.AddressPlan(max(1, addressCount))
	if err != nil {
		return result, err
	}
	if apps.network != nil {
		authority, err := apps.network.Authority.SyncPools(result.Resources.Networks)
		if err != nil {
			return result, err
		}
		// This is a read-only view of already committed holds. Capacity here is
		// storage for that complete view; tenant/node admission stays in Quotas.
		authority, err = authority.ResizeAddresses(max(1, addressCount+authority.AddressBook().Count()))
		if err != nil {
			return result, err
		}
		result.NetworkAuthority = &authority
		result.RouteConsumers = routeConsumerDemand(authority)
		result.Addresses = authority.AddressBook()
	}
	// Shape matching reserves/conflict-checks old space; only an exact signed
	// system-admin mapping qualifies it as a registered native source.
	bridges := map[string]string{}
	nativeSources := map[string]string{}
	for key, row := range result.ManagedSources {
		if row.Bridge != nil {
			id := row.Network.Tenant + "/" + row.Network.ID
			bridges[key] = id
			nativeSources[id] = key
		}
	}
	for _, key := range keys {
		if !strings.HasPrefix(key, "network/bridge/") {
			continue
		}
		if _, managed := result.ManagedSources[key]; managed {
			continue
		}
		if g, ok := result.Goals[key]; ok {
			if g.Network == nil {
				return result, ErrCatalog
			}
			networkID := g.Network.Tenant + "/" + g.Network.ID
			if prior, exists := nativeSources[networkID]; exists && prior != key {
				return result, ErrCatalog
			}
			nativeSources[networkID] = key
			bridges[key] = networkID
			continue
		}
		result.Compatible = false // a raw Bridge without an app Goal or managed source
	}
	for _, key := range keys {
		o := objects[key]
		if g, ok := result.Goals[key]; ok {
			if g.Goal.Kind != "task" {
				continue
			}
			var service deployment.ComposeService
			if json.Unmarshal(g.Goal.Config, &service) != nil {
				return result, ErrCatalog
			}
			for alias, attachment := range service.Networks {
				packetOwner, ownerErr := p.taskPacketOwner(s, g.Goal, alias, objects)
				if ownerErr != nil {
					return result, ownerErr
				}
				source := deployment.ResourceKey("bridge", g.Goal.Tenant, g.Goal.App, alias+"/"+g.Goal.Node)
				if _, exists := result.Goals[source]; !exists {
					source = deployment.ResourceKey("network-ref", g.Goal.Tenant, g.Goal.App, alias+"/"+g.Goal.Node)
				}
				parent, exists := result.Goals[source]
				if !exists || !hasSource(g.Goal, source, objects[source]) {
					return result, ErrCatalog
				}
				networkID := ""
				switch parent.Goal.Kind {
				case "bridge":
					if parent.Goal.Owner != packetOwner || parent.Network == nil {
						return result, ErrCatalog
					}
					networkID = parent.Network.Tenant + "/" + parent.Network.ID
				case "network-ref":
					var ref deployment.NetworkReference
					if json.Unmarshal(parent.Goal.Config, &ref) != nil || ref.Tenant != g.Goal.Tenant || ref.Node != g.Goal.Node || ref.Owner != packetOwner || ref.Owner != parent.Goal.Owner || !ref.RetainSource {
						return result, ErrCatalog
					}
					original, ok := objects[ref.Source.Key]
					if !ok || !original.Present || original.Revision != ref.Source.Revision || original.Generation != ref.Source.Generation || sha256.Sum256([]byte(original.Value)) != ref.Spec || bridges[ref.Source.Key] != ref.Tenant+"/"+ref.Network {
						return result, ErrCatalog
					}
					networkID = ref.Tenant + "/" + ref.Network
				default:
					return result, ErrCatalog
				}
				for family, address := range []string{attachment.IPv4, attachment.IPv6} {
					if address == "" {
						continue
					}
					ip, err := netip.ParseAddr(address)
					if err != nil {
						return result, err
					}
					result.AddressSources[ip.String()] = deployment.ObjectRef{Key: key, Revision: o.Revision, Generation: o.Generation}
					result.Addresses, err = projectStaticAddress(result.Addresses, result.NetworkAuthority, key+"/"+alias+"/"+strconv.Itoa(family), hex.EncodeToString(packetOwner[:]), networkID, o.Generation, ip)
					if err != nil {
						return result, err
					}
				}
			}
			continue
		}
		if !strings.HasPrefix(key, "workload/task/") {
			continue
		}
		result.Compatible = false // a raw Task without an app Goal
	}
	if !result.Compatible && len(result.Goals) > 0 {
		return result, ErrCatalog
	}
	tunnelAddresses := map[netip.Addr]string{}
	for _, n := range result.Resources.Networks.AllNetworks() {
		for _, address := range n.TunnelAddresses {
			tunnelAddresses[address.Addr()] = n.Tenant + "/" + n.ID
		}
	}
	for key, g := range result.Goals {
		if g.Goal.Kind != "tunnel" {
			continue
		}
		t, err := deployment.ResolveTunnel(p.Cluster, key, objects[key], objects)
		if err != nil {
			return result, err
		}
		g.Tunnel = &t
		result.Goals[key] = g
		if t.Lifecycle.Released() {
			continue
		}
		for _, a := range t.Addresses {
			if old, exists := tunnelAddresses[a.Addr()]; exists && old != key {
				return result, ErrCatalog
			}
			tunnelAddresses[a.Addr()] = key
			for _, n := range result.Resources.Networks.AllNetworks() {
				for _, pool := range n.Pools {
					if pool.Prefix.Contains(a.Addr()) {
						return result, ErrCatalog
					}
				}
			}
		}
	}
	if err = p.projectMoveResources(s, apps, volumes, &result); err != nil {
		return result, err
	}
	if err = p.projectIngress(s, &result, apps); err != nil {
		return result, err
	}
	if err = p.projectPublishedPorts(s, &result, apps); err != nil {
		return result, err
	}
	sources, err := p.ManagedDNS(s)
	if err != nil {
		return result, err
	}
	result.ManagedDNSConsumers = managedDNSConsumerDemand(result, apps, sources)
	if err = admitMoveConsumers(result); err != nil {
		return result, err
	}
	for _, allocation := range result.Addresses.Checkpoint().Allocations {
		if _, current := result.AddressSources[allocation.Address.String()]; !current {
			// Revision zero explicitly denotes a retained reservation without
			// a current Goal. Compile must refuse borrowing it, never infer Gone.
			result.AddressSources[allocation.Address.String()] = deployment.ObjectRef{Key: allocation.Endpoint, Generation: allocation.Generation}
		}
	}
	return result, nil
}

func projectStaticAddress(book network.Book, authority *services.Authority, endpoint, owner, networkID string, generation uint64, address netip.Addr) (network.Book, error) {
	next, err := book.WithCommittedAllocation(endpoint, owner, networkID, generation, address)
	if err != nil || authority == nil {
		return next, err
	}
	allocation, found := next.Allocation(endpoint)
	if !found {
		return book, ErrCatalog
	}
	candidate, err := authority.WithCommittedStaticAllocation(allocation, networkID)
	if err != nil {
		return book, err
	}
	*authority = candidate
	return candidate.AddressBook(), nil
}
func hasSource(g deployment.GoalCommand, key string, o state.Object) bool {
	return o.Present && o.Generation > 0 && slices.Contains(g.Dependencies, deployment.ObjectRef{Key: key, Revision: o.Revision, Generation: o.Generation})
}
