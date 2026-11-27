// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func validateServicePlacement(service ComposeService) error {
	if len(service.Sfc.Nodes) == 0 {
		if service.Sfc.PerNode != 0 {
			return inputError("REPLICA_NODES_REQUIRED", "x-sfc.per_node")
		}
		return nil
	}
	if service.Sfc.Node != "" || len(service.Sfc.Nodes) > 128 || service.Sfc.PerNode > 128 {
		return inputError("INVALID_REPLICA_PLACEMENT", "x-sfc")
	}
	seen := map[string]bool{}
	for _, node := range service.Sfc.Nodes {
		if !identifier(node) || seen[node] {
			return inputError("INVALID_REPLICA_NODE", node)
		}
		seen[node] = true
	}
	count := uint64(len(service.Sfc.Nodes)) * uint64(max(1, service.Sfc.PerNode))
	if count > 128 {
		return inputError("REPLICA_LIMIT", "services")
	}
	if count > 1 {
		for _, mount := range service.Volumes {
			if !mount.ReadOnly {
				return inputError("REPLICA_SINGLE_WRITER_FORBIDDEN", mount.Source)
			}
		}
		for name, attachment := range service.Networks {
			if attachment.IPv4 != "" || attachment.IPv6 != "" {
				return inputError("REPLICA_SHARED_STATIC_ADDRESS", name)
			}
		}
	}
	return nil
}

func servicePlacements(name string, service ComposeService, defaultNode string) ([]TaskInstance, error) {
	if !identifier(name) {
		return nil, ErrInputs
	}
	if err := validateServicePlacement(service); err != nil {
		return nil, err
	}
	if len(service.Sfc.Nodes) == 0 {
		node := service.Sfc.Node
		if node == "" {
			node = defaultNode
		}
		if !identifier(node) {
			return nil, inputError("PLACEMENT_REQUIRED", "services."+name)
		}
		return []TaskInstance{{Service: name, Node: node}}, nil
	}
	out := []TaskInstance{}
	for _, node := range service.Sfc.Nodes {
		for ordinal := uint32(1); ordinal <= max(1, service.Sfc.PerNode); ordinal++ {
			out = append(out, TaskInstance{Service: name, Node: node, Ordinal: ordinal})
		}
	}
	return out, nil
}

func planServicePlacements(c Compose, defaultNode string) (map[string][]TaskInstance, error) {
	out := map[string][]TaskInstance{}
	count := 0
	for _, name := range mapKeys(c.Services) {
		placements, err := servicePlacements(name, c.Services[name], defaultNode)
		if err != nil {
			return nil, err
		}
		count += len(placements)
		if count > 128 {
			return nil, inputError("REPLICA_LIMIT", "services")
		}
		out[name] = placements
	}
	return out, nil
}

func materializeTaskInstance(source ComposeService, instance TaskInstance) (ComposeService, error) {
	raw, err := json.Marshal(source)
	var service ComposeService
	if err != nil || json.Unmarshal(raw, &service) != nil || instance.ResourceID() == "" {
		return service, ErrInputs
	}
	service.Sfc.Node = instance.Node
	service.Sfc.Nodes, service.Sfc.PerNode = nil, 0
	if instance.Ordinal != 0 {
		copy := instance
		service.Sfc.Instance = &copy
	}
	return service, nil
}

func dynamicTaskAddresses(service ComposeService) bool {
	for _, attachment := range service.Networks {
		if attachment.IPv4 == "" && attachment.IPv6 == "" {
			return true
		}
	}
	return false
}

// Preserve declaration intent while keeping all other existing singleton
// normalization. The separately frozen Task goal owns assigned addresses;
// recording them as user-fixed input would prevent a later node relocation.
func singletonDeclaredAddresses(source, planned ComposeService) ComposeService {
	if !dynamicTaskAddresses(source) {
		return planned
	}
	networks := make(map[string]Attachment, len(planned.Networks))
	for alias, attachment := range planned.Networks {
		declared := source.Networks[alias]
		attachment.IPv4, attachment.IPv6 = declared.IPv4, declared.IPv6
		networks[alias] = attachment
	}
	planned.Networks = networks
	return planned
}

// Resolve Task addresses through the existing Book's static eligibility
// rules. Candidate addresses are not allocation receipts: only the ordinary
// later FSM/Book reservation can publish a generation or authorize a native.
func replicaAddresses(b Blueprint, ctx PlanningContext, instance TaskInstance, service ComposeService, networks map[string]ComposeNetwork, borrowed map[string]NetworkReference, used map[string]bool) (ComposeService, error) {
	if instance.Ordinal == 0 && !dynamicTaskAddresses(service) {
		return service, nil
	}
	key := ResourceKey("task", b.d.Tenant, b.d.App, instance.ResourceID())
	var previous ComposeService
	if object := ctx.Current[key]; object.Present {
		var goal GoalCommand
		if json.Unmarshal([]byte(object.Value), &goal) == nil && goal.Cluster == b.d.Cluster && goal.Tenant == b.d.Tenant && goal.App == b.d.App && goal.Deployment == b.d.Deployment && goal.Kind == "task" && goal.Node == instance.Node && goal.Owner == ctx.Nodes[instance.Node].Key {
			_ = json.Unmarshal(goal.Config, &previous)
		}
	}
	for _, alias := range mapKeys(service.Networks) {
		attachment := service.Networks[alias]
		// An explicit singleton attachment keeps its historical shape. Only a
		// completely unspecified attachment requests dynamic assignment; an
		// omitted other family must not change an existing static declaration.
		if instance.Ordinal == 0 && (attachment.IPv4 != "" || attachment.IPv6 != "") {
			continue
		}
		var pools []tenancy.Subnet
		if definition := networks[alias]; definition.External {
			reference, ok := borrowed[ResourceKey("network-ref", b.d.Tenant, b.d.App, alias+"/"+instance.Node)]
			if !ok {
				return service, inputError("EXTERNAL_NETWORK_BINDING_REQUIRED", alias)
			}
			pools = reference.Pools
		} else if pool, ok := definition.Sfc.Pools[instance.Node]; ok {
			pools = []tenancy.Subnet{{ID: "pool", Prefix: mustPrefix(pool.CIDR), Gateway: mustAddr(pool.Gateway), MTU: max(1280, definition.Sfc.MTU)}}
		}
		if len(pools) == 0 {
			return service, inputError("NETWORK_BINDING_REQUIRED", alias)
		}
		nodeKey := ctx.Nodes[instance.Node].Key
		owner := hex.EncodeToString(nodeKey[:])
		book, _ := network.NewBook(1)
		bookNetwork := key + "/" + alias
		for index, pool := range pools {
			var err error
			book, err = book.AddPool(network.Pool{ID: strconv.Itoa(index), Network: bookNetwork, Owner: owner, Prefix: pool.Prefix, Gateway: pool.Gateway, MTU: pool.MTU, IPAM: pool.IPAM})
			if err != nil {
				return service, err
			}
		}
		for family := 0; family < 2; family++ {
			wanted := attachment.IPv4
			if family == 1 {
				wanted = attachment.IPv6
			}
			if wanted != "" {
				continue
			}
			endpoint := key + "/" + alias + "/" + strconv.Itoa(family)
			excluded := map[string]bool{}
			for ip := range ctx.Addresses {
				excluded[ip] = true
			}
			for token := range used {
				if ip, ok := splitNodeAddress(instance.Node, token); ok {
					excluded[ip] = true
				}
			}
			var held []netip.Addr
			for _, pending := range ctx.Planned {
				for _, address := range pending.Demand.Addresses {
					if pending.Scope == b.Scope() && pending.Demand.Key == key && pending.Demand.Node == instance.Node && address.Endpoint == endpoint {
						held = append(held, address.Address)
					} else {
						excluded[address.Address.String()] = true
					}
				}
			}
			slices.SortFunc(held, func(a, b netip.Addr) int { return a.Compare(b) })
			held = slices.Compact(held)
			if len(held) > 1 {
				return service, inputError("REPLICA_ADDRESS_INTENT_CONFLICT", instance.ResourceID())
			}
			prior := previous.Networks[alias].IPv4
			if family == 1 {
				prior = previous.Networks[alias].IPv6
			}
			if prior != "" {
				ref, known := ctx.Addresses[prior]
				object := ctx.Current[key]
				if known && ref.Key == key && ref.Generation > 0 && ref.Generation == object.Generation && ref.Revision == object.Revision {
					held = append(held, mustAddr(prior))
					delete(excluded, prior)
				}
			}
			chosen := netip.Addr{}
			for _, candidate := range held {
				if candidate.Is4() != (family == 0) || excluded[candidate.String()] {
					continue
				}
				if _, allocation, err := book.Reserve(endpoint, owner, bookNetwork, "", 1, candidate); err == nil {
					chosen = allocation.Address
					break
				}
			}
			eligible := false
			if !chosen.IsValid() {
				for _, pool := range pools {
					if pool.Prefix.Addr().Is4() != (family == 0) {
						continue
					}
					eligible = true
					candidate := pool.Prefix.Addr().Next()
					for n := 0; n <= len(excluded)+3 && candidate.IsValid() && pool.Prefix.Contains(candidate); n++ {
						if !excluded[candidate.String()] {
							if _, allocation, err := book.Reserve(endpoint, owner, bookNetwork, "", 1, candidate); err == nil {
								chosen = allocation.Address
								break
							}
						}
						candidate = candidate.Next()
					}
					if chosen.IsValid() {
						break
					}
				}
			}
			if !chosen.IsValid() {
				if eligible {
					return service, inputError("REPLICA_ADDRESS_CAPACITY", alias)
				}
				continue
			}
			if family == 0 {
				attachment.IPv4 = chosen.String()
			} else {
				attachment.IPv6 = chosen.String()
			}
		}
		service.Networks[alias] = attachment
	}
	return service, nil
}

func splitNodeAddress(node, token string) (string, bool) {
	prefix := node + "/"
	if len(token) <= len(prefix) || token[:len(prefix)] != prefix {
		return "", false
	}
	return token[len(prefix):], true
}

func expandReplicaDependencies(input []Dependency, placements map[string][]TaskInstance, tenant, app string) []Dependency {
	out := []Dependency{}
	for _, dependency := range input {
		id, err := ResourceIDFromKey("task", tenant, app, dependency.Key)
		if err == nil && len(placements[id]) > 0 {
			for _, instance := range placements[id] {
				value := Dependency{Key: ResourceKey("task", tenant, app, instance.ResourceID()), Condition: dependency.Condition}
				if !slices.Contains(out, value) {
					out = append(out, value)
				}
			}
		} else if !slices.Contains(out, dependency) {
			out = append(out, dependency)
		}
	}
	return out
}
