// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"

	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
)

// ResourceDemand is desired capacity/address space, never an applied Goal,
// task generation, native identity, or readiness observation.
type ResourceDemand struct {
	Ports           []workload.PublishedPort `json:",omitempty"`
	Key, Kind, Node string
	Owner           [32]byte
	Config          [32]byte
	Need            workload.Resources
	Network         *tenancy.Network
	Addresses       []StaticAddressDemand
	Ingress         *IngressDeclaration
}

// StaticAddressDemand is a future attachment, not an allocation receipt.
// Endpoint uses the same key as the real Book consumer, without a generation.
type StaticAddressDemand struct {
	Endpoint, Network string
	Address           netip.Addr
}

// PlannedResource identifies the one committed intent holding this demand.
// Its source remains that intent and its immutable artifact, not another store.
type PlannedResource struct {
	Origin [32]byte
	Scope  AppScope
	Demand ResourceDemand
}

func stepNeed(s Step) (workload.Resources, error) {
	var need workload.Resources
	var err error
	switch s.Kind {
	case "task":
		var v ComposeService
		if json.Unmarshal(s.Goal, &v) != nil {
			return need, ErrInputs
		}
		need.CPU, err = nanoCPU(v.CPUs)
		if err == nil {
			need.Memory, err = byteSize(v.Memory)
		}
	case "registry":
		var v RegistryDeclaration
		if json.Unmarshal(s.Goal, &v) != nil {
			return need, ErrInputs
		}
		need.CPU, err = nanoCPU(v.Resources.CPUs)
		need.Memory = v.Resources.Memory
	}
	return need, err
}

func (b Blueprint) ResourceDemands() ([]ResourceDemand, error) {
	var demands []ResourceDemand
	steps := b.Steps()
	byKey := make(map[string]Step, len(steps))
	for _, step := range steps {
		byKey[step.Key] = step
	}
	for _, s := range steps {
		if s.Kind != "bridge" && s.Kind != "task" && s.Kind != "registry" && s.Kind != "ingress" {
			continue
		}
		need, err := stepNeed(s)
		if err != nil {
			return nil, err
		}
		d := ResourceDemand{Key: s.Key, Kind: s.Kind, Node: s.Node, Owner: s.Owner, Config: sha256.Sum256(s.Goal), Need: need}
		if s.Kind == "bridge" {
			var v bridgeDeclaration
			if json.Unmarshal(s.Goal, &v) != nil {
				return nil, ErrInputs
			}
			prefix, err := netip.ParsePrefix(v.Pool.CIDR)
			if err != nil {
				return nil, err
			}
			gateway, err := netip.ParseAddr(v.Pool.Gateway)
			if err != nil {
				return nil, err
			}
			d.Network = &tenancy.Network{Tenant: b.d.Tenant, ID: PoolID(b.d.Tenant, b.d.App, v.Network, s.Node), Node: s.Node, Owner: s.Owner, Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefix, Gateway: gateway, MTU: v.MTU}}}
		}
		if s.Kind == "task" {
			var service ComposeService
			if json.Unmarshal(s.Goal, &service) != nil || service.MyDC.Node != s.Node {
				return nil, ErrInputs
			}
			d.Ports = slices.Clone(service.Ports)
			for _, alias := range mapKeys(service.Networks) {
				attachment := service.Networks[alias]
				networkID := ""
				bridge := ResourceKey("bridge", b.d.Tenant, b.d.App, alias+"/"+s.Node)
				if parent, exists := byKey[bridge]; exists && parent.Kind == "bridge" {
					networkID = b.d.Tenant + "/" + PoolID(b.d.Tenant, b.d.App, alias, s.Node)
				} else {
					parent := byKey[ResourceKey("network-ref", b.d.Tenant, b.d.App, alias+"/"+s.Node)]
					var ref NetworkReference
					if parent.Kind != "network-ref" || json.Unmarshal(parent.Goal, &ref) != nil || ref.Node != s.Node || ref.Owner != parent.Owner || !b.d.Nodes[s.Node].resourceIdentity(b.d.Cluster, s.Node, ref.Owner) || ref.Tenant != b.d.Tenant {
						return nil, ErrInputs
					}
					networkID = ref.Tenant + "/" + ref.Network
				}
				for family, raw := range []string{attachment.IPv4, attachment.IPv6} {
					if raw == "" {
						continue
					}
					address, err := netip.ParseAddr(raw)
					if err != nil || address.Is4In6() || address.Zone() != "" {
						return nil, ErrInputs
					}
					d.Addresses = append(d.Addresses, StaticAddressDemand{Endpoint: s.Key + "/" + alias + "/" + strconv.Itoa(family), Network: networkID, Address: address})
				}
			}
		}
		if s.Kind == "ingress" {
			var ingress IngressDeclaration
			if json.Unmarshal(s.Goal, &ingress) != nil || ingress.Node != s.Node || ingress.Runtime.validate() != nil {
				return nil, ErrInputs
			}
			d.Ingress = &ingress
		}
		demands = append(demands, d)
	}
	return demands, nil
}

func (d ResourceDemand) Matches(g GoalCommand) bool {
	return d.Kind == g.Kind && d.Node == g.Node && d.Owner == g.Owner && d.Config == sha256.Sum256(g.Config)
}

func plannedCredit(b Blueprint, ctx PlanningContext, s Step, need workload.Resources) bool {
	for _, held := range ctx.Planned {
		if plannedStep(b, held, s) && held.Demand.Need == need {
			return true
		}
	}
	return false
}

func plannedNetworkAllowed(b Blueprint, ctx PlanningContext, wanted tenancy.Network) bool {
	for _, held := range ctx.Planned {
		n := held.Demand.Network
		if n == nil {
			continue
		}
		for _, left := range n.Pools {
			for _, right := range wanted.Pools {
				if !left.Prefix.Overlaps(right.Prefix) {
					continue
				}
				if held.Origin == ([32]byte{}) || held.Scope != b.Scope() || n.Tenant != wanted.Tenant || n.ID != wanted.ID || n.Node != wanted.Node || n.Owner != wanted.Owner || len(n.Pools) != len(wanted.Pools) {
					return false
				}
				for i := range n.Pools {
					if n.Pools[i] != wanted.Pools[i] {
						return false
					}
				}
			}
		}
	}
	return true
}

// plannedStep gives credit only to the exact accepted artifact's desired step.
// It grants no native allocation/readiness and never weakens a retained Book hold.
func plannedStep(b Blueprint, held PlannedResource, s Step) bool {
	return held.Origin != ([32]byte{}) && held.Scope == b.Scope() && held.Demand.Key == s.Key && held.Demand.Kind == s.Kind && held.Demand.Node == s.Node && held.Demand.Owner == s.Owner && held.Demand.Config == sha256.Sum256(s.Goal)
}

func plannedAddressAllowed(b Blueprint, ctx PlanningContext, s Step, address netip.Addr) bool {
	for _, held := range ctx.Planned {
		if slices.ContainsFunc(held.Demand.Addresses, func(a StaticAddressDemand) bool { return a.Address == address }) && !plannedStep(b, held, s) {
			return false
		}
	}
	return true
}
