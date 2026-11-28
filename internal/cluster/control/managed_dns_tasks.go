// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
)

type managedTaskDNSNetwork struct {
	Alias      string
	Attachment deployment.Attachment
	Source     ManagedDNSSource
	Reference  deployment.NetworkReference
}

// This reader uses the SAME frozen Task/network-reference decoder as native
// Task material. It creates no app-owned DNS Goal, reservation or authority.
func (p Policy) managedTaskDNSNetworks(s state.State, g deployment.GoalCommand) ([]managedTaskDNSNetwork, error) {
	var service deployment.ComposeService
	if g.Kind != "task" || canonical(g.Config, &service) != nil {
		return nil, ErrCatalog
	}
	sources, err := p.ManagedDNS(s)
	if err != nil {
		return nil, err
	}
	aliases := make([]string, 0, len(service.Networks))
	for alias := range service.Networks {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)
	objects := s.Objects("")
	var out []managedTaskDNSNetwork
	for _, alias := range aliases {
		attachment := service.Networks[alias]
		material, err := deployment.ResolveTaskNetwork(p.Cluster, g, alias, objects)
		if err != nil {
			return nil, err
		}
		if material.Reference == nil || material.Reference.ManagedName == "" {
			if len(attachment.Aliases) != 0 {
				return nil, ErrCatalog
			}
			continue
		}
		ref := *material.Reference
		source, found := sources[services.ManagedDNSKey(g.Tenant, ref.ManagedName)]
		if !found || !source.Definition.Policy.Enabled {
			requires := len(attachment.Aliases) != 0
			for _, pool := range ref.Pools {
				requires = requires || slices.Contains(service.DNS, pool.Gateway.String())
			}
			if requires {
				return nil, ErrCatalog
			}
			continue
		}
		out = append(out, managedTaskDNSNetwork{Alias: alias, Attachment: attachment, Source: source, Reference: ref})
	}
	return out, nil
}

// Called only after validateAppCommands, in the candidate Task transaction.
// The new names and static addresses compete at ONE commit boundary, including
// earlier committed Tasks whose owners have not yet collected their receipt.
func (p Policy) validateManagedTaskDNS(s state.State, projection ResourceProjection, cmd state.Command) error {
	g, exists := projection.Goals[cmd.Key]
	if cmd.Kind != state.Mutate || cmd.Delete || !exists || g.Goal.Kind != "task" || g.Goal.Lifecycle != nil && g.Goal.Lifecycle.Drain {
		return nil
	}
	required, err := p.managedTaskDNSNetworks(s, g.Goal)
	if err != nil || len(required) == 0 {
		return err
	}
	if err := admitIngressConsumers(projection, g); err != nil {
		return err
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return err
	}
	authority, err := projection.addressAuthority(p.Cluster)
	if err != nil {
		return err
	}
	checked := map[string]bool{}
	for _, network := range required {
		definition := network.Source.Definition
		key := services.ManagedDNSKey(definition.Tenant, definition.Network)
		if checked[key] {
			continue
		}
		checked[key] = true
		registrations, err := p.managedDNSRegistrations(s, projection, definition, &cmd)
		if err != nil {
			return err
		}
		if _, err := definition.Plans(catalog, projection.Resources.Networks, authority, network.Source.Principal, 1, 1, registrations); err != nil {
			return err
		}
	}
	return nil
}

// ManagedTaskDNS is a read-only requirement, not a native permit or Ready fact.
// The actual Task adapter additionally inspects these exact local DNS instances
// immediately before native Create/Start/Recover using its current Task grant.
func (p Policy) ManagedTaskDNS(s state.State, task deployment.ObjectRef) ([]AppDNSOwner, error) {
	o := s.Object(task.Key)
	if !o.Present || task.Generation == 0 || o.Generation != task.Generation || o.Revision != task.Revision {
		return nil, ErrCatalog
	}
	goal, err := deployment.DecodeGoalResources(p.Cluster, task.Key, o)
	if err != nil || goal.Goal.Kind != "task" || goal.Goal.Lifecycle != nil && goal.Goal.Lifecycle.Drain {
		return nil, ErrCatalog
	}
	required, err := p.managedTaskDNSNetworks(s, goal.Goal)
	if err != nil || len(required) == 0 {
		return nil, err
	}
	apps, err := p.readOnlyApps(s)
	if err != nil {
		return nil, err
	}
	authority, _, known := apps.NetworkDNS(goal.Goal.Owner)
	if !known {
		return nil, ErrCatalog
	}
	seen := map[[32]byte]bool{}
	var out []AppDNSOwner
	for _, network := range required {
		_, rows, known := apps.NetworkDNS(network.Reference.Owner)
		if !known {
			return nil, ErrCatalog
		}
		for family, address := range []string{network.Attachment.IPv4, network.Attachment.IPv6} {
			if address == "" {
				continue
			}
			endpoint := task.Key + "/" + network.Alias + "/" + strconv.Itoa(family)
			allocation, held := authority.AddressBook().AllocationOf(endpoint, task.Generation)
			if !held || allocation.Generation != task.Generation || allocation.Address.String() != address {
				return nil, ErrCatalog
			}
			pool, exists := authority.AddressBook().Pool(allocation.Pool)
			if !exists || pool.Network != network.Reference.Tenant+"/"+network.Reference.Network {
				return nil, ErrCatalog
			}
			found := false
			for _, row := range rows {
				if row.Managed == nil || !row.Config.Enabled || row.Source.Key != services.ManagedDNSKey(goal.Goal.Tenant, network.Reference.ManagedName) || row.Config.Network != network.Reference.Network || row.Config.Tenant+"/"+row.Config.Network+"/"+row.Config.Pool != pool.ID {
					continue
				}
				// A whole fresh group digest is checked, including remote owner
				// records. A view for the earlier empty network grants no Task.
				if _, err := p.managedDNSMaterial(s, apps, network.Reference.Owner, row); err != nil || row.Managed.Bridge != network.Reference.Source {
					return nil, ErrCatalog
				}
				if !slices.ContainsFunc(row.Config.Names, func(name services.DNSName) bool {
					return name.Endpoint == endpoint && name.Generation == task.Generation
				}) {
					return nil, ErrCatalog
				}
				found = true
				if !seen[row.Reference] {
					seen[row.Reference] = true
					out = append(out, row)
				}
			}
			if !found {
				return nil, ErrCatalog
			}
		}
	}
	return out, nil
}
