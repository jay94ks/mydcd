// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload"
	"slices"
)

// AppTaskMaterial is only an original committed metadata view. Activation
// remains subject to a fresh owner-only Binding permit at the actual SDK edge.
func (p Policy) AppTaskMaterial(s state.State, task deployment.ObjectRef) (deployment.TaskMaterial, error) {
	a, err := p.readOnlyApps(s)
	if err != nil {
		return deployment.TaskMaterial{}, err
	}
	b, ok := a.Binding(task)
	if !ok {
		return deployment.TaskMaterial{}, ErrCatalog
	}
	o := s.Object(task.Key)
	var goal deployment.GoalCommand
	if !o.Present || o.Generation != task.Generation || o.Revision != task.Revision || canonical([]byte(o.Value), &goal) != nil || goal.Kind != "task" || goal.Owner != b.Needs().Use.NodeKey {
		return deployment.TaskMaterial{}, ErrCatalog
	}
	m := deployment.TaskMaterial{Binding: b}
	taskID, err := deployment.ResourceIDFromKey("task", goal.Tenant, goal.App, task.Key)
	if err != nil {
		return m, ErrCatalog
	}
	if b.Needs().HasSources() {
		m.Projection = &workload.InputRef{Key: deployment.ResourceKey("inputs", goal.Tenant, goal.App, taskID), Generation: task.Generation, Binding: b.Digest()}
	}
	v, err := p.Volumes(s)
	if err != nil {
		return m, err
	}
	for _, pin := range b.Pins() {
		row, ok := v.entries[pin.Key]
		if !ok || row.State.Scope() != pin.Scope || row.Native.Owner != pin.Consumer.Owner {
			return m, ErrCatalog
		}
		if ref, fixed := b.Needs().FixedVolumes[pin.Key]; fixed && !ref.Matches(row.Native) || !fixed && row.State.Fixed() {
			return m, ErrCatalog
		}
		m.Volumes = append(m.Volumes, row.Native)
	}
	if _, err = p.ProjectResources(s); err != nil {
		return m, err
	}
	var service deployment.ComposeService
	if json.Unmarshal(goal.Config, &service) != nil || len(service.Networks) == 0 || len(service.Networks) > workload.MaxTaskNetworks {
		return m, ErrCatalog
	}
	if service.CheckVolumeNeeds(b.Needs()) != nil {
		return m, ErrCatalog
	}
	// Alias order: the first is the primary attachment, the rest are Extra.
	aliases := make([]string, 0, len(service.Networks))
	for alias := range service.Networks {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)
	objects := s.Objects("")
	for i, alias := range aliases {
		source, err := deployment.ResolveTaskNetwork(p.Cluster, goal, alias, objects)
		if err != nil {
			return m, err
		}
		if i == 0 {
			m.Network, m.Bridge = source.Source, source.Bridge
			continue
		}
		m.Extra = append(m.Extra, deployment.TaskNetworkBinding{Alias: alias, Network: source.Source, Bridge: source.Bridge})
	}
	return m, nil
}
