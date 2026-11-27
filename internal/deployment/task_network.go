// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network"
)

// TaskNetworkMaterial is public frozen metadata. Current admission and native
// readiness remain with the management policy and the original local owner.
type TaskNetworkMaterial struct {
	Source    ObjectRef
	Bridge    network.BridgeSpec
	Reference *NetworkReference
}

// ResolveTaskNetwork is the one reader for a Task's exact native dependency.
// The current app reference and the frozen legacy app Bridge are distinct
// input forms. Neither an existing native-looking name nor an alternate node
// can replace a missing, stale or ambiguous original dependency.
func ResolveTaskNetwork(cluster [32]byte, task GoalCommand, alias string, objects map[string]state.Object) (TaskNetworkMaterial, error) {
	return resolveTaskNetwork(cluster, task, alias, objects, false)
}

// ResolveRetainedTaskNetwork reads an already committed attachment, including
// its exact draining source, for projection and positive retirement. It grants
// no fresh native use; Task/Start admission continues to use ResolveTaskNetwork.
// Source generation/revision/hash and frozen lineage remain exact in both paths.
func ResolveRetainedTaskNetwork(cluster [32]byte, task GoalCommand, alias string, objects map[string]state.Object) (TaskNetworkMaterial, error) {
	return resolveTaskNetwork(cluster, task, alias, objects, true)
}

func resolveTaskNetwork(cluster [32]byte, task GoalCommand, alias string, objects map[string]state.Object, retained bool) (TaskNetworkMaterial, error) {
	if cluster == ([32]byte{}) || task.Schema != 1 || task.Cluster != cluster || task.Kind != "task" || !identifier(task.Tenant) || !identifier(task.App) || !identifier(task.Deployment) || !identifier(task.Node) || !identifier(alias) || task.Owner == ([32]byte{}) {
		return TaskNetworkMaterial{}, ErrInputs
	}
	bridgeKey := ResourceKey("bridge", task.Tenant, task.App, alias+"/"+task.Node)
	refKey := ResourceKey("network-ref", task.Tenant, task.App, alias+"/"+task.Node)
	key := ""
	for _, dependency := range task.Dependencies {
		if dependency.Key != bridgeKey && dependency.Key != refKey {
			continue
		}
		if key != "" {
			return TaskNetworkMaterial{}, ErrInputs
		}
		key = dependency.Key
	}
	if key == "" || !containsFrozenSource(task, key, objects[key]) {
		return TaskNetworkMaterial{}, ErrInputs
	}
	o := objects[key]
	source, err := DecodeGoalResources(cluster, key, o)
	if err != nil || source.Goal.Tenant != task.Tenant || source.Goal.App != task.App || source.Goal.Deployment != task.Deployment || source.Goal.Node != task.Node || !lifecycle.ResourceIdentity(cluster, task.Node, task.Owner, source.Goal.Owner, task.ResourceKeys) || !retained && source.Goal.Lifecycle != nil && source.Goal.Lifecycle.Drain {
		return TaskNetworkMaterial{}, ErrInputs
	}
	if key == bridgeKey {
		if source.Bridge == nil {
			return TaskNetworkMaterial{}, ErrInputs
		}
		return TaskNetworkMaterial{Source: ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}, Bridge: *source.Bridge}, nil
	}
	var ref NetworkReference
	if source.Goal.Kind != "network-ref" || json.Unmarshal(source.Goal.Config, &ref) != nil || ref.Tenant != task.Tenant || ref.Node != task.Node || ref.Owner != source.Goal.Owner {
		return TaskNetworkMaterial{}, ErrInputs
	}
	native, err := referenceBridge(cluster, ref, objects, retained)
	if err != nil {
		return TaskNetworkMaterial{}, err
	}
	return TaskNetworkMaterial{Source: ref.Source, Bridge: native, Reference: &ref}, nil
}

func containsFrozenSource(g GoalCommand, key string, o state.Object) bool {
	if !o.Present || o.Generation == 0 || o.Revision < o.Generation {
		return false
	}
	found := false
	for _, ref := range g.Dependencies {
		if ref.Key != key {
			continue
		}
		if found || ref != (ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}) {
			return false
		}
		found = true
	}
	return found
}

// NativeOwner is the owner of the exact borrowed Bridge/TUN packet domain.
// It is independent of the Task signer after an installed identity switch.
func (m TaskNetworkMaterial) NativeOwner(cluster [32]byte) [32]byte {
	return ownerKey(m.Bridge.Owner, cluster)
}
