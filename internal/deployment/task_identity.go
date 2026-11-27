// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"strconv"
	"strings"
)

// TaskInstance is frozen per-Task compiler metadata, never an app input.
// Ordinal zero preserves the original singleton key and wire shape.
type TaskInstance struct {
	Service, Node string
	Ordinal       uint32
}

// ReplicaInstanceForKey decodes an explicit instance's scoped identity only.
// It is not a declaration, ownership proof, generation or native receipt.
func ReplicaInstanceForKey(tenant, app, key string) (TaskInstance, error) {
	id, err := ResourceIDFromKey("task", tenant, app, key)
	parts := strings.Split(id, "/")
	if err != nil || len(parts) != 3 || !strings.HasPrefix(parts[2], "r") {
		return TaskInstance{}, ErrInputs
	}
	ordinal, err := strconv.ParseUint(strings.TrimPrefix(parts[2], "r"), 10, 32)
	instance := TaskInstance{Service: parts[0], Node: parts[1], Ordinal: uint32(ordinal)}
	if err != nil || instance.Ordinal == 0 || instance.ResourceID() != id {
		return TaskInstance{}, ErrInputs
	}
	return instance, nil
}

func (i TaskInstance) ResourceID() string {
	if !identifier(i.Service) || !identifier(i.Node) || i.Ordinal > 128 {
		return ""
	}
	if i.Ordinal == 0 {
		return i.Service
	}
	return i.Service + "/" + i.Node + "/r" + strconv.FormatUint(uint64(i.Ordinal), 10)
}

// ResourceIDFromKey checks the complete typed scope, not the last path segment.
// It is shared by singleton and replica Task/inputs consumers.
func ResourceIDFromKey(kind, tenant, app, key string) (string, error) {
	root := ResourceKey(kind, tenant, app, "root")
	if root == "" {
		return "", ErrInputs
	}
	prefix := strings.TrimSuffix(root, "root")
	id, ok := strings.CutPrefix(key, prefix)
	if !ok || ResourceKey(kind, tenant, app, id) != key {
		return "", ErrInputs
	}
	return id, nil
}

func TaskInstanceForKey(tenant, app, key string, service ComposeService) (TaskInstance, error) {
	id, err := ResourceIDFromKey("task", tenant, app, key)
	if err != nil || !identifier(service.Sfc.Node) {
		return TaskInstance{}, ErrInputs
	}
	instance := TaskInstance{Service: id, Node: service.Sfc.Node}
	if service.Sfc.Instance != nil {
		instance = *service.Sfc.Instance
		if instance.Ordinal == 0 {
			return TaskInstance{}, ErrInputs
		}
	}
	if instance.Node != service.Sfc.Node || instance.ResourceID() != id {
		return TaskInstance{}, ErrInputs
	}
	return instance, nil
}

func (b Blueprint) taskInput(id string) (ComposeService, string, error) {
	// Explicit singleton addresses retain their original normalization/wire
	// behavior. A dynamic declaration instead consumes the same frozen Task
	// goal as its native adapter, never the still-unspecified public input.
	if service, ok := b.d.Input.Services[id]; ok && service.Sfc.Instance == nil && len(service.Sfc.Nodes) == 0 && !dynamicTaskAddresses(service) {
		return service, id, nil
	}
	key := ResourceKey("task", b.d.Tenant, b.d.App, id)
	for _, step := range b.d.Steps {
		if step.Kind != "task" || step.Key != key {
			continue
		}
		var service ComposeService
		if json.Unmarshal(step.Goal, &service) != nil {
			return ComposeService{}, "", ErrInputs
		}
		instance, err := TaskInstanceForKey(b.d.Tenant, b.d.App, key, service)
		if err != nil || instance.Node != step.Node {
			return ComposeService{}, "", ErrInputs
		}
		if _, exists := b.d.Input.Services[instance.Service]; !exists {
			return ComposeService{}, "", ErrInputs
		}
		return service, instance.Service, nil
	}
	return ComposeService{}, "", ErrInputs
}

// TaskInput exposes an owned per-instance declaration for existing adapters.
// Neither this read nor the internal identity grants permission or readiness.
func (b Blueprint) TaskInput(id string) (ComposeService, string, error) {
	service, name, err := b.taskInput(id)
	if err != nil {
		return ComposeService{}, "", err
	}
	raw, _ := json.Marshal(service)
	var owned ComposeService
	if json.Unmarshal(raw, &owned) != nil {
		return ComposeService{}, "", ErrInputs
	}
	return owned, name, nil
}

func (b Blueprint) ServiceInstances(service string) ([]TaskInstance, error) {
	source, exists := b.d.Input.Services[service]
	if !exists {
		return nil, ErrInputs
	}
	return servicePlacements(service, source, b.d.DefaultNode)
}
