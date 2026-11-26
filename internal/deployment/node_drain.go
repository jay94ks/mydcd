// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/access"
	"slices"
)

// DeclaredService returns the effective declaration before per-instance
// address assignment. A planned dynamic address is not a user-fixed address.
func (b Blueprint) DeclaredService(name string) (ComposeService, bool) {
	service, ok := b.d.Input.Services[name]
	if !ok {
		return ComposeService{}, false
	}
	raw, _ := json.Marshal(service)
	var owned ComposeService
	if json.Unmarshal(raw, &owned) != nil {
		return ComposeService{}, false
	}
	return owned, true
}

// RelocateNode compiles an explicitly approved evacuation from the frozen
// effective input. It does not reconstruct original YAML, issue native calls,
// or bypass Inventory's existing replacement/Volume move closure.
func (b Blueprint) RelocateNode(c access.Catalog, ctx PlanningContext, from, to string, services []string) (Blueprint, error) {
	return b.relocateNode(c, ctx, from, to, services, nil)
}
func (b Blueprint) RelocateVolumeNode(c access.Catalog, ctx PlanningContext, from, to string, services []string, move VolumeMovePlacement) (Blueprint, error) {
	return b.relocateNode(c, ctx, from, to, services, &move)
}
func (b Blueprint) relocateNode(c access.Catalog, ctx PlanningContext, from, to string, services []string, move *VolumeMovePlacement) (Blueprint, error) {
	if from == to || !identifier(from) || !identifier(to) || len(services) == 0 {
		return Blueprint{}, ErrInputs
	}
	raw, _ := json.Marshal(b.d.Input)
	var input Compose
	if json.Unmarshal(raw, &input) != nil {
		return Blueprint{}, ErrInputs
	}
	for _, name := range services {
		service, found := input.Services[name]
		if !found {
			return Blueprint{}, ErrInputs
		}
		if service.MyDC.Node == from || service.MyDC.Node == "" && len(service.MyDC.Nodes) == 0 && b.d.DefaultNode == from {
			service.MyDC.Node = to
		} else if slices.Contains(service.MyDC.Nodes, from) {
			if slices.Contains(service.MyDC.Nodes, to) {
				return Blueprint{}, inputError("INSTANCE_NODE_CONFLICT", name)
			}
			service.MyDC.Nodes = slices.Clone(service.MyDC.Nodes)
			for i, node := range service.MyDC.Nodes {
				if node == from {
					service.MyDC.Nodes[i] = to
				}
			}
		} else {
			return Blueprint{}, ErrInputs
		}
		for _, mount := range service.Volumes {
			allowed := false
			if move != nil {
				for _, row := range volumeMovePlacements(*move) {
					allowed = allowed || mount.Source == row.Scope.ID
				}
			}
			if mount.Type == "volume" && !allowed {
				return Blueprint{}, inputError("VOLUME_MOVE_REQUIRED", mount.Source)
			}
		}
		for _, attachment := range service.Networks {
			if attachment.IPv4 != "" || attachment.IPv6 != "" {
				return Blueprint{}, inputError("STATIC_ADDRESS_REPLAN_REQUIRED", name)
			}
		}
		input.Services[name] = service
	}
	if move != nil {
		for _, row := range volumeMovePlacements(*move) {
			definition, ok := input.Volumes[row.Scope.ID]
			if !ok || row.Scope.Cluster != ctx.Cluster || row.Scope.Tenant != b.d.Tenant || row.Scope.App != b.d.App || row.Source.Node != from || row.Target.Node != to {
				return Blueprint{}, ErrInputs
			}
			definition.MyDC.Node = to
			input.Volumes[row.Scope.ID] = definition
		}
	}

	if ctx.DefaultNode == "" {
		ctx.DefaultNode = b.d.DefaultNode
	}
	ctx.Project, ctx.Deployment = b.d.App, b.d.Deployment
	if move != nil {
		return compileVolumeMove(input, c, ctx, *move, b.d.InputKind)
	}
	return compile(input, c, ctx, nil, b.d.InputKind)
}
