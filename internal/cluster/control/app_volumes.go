// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

type AppVolumeMaterial struct {
	Spec          volumes.NativeSpec
	Generation    uint64
	CapacityBytes uint64
}

func (v Volumes) Native(tenant, app, id string) (volumes.NativeReady, bool) {
	entry, ok := v.entries[(volumes.Scope{Tenant: tenant, App: app, ID: id}).Key()]
	if !ok || entry.State.Deleted() {
		return volumes.NativeReady{}, false
	}
	raw, _ := json.Marshal(entry.Native)
	var owned volumes.NativeReady
	_ = json.Unmarshal(raw, &owned)
	return owned, true
}

// AppVolumeMaterial derives metadata only. It neither adopts nor prepares an
// Engine volume and cannot replace the mandatory current owner native permit.
func (p Policy) AppVolumeMaterial(s state.State, source deployment.ObjectRef) (AppVolumeMaterial, error) {
	o := s.Object(source.Key)
	var goal deployment.GoalCommand
	if !o.Present || o.Generation != source.Generation || o.Revision != source.Revision || canonical([]byte(o.Value), &goal) != nil || goal.Kind != "volume" || goal.Cluster != p.Cluster || goal.Lifecycle != nil && goal.Lifecycle.Drain {
		return AppVolumeMaterial{}, ErrCatalog
	}
	id := source.Key[strings.LastIndex(source.Key, "/")+1:]
	if source.Key != deployment.ResourceKey("volume", goal.Tenant, goal.App, id) {
		return AppVolumeMaterial{}, ErrCatalog
	}
	var declaration deployment.ComposeVolume
	if canonical(goal.Config, &declaration) != nil || declaration.MyDC.Node != goal.Node || declaration.MyDC.Retain == nil || !*declaration.MyDC.Retain || declaration.MyDC.Quota != "observe" {
		return AppVolumeMaterial{}, ErrCatalog
	}
	v, err := p.Volumes(s)
	if err != nil {
		return AppVolumeMaterial{}, err
	}
	if entry, exists := v.entries[goal.Tenant+"/"+goal.App+"/"+id]; exists && entry.State.DeleteRevision() != 0 {
		return AppVolumeMaterial{}, ErrCatalog
	}
	if original, exists := v.Native(goal.Tenant, goal.App, id); exists {
		if original.Verify() != nil || original.Spec.Scope.Cluster != p.Cluster || original.Spec.Node != goal.Node || original.Spec.NodeKey != goal.Owner || declaration.MyDC.UID != 0 && declaration.MyDC.UID != original.Spec.UID || declaration.MyDC.GID != 0 && declaration.MyDC.GID != original.Spec.GID {
			return AppVolumeMaterial{}, ErrCatalog
		}
		if declaration.MyDC.Mode != "" {
			mode, err := strconv.ParseUint(declaration.MyDC.Mode, 8, 32)
			if err != nil || uint32(mode) != original.Spec.Mode {
				return AppVolumeMaterial{}, ErrCatalog
			}
		}
		e := v.entries[goal.Tenant+"/"+goal.App+"/"+id]
		if uint64(declaration.MyDC.Capacity) > e.CapacityBytes {
			return AppVolumeMaterial{}, ErrCatalog
		}
		return AppVolumeMaterial{original.Spec, original.Generation, e.CapacityBytes}, nil
	}
	if v.volumeMetadataSlots() >= maxVolumes {
		return AppVolumeMaterial{}, ErrCatalog
	}
	if !v.restoreTargetAvailable(volumes.Scope{Cluster: p.Cluster, Tenant: goal.Tenant, App: goal.App, ID: id, Generation: source.Generation}) {
		return AppVolumeMaterial{}, ErrCatalog
	}
	if declaration.External {
		return AppVolumeMaterial{}, ErrCatalog
	}
	mode, err := strconv.ParseUint(declaration.MyDC.Mode, 8, 32)
	if err != nil {
		return AppVolumeMaterial{}, ErrCatalog
	}
	spec := volumes.NativeSpec{Schema: 1, Scope: volumes.Scope{Cluster: p.Cluster, Tenant: goal.Tenant, App: goal.App, ID: id, Generation: source.Generation}, Node: goal.Node, NodeKey: goal.Owner, Materialization: "initial", UID: declaration.MyDC.UID, GID: declaration.MyDC.GID, Mode: uint32(mode), Retain: true}
	if spec.Validate() != nil {
		return AppVolumeMaterial{}, ErrCatalog
	}
	if !v.admitOriginal(goal.Tenant, goal.Node, goal.Owner, uint64(declaration.MyDC.Capacity)) {
		return AppVolumeMaterial{}, ErrCatalog
	}
	return AppVolumeMaterial{spec, source.Generation, uint64(declaration.MyDC.Capacity)}, nil
}

func (p Policy) reduceAppVolumeReady(s state.State, r AppProgress, a Apps, entry appEntry, e deployment.Execution) (map[string][]byte, state.Code) {
	stage, ok := e.Stage(r.Key)
	if !ok || stage.Result == nil || stage.Result.Code != state.Applied || stage.Command == nil {
		return nil, state.ConditionFailed
	}
	source := deployment.ObjectRef{Key: r.Key, Generation: stage.Result.Generation, Revision: stage.Result.Revision}
	if _, err := p.NativePermit(s, r.Reporter, NativeRequest{Source: source}); err != nil {
		return nil, state.Forbidden
	}
	material, err := p.AppVolumeMaterial(s, source)
	if err != nil || r.Volume.Verify() != nil || r.Volume.Spec != material.Spec || r.Volume.Generation != material.Generation || !p.ownsResource(s, r.Reporter, r.Volume.Spec.NodeKey) || r.Observation.Native != r.Volume.Owner.Native || !r.Observation.Applied || r.Observation.Released {
		return nil, state.ConditionFailed
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	key := volumeKey(material.Spec.Scope)
	_, exists := v.entries[key]
	if exists {
		left, _ := json.Marshal(v.entries[key].Native)
		right, _ := json.Marshal(r.Volume)
		if !bytes.Equal(left, right) {
			return nil, state.ConditionFailed
		}
	} else {
		if v.volumeReservations() >= maxVolumes {
			return nil, state.ConditionFailed
		}
		c, err := p.Catalog(s)
		if err != nil {
			return nil, state.Invalid
		}
		capacity, err := p.bindingCapacity(s, deployment.Needs{Use: secrets.Use{Tenant: material.Spec.Scope.Tenant, Node: material.Spec.Node, NodeKey: material.Spec.NodeKey}})
		if err != nil || capacity < 1 {
			return nil, state.Forbidden
		}
		core, err := volumes.New(c, entry.Origin.Session.User, material.Spec.Scope, r.Volume.Owner, min(capacity, 256))
		if err != nil {
			return nil, state.Forbidden
		}
		v.entries[key] = registeredVolume{Native: *r.Volume, State: core, CapacityBytes: material.CapacityBytes}
	}
	e, err = e.Observe(e.Revision(), *r.Observation, r.At)
	if err != nil {
		return nil, state.ConditionFailed
	}
	entry.Inventory, err = p.advanceAppInventory(s, entry.Inventory, e)
	if err != nil {
		return nil, state.ConditionFailed
	}
	a.entries[appKey(r.Tenant, r.App)] = entry
	writes, code := p.appsCheckpoint(s, a, r.At)
	if code != state.Applied {
		return nil, code
	}
	if !exists {
		other, code := p.volumeCheckpoint(s, v)
		if code != state.Applied {
			return nil, code
		}
		for key, value := range other {
			writes[key] = value
		}
	}
	return writes, state.Applied
}
