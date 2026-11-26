// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Built-in registries (UI-80) in the fake, with the record CAS of
// control.reduceRegistries: put of a new ID needs Expected 0 and a retained
// tenant-managed fixed Volume on the spec's node; every other change needs
// Expected = the record revision and bumps it by one; put may not change
// the Volume; delete needs a stopped, inactive registry. No server is run:
// start makes the registry active without a report (pending) until
// Fake.ObserveRegistry; stop makes it inactive at once.

// FakeRegistrySpec is the fixture default for a registry definition.
func FakeRegistrySpec(cluster [32]byte, tenant, id, node, authority string, vol volumes.Scope) registry.Specification {
	port := "443"
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		port = authority[i+1:]
	}
	return registry.Specification{Schema: 1, Tenant: tenant, ID: id, Node: node, Address: "0.0.0.0:" + port, Authority: authority,
		Volume: vol, Enabled: true, Metadata: registry.MetadataLimits{ManifestBytes: 4 << 20, Records: 4096, TotalBytes: 64 << 20},
		Blobs: registry.BlobLimits{BlobBytes: 4 << 30, TotalBytes: 50 << 30, Records: 16384}, Budget: workload.Resources{CPU: 1e9, Memory: 256 << 20},
		MaxRequests: 64, MaxHeaderBytes: 16 << 10, RequestTimeoutMS: 60000, TokenSeconds: 300}
}

// loadRegistries fills the fixture rows' stored definition.
func (w *world) loadRegistries(now int64) {
	w.registries = slices.Clone(w.registries)
	for i := range w.registries {
		r := &w.registries[i]
		if r.Spec.Schema == 0 {
			node := map[string]string{"shop": "node-b", "payments": "node-c"}[r.Tenant]
			r.Spec = FakeRegistrySpec(w.cluster, r.Tenant, r.ID, node, r.Endpoint, volumes.Scope{Cluster: w.cluster, Tenant: r.Tenant, ID: r.ID + "-data", Generation: 1, Registry: r.ID})
			r.Spec.Enabled = r.Active
			if r.Active {
				r.ObservedAt = now * 1000
			}
		}
		w.syncRegistry(r)
	}
}

// syncRegistry copies the spec into the row's screen fields.
func (w *world) syncRegistry(r *RegistryView) {
	r.Node, r.Address, r.Volume, r.Enabled = r.Spec.Node, r.Spec.Address, r.Spec.Volume.ID, r.Spec.Enabled
	r.Endpoint = r.Spec.Authority
	if r.Name == "" {
		r.Name = r.ID
	}
}

// ObserveRegistry reports that the registry serves its current spec (or,
// with ok false, drops the report).
func (f *Fake) ObserveRegistry(tenant, id string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.w.registries {
		r := &f.w.registries[i]
		if r.Tenant == tenant && r.ID == id && r.Active {
			r.ObservedAt = 0
			if ok {
				r.ObservedAt = f.now().UnixMilli()
			}
		}
	}
}

func (c *fakeConn) applyRegistry(op UserOperation, actor string) error {
	w := c.f.w
	ch := op.Change
	var sel control.RegistrySelection
	var spec registry.Specification
	if ch.Action == ActionPutRegistry {
		var q control.RegistryPut
		if decodePayload(ch.Payload, &q) != nil || q.Spec.Validate(w.cluster) != nil {
			return errors.New("payload")
		}
		spec, sel = q.Spec, control.RegistrySelection{Tenant: q.Spec.Tenant, ID: q.Spec.ID}
	} else if decodePayload(ch.Payload, &sel) != nil || sel.Tenant == "" || sel.ID == "" {
		return errors.New("payload")
	}
	if !w.canManage(actor, sel.Tenant) {
		return errForbidden
	}
	i := slices.IndexFunc(w.registries, func(r RegistryView) bool { return r.Tenant == sel.Tenant && r.ID == sel.ID })
	if i < 0 {
		if ch.Action != ActionPutRegistry || ch.Expected != 0 {
			return errCAS
		}
		v := slices.IndexFunc(w.volumes, func(v volumeRow) bool { return v.Scope == spec.Volume })
		if v < 0 || w.volumes[v].Kind != "fixed" || w.volumes[v].App != "" || !w.volumes[v].Retain || w.volumes[v].Node != spec.Node {
			return errCAS
		}
		r := RegistryView{Tenant: sel.Tenant, ID: sel.ID, Revision: 1, Generation: 1, Spec: spec, Active: spec.Enabled}
		w.syncRegistry(&r)
		w.registries = append(w.registries, r)
		return nil
	}
	r := &w.registries[i]
	if r.Deleted || r.Revision != ch.Expected {
		return errCAS
	}
	switch ch.Action {
	case ActionPutRegistry:
		if spec.Volume != r.Spec.Volume {
			return errors.New("volume")
		}
		changed := spec != r.Spec
		r.Spec = spec
		if changed {
			r.ObservedAt = 0 // a new spec is not served until reported
		}
	case ActionStartRegistry:
		r.Spec.Enabled = true
	case ActionStopRegistry:
		r.Spec.Enabled = false
	case ActionDeleteRegistry:
		if r.Spec.Enabled || r.Active {
			return errCAS
		}
		r.Deleted = true
	default:
		return errors.New("action")
	}
	if r.Spec.Enabled && !r.Active {
		r.Active, r.Generation, r.ObservedAt = true, r.Generation+1, 0
	} else if !r.Spec.Enabled {
		r.Active, r.ObservedAt = false, 0
	}
	r.Revision++
	w.syncRegistry(r)
	return nil
}
