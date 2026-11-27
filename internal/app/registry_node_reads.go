// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"time"
)

func init() {
	defineNodeRead((*Runtime).nodeReadExternalRegistryWork, false, "external-registry-work")
	defineNodeRead((*Runtime).nodeReadRegistryImagePermit, false, "registry-image-permit")
	defineNodeRead((*Runtime).nodeReadRegistryWork, false, "registry-work")
	defineNodeRead((*Runtime).nodeReadRegistryMaintenanceWork, false, "registry-maintenance-work")
	defineNodeRead((*Runtime).nodeReadRegistryPruneOwner, false, "registry-prune-owner")
	defineNodeRead((*Runtime).nodeReadRegistryCatalogOwner, false, "registry-catalog-owner")
	defineNodeRead((*Runtime).nodeReadExternalRegistryProbe, false, "external-registry-probe")
}

func (r *Runtime) nodeReadExternalRegistryWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.ExternalRegistryWorkRequest](input)
	now := time.Now().Unix()
	if err != nil || q.At <= 0 || !access.Recent(q.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.ExternalRegistryWork(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadRegistryImagePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.RegistryImageRequest](input)
	now := time.Now().Unix()
	if err != nil || q.At <= 0 || !access.Recent(q.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	permit, err := r.controlPolicy.RegistryImagePermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadRegistryWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.RegistryWorkRequest](input)
	now := time.Now().Unix()
	if err != nil || q.At <= 0 || !access.Recent(q.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	work, err := r.controlPolicy.RegistryWork(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadRegistryMaintenanceWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.RegistryMaintenanceWorkRequest](input)
	if err != nil {
		return nil, err
	}
	work, err := r.controlPolicy.RegistryMaintenanceWork(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(work)
}

func (r *Runtime) nodeReadRegistryPruneOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	q, err := schema.Decode[registryPruneOwnerRequest](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	result, err := r.registryPruneOwner(ctx, q.Read, q.Results)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func (r *Runtime) nodeReadRegistryCatalogOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	read, err := schema.Decode[control.RegistryCatalogueRead](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	result, err := r.registryCatalogueOwner(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func (r *Runtime) nodeReadExternalRegistryProbe(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	read, err := schema.Decode[control.ExternalRegistryProbeRead](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	result, err := r.probeExternalRegistry(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
