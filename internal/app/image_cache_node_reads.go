// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"time"
)

func init() {
	defineNodeRead((*Runtime).nodeReadImageCacheNativePlan, false, "image-cache-native-plan")
	defineNodeRead((*Runtime).nodeReadImageCacheWork, false, "image-cache-work", "image-cache-plan-permit")
	defineNodeRead((*Runtime).nodeReadImageResolveOwner, false, "image-resolve-owner")
}

func (r *Runtime) nodeReadImageCacheNativePlan(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	read, err := schema.Decode[control.ImageCacheRead](input)
	if err != nil {
		return nil, err
	}
	plan, err := r.nativeImageCachePlan(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(plan)
}

func (r *Runtime) nodeReadImageCacheWork(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	if method == "image-cache-work" {
		q, err := schema.Decode[control.ImageCacheWorkRequest](input)
		if err != nil {
			return nil, err
		}
		work, err := r.controlPolicy.ImageCacheWork(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(work)
	}
	q, err := schema.Decode[control.ImageCacheRead](input)
	if err != nil {
		return nil, err
	}
	permit, err := r.controlPolicy.ImageCacheReadPermit(v.State, caller, time.Now().Unix(), q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadImageResolveOwner(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	read, err := schema.Decode[control.ImageResolveRead](input)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	result, err := r.resolveImageOwner(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
