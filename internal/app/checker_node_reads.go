// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"slices"
	"time"
)

func init() {
	defineNodeRead((*Runtime).nodeReadCheckerCacheObserve, false, "checker-cache-observe")
	defineNodeRead((*Runtime).nodeReadCheckerBuildPermit, false, "checker-build-permit")
	defineNodeRead((*Runtime).nodeReadCheckerArtifactPermit, false, "checker-artifact-permit")
	defineNodeRead((*Runtime).nodeReadCheckerCacheGcFence, false, "checker-cache-gc-fence")
	defineNodeRead((*Runtime).nodeReadCheckerSourcePermit, false, "checker-source-permit")
	defineNodeRead((*Runtime).nodeReadCheckerProbePermit, true, "checker-probe-permit", "checker-shutdown-permit", "app-native-permit", "app-result", "app-binding-permit", "app-input-read-permit")
}

func (r *Runtime) nodeReadCheckerCacheObserve(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	peer, known := r.Mesh.Peer(sfcp.Identity(caller))
	if err != nil || !known || !peer.Member {
		return nil, sfcp.ErrAdmission
	}
	q, err := schema.Decode[control.CheckerArtifactRequest](input)
	if err != nil {
		return nil, err
	}
	observation, err := r.observeCheckerCache(ctx, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(observation)
}

func (r *Runtime) nodeReadCheckerBuildPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.CheckerBuildRequest](input)
	now := time.Now().Unix()
	if err != nil || !access.Recent(q.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	permit, err := r.controlPolicy.CheckerBuildPermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadCheckerArtifactPermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.CheckerArtifactRequest](input)
	now := time.Now().Unix()
	if err != nil || !access.Recent(q.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	permit, err := r.controlPolicy.CheckerArtifactPermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadCheckerCacheGcFence(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local || len(input) != 0 {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	directory, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(directory.Issuers(), caller) {
		return nil, sfcp.ErrAdmission
	}
	return json.Marshal(checkerCacheFence{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: caller, Index: v.State.Index(), Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.LifecycleKey).Revision})
}

func (r *Runtime) nodeReadCheckerSourcePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.LifecycleSourcePermitRequest](input)
	now := time.Now().Unix()
	if err != nil || !access.Recent(q.At, now, 30) {
		return nil, sfcp.ErrAdmission
	}
	permit, err := r.controlPolicy.LifecycleSourcePermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) nodeReadCheckerProbePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, errors.New("managed quorum app read required")
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	if method == "checker-probe-permit" {
		if len(input) > control.MaxCheckerProbePermitBytes {
			return nil, sfcp.ErrAdmission
		}
		q, err := schema.Decode[control.CheckerProbeRequest](input)
		now := time.Now().UnixMilli()
		if err != nil || !access.RecentMillis(q.At, now, 30000) || q.DeadlineUnixMilli <= now {
			return nil, sfcp.ErrAdmission
		}
		permit, err := r.controlPolicy.CheckerProbePermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "checker-shutdown-permit" {
		q, err := schema.Decode[control.CheckerShutdownRequest](input)
		now := time.Now().Unix()
		if err != nil || !access.Recent(q.At, now, 30) {
			return nil, errors.New("stale shutdown check request")
		}
		permit, err := r.controlPolicy.CheckerShutdownPermit(v.State, caller, q)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "app-input-read-permit" {
		request, err := schema.Decode[control.AppInputFetch](input)
		now := time.Now().Unix()
		if err != nil || !access.Recent(request.Binding.At, now, 30) {
			return nil, errors.New("stale input fetch request")
		}
		permit, err := r.controlPolicy.AppInputFetchPermit(v.State, caller, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "app-binding-permit" {
		request, err := schema.Decode[control.AppBindingRequest](input)
		now := time.Now().Unix()
		if err != nil || !access.Recent(request.At, now, 30) {
			return nil, errors.New("stale app binding request")
		}
		permit, err := r.controlPolicy.AppBindingPermit(v.State, caller, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	if method == "app-native-permit" {
		request, err := schema.Decode[control.NativeRequest](input)
		if err != nil {
			return nil, err
		}
		permit, err := r.controlPolicy.NativePermit(v.State, caller, request)
		if err != nil {
			return nil, err
		}
		return json.Marshal(permit)
	}
	cmd, err := state.DecodeCommand(input)
	if err != nil {
		return nil, err
	}
	result, err := r.controlPolicy.AppResult(v.State, caller, cmd)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
