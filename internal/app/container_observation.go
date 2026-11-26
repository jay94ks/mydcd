// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

func (r *Runtime) containerReadPermit(ctx context.Context, read control.ContainerRead) error {
	raw, err := json.Marshal(read)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "container-read-permit", raw)
	if err != nil {
		return err
	}
	index, err := schema.Decode[uint64](reply.Data)
	if err != nil || index == 0 || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex < index {
		return mydcp.ErrAdmission
	}
	return nil
}
func (r *Runtime) observeContainer(ctx context.Context, read control.ContainerRead) (containerops.Result, error) {
	var result containerops.Result
	if read.Target.Owner != r.Identity.Public {
		owner, ok := r.nativeOwner(read.Target.Owner)
		if !ok || !r.acceptsResourceOwner(ctx, read.Target.Node, read.Target.Owner) {
			return result, mydcp.ErrAdmission
		}
		return owner.observeContainer(ctx, read)
	}
	if read.Target.Owner != r.Identity.Public || !read.Target.Valid() || read.Query.Validate() != nil {
		return result, mydcp.ErrAdmission
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if err := r.containerReadPermit(ctx, read); err != nil {
		return result, err
	}
	r.life.RLock()
	if r.closed || r.workload == nil {
		r.life.RUnlock()
		return result, mydcp.ErrAdmission
	}
	result, err := r.observeContainerPage(ctx, read)
	r.life.RUnlock()
	if err != nil {
		return result, err
	}
	if err = r.containerReadPermit(ctx, read); err != nil {
		return containerops.Result{}, err
	}
	return result, nil
}

func (r *Runtime) observeContainerPage(ctx context.Context, read control.ContainerRead) (containerops.Result, error) {
	if read.Query.Kind == "inspect" {
		if read.Query.Cursor != "" {
			target, driver, err := r.workload.ContainerDetailIdentity(ctx, read.Target)
			if err != nil {
				return containerops.Result{}, err
			}
			result, err := r.logPages.Next(read.Session.User, target, read.Query, time.Now().Unix())
			if errors.Is(err, containerops.ErrLogCursorExpired) {
				return containerops.Result{Schema: 1, Kind: "inspect", Target: target, ObservedAt: time.Now().UTC(), LogDriver: driver, DetailCode: "CURSOR_EXPIRED"}, nil
			}
			return result, err
		}
		view, err := r.Engine().Read(ctx, false)
		if err != nil {
			return containerops.Result{}, err
		}
		declaration, err := r.controlPolicy.ContainerDetailDeclaration(view.State, read, time.Now().Unix())
		if err != nil {
			return containerops.Result{}, err
		}
		result, err := r.workload.ObserveContainerDetail(ctx, read.Target, read.Query, declaration)
		if errors.Is(err, containerops.ErrLogWindowLimit) {
			result.Detail = nil
			result.DetailCode = "DETAIL_WINDOW_LIMIT"
			return result, nil
		}
		if err != nil {
			return containerops.Result{}, err
		}
		if err = r.addContainerCheckerDetails(&result, read.Query); err != nil {
			if errors.Is(err, containerops.ErrLimit) {
				result.Detail = nil
				result.DetailCode = "DETAIL_WINDOW_LIMIT"
				return result, nil
			}
			return containerops.Result{}, err
		}
		if err = r.addContainerEventHistory(&result, read.Query); err != nil {
			return containerops.Result{}, err
		}
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return containerops.Result{}, err
		}
		page, err := r.logPages.OpenDetail(read.Session.User, read.Target, read.Query, result, nonce, time.Now().Unix())
		if errors.Is(err, containerops.ErrLogWindowLimit) {
			result.Detail = nil
			result.DetailCode = "DETAIL_WINDOW_LIMIT"
			return result, nil
		}
		if errors.Is(err, containerops.ErrLogCursorCapacity) {
			result.Detail = nil
			result.DetailCode = "DETAIL_CURSOR_CAPACITY"
			return result, nil
		}
		return page, err
	}
	if read.Query.Kind != "logs" {
		return r.workload.ObserveContainer(ctx, read.Target, read.Query)
	}
	var result containerops.Result
	var err error
	if read.Query.Cursor != "" {
		current, probeErr := r.workload.ProbeTarget(ctx, read.Target.Instance, read.Target.Generation, read.Target.Revision)
		if probeErr != nil {
			return result, probeErr
		}
		target := read.Target
		target.NativeID, target.StartedAt = current.Status.NativeID, current.Status.StartedAt
		if !target.Matches(read.Target) {
			return result, mydcp.ErrAdmission
		}
		result, err = r.logPages.Next(read.Session.User, target, read.Query, time.Now().Unix())
		if errors.Is(err, containerops.ErrLogCursorExpired) {
			return containerops.Result{Schema: 1, Kind: "logs", Target: target, ObservedAt: time.Now().UTC(), LogDriver: current.Status.LogDriver, LogCode: "CURSOR_EXPIRED"}, nil
		}
		return result, err
	}
	result, err = r.workload.ObserveContainerLogWindow(ctx, read.Target, read.Query)
	if errors.Is(err, containerops.ErrLogWindowLimit) {
		result.Truncated, result.LogCode = false, "LOG_WINDOW_LIMIT"
		return result, nil
	}
	if err != nil {
		return containerops.Result{}, err
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return containerops.Result{}, err
	}
	page, err := r.logPages.Open(read.Session.User, read.Target, read.Query, result, nonce, time.Now().Unix())
	if errors.Is(err, containerops.ErrLogCursorCapacity) {
		result.Stdout, result.Stderr = nil, nil
		result.LogCode = "LOG_CURSOR_CAPACITY"
		return result, nil
	}
	return page, err
}
func (r *Runtime) containerObservation(ctx context.Context, read control.ContainerRead) (containerops.Result, error) {
	if read.Target.Owner == r.Identity.Public {
		return r.observeContainer(ctx, read)
	}
	peer, ok := r.Mesh.Peer(mydcp.Identity(read.Target.Owner))
	if !ok || !peer.Member || peer.ID != read.Target.Node {
		return containerops.Result{}, mydcp.ErrAdmission
	}
	raw, err := json.Marshal(read)
	if err != nil {
		return containerops.Result{}, err
	}
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "container-observe", Input: raw})
	if err != nil {
		return containerops.Result{}, err
	}
	result, err := schema.Decode[containerops.Result](reply.Data)
	if err != nil || result.Validate(read.Query, read.Target) != nil {
		return containerops.Result{}, mydcp.ErrAdmission
	}
	return result, nil
}

func (r *Runtime) containerReadModule(ctx context.Context, method, key string, input []byte, v cluster.View) ([]byte, error) {
	read, err := schema.Decode[control.ContainerRead](input)
	if err != nil {
		return nil, err
	}
	if method == "container-read-permit" {
		if v.Local {
			return nil, mydcp.ErrAdmission
		}
		// The member transport binds key; the provider must be the exact owner.
		caller, err := identity.ParseKey(key)
		if err != nil {
			return nil, err
		}
		index, err := r.controlPolicy.ContainerReadPermit(v.State, caller, read, time.Now().Unix())
		if err != nil {
			return nil, err
		}
		return json.Marshal(index)
	}
	caller, err := identity.ParseKey(key)
	peer, ok := r.Mesh.Peer(mydcp.Identity(caller))
	if err != nil || !ok || !peer.Member {
		return nil, mydcp.ErrAdmission
	}
	result, err := r.observeContainer(ctx, read)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
