// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

func (r *Runtime) containerSessionRead(_ context.Context, method, key string, input []byte, v cluster.View) ([]byte, error) {
	if v.Local {
		return nil, mydcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	if method == "container-session-plan" {
		members, err := r.controlPolicy.Members(v.State)
		if err != nil || !members.MemberKey(caller) {
			return nil, mydcp.ErrAdmission
		}
		q, err := schema.Decode[control.ContainerSessionPlan](input)
		if err != nil {
			return nil, err
		}
		target, err := r.controlPolicy.ContainerSessionTarget(v.State, q, time.Now().Unix())
		if err != nil {
			return nil, err
		}
		return json.Marshal(target)
	}
	q, err := schema.Decode[control.ContainerSessionPermit](input)
	if err != nil {
		return nil, err
	}
	index, err := r.controlPolicy.ContainerSessionPermit(v.State, caller, q, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	return json.Marshal(index)
}

func (r *Runtime) containerSessionPlan(ctx context.Context, q control.ContainerSessionPlan) (containerops.Target, error) {
	raw, err := json.Marshal(q)
	if err != nil {
		return containerops.Target{}, err
	}
	reply, err := r.appCall(ctx, "container-session-plan", raw)
	if err != nil {
		return containerops.Target{}, err
	}
	target, err := schema.Decode[containerops.Target](reply.Data)
	if err != nil || !target.Valid() || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex < target.Revision {
		return containerops.Target{}, mydcp.ErrAdmission
	}
	return target, nil
}

func (r *Runtime) containerSessionPermit(ctx context.Context, q control.ContainerSessionPermit) error {
	raw, err := json.Marshal(q)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "container-session-permit", raw)
	if err != nil {
		return err
	}
	index, err := schema.Decode[uint64](reply.Data)
	if err != nil || index == 0 || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex < index {
		return mydcp.ErrAdmission
	}
	return nil
}

func (r *Runtime) containerExecStatus(ctx context.Context, current access.Session, intent containerops.SessionIntent) (containerops.ExecStatus, error) {
	var out containerops.ExecStatus
	if intent.Target.Owner != r.Identity.Public {
		owner, ok := r.nativeOwner(intent.Target.Owner)
		if !ok || !r.acceptsResourceOwner(ctx, intent.Target.Node, intent.Target.Owner) {
			return out, mydcp.ErrAdmission
		}
		return owner.containerExecStatus(ctx, current, intent)
	}
	if intent.Target.Owner != r.Identity.Public || intent.User != current.User {
		return out, mydcp.ErrAdmission
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.workload == nil {
		return out, mydcp.ErrAdmission
	}
	return r.containerExecStatusLocked(ctx, current, intent)
}

func (r *Runtime) containerExecStatusLocked(ctx context.Context, current access.Session, intent containerops.SessionIntent) (containerops.ExecStatus, error) {
	var out containerops.ExecStatus
	row, err := r.userExecRecord(intent)
	if err != nil {
		return out, err
	}
	permit := func(call context.Context) error {
		return r.containerSessionPermit(call, control.ContainerSessionPermit{Session: current, Original: row.Original, Intent: row.Intent, Status: true})
	}
	if err := permit(ctx); err != nil {
		return out, err
	}
	next, running, inspectErr := r.workload.InspectContainerExec(ctx, intent.Target, row.Receipt, permit)
	// Unavailable native state is not a new exec or a successful zero exit.
	if inspectErr == nil {
		if err := r.updateUserExec(intent, next); err != nil {
			return out, err
		}
		latest, err := r.userExecRecord(intent)
		if err != nil {
			return out, err
		}
		if latest.Receipt.Phase != next.Phase {
			running = nil
		}
		next = latest.Receipt
	} else {
		next, running = row.Receipt, nil
	}
	if err := permit(ctx); err != nil {
		return out, err
	}
	return containerops.ExecStatus{Schema: 1, Request: intent.Request, Target: intent.Target, Receipt: next, Running: running, ObservedAt: time.Now().UTC()}, nil
}
