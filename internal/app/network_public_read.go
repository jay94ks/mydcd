// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// Read the original owner through the existing authenticated observe RPC. A
// missing response never becomes a fabricated zero count or signed closure.
func (r *Runtime) networkClosureRead(ctx context.Context, target control.NetworkReadTarget) (control.NetworkClosureStatus, error) {
	out := control.NetworkClosureStatus{State: "unreachable"}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if ctx.Err() != nil || !r.life.TryRLock() {
		return out, mydcp.ErrAdmission
	}
	defer r.life.RUnlock()
	if r.closed {
		return out, mydcp.ErrAdmission
	}
	var raw []byte
	if target.Network.Owner == r.Identity.Public {
		v, err := r.Engine().Read(ctx, false)
		if err != nil {
			return out, err
		}
		projection, err := r.controlPolicy.ProjectResources(v.State)
		if err != nil {
			return out, err
		}
		source, ok := projection.ManagedSources[target.Source.Key]
		o := v.State.Object(target.Source.Key)
		if !ok || source.Network.ID != target.Network.ID || source.Network.Tenant != target.Network.Tenant || source.Network.Owner != target.Network.Owner || o.Generation != target.Source.Generation || o.Revision != target.Source.Revision {
			return out, mydcp.ErrAdmission
		}
		raw, err = r.observeManagedNetwork(ctx, target.Source.Key, v, projection, source)
		if err != nil {
			return out, err
		}
	} else {
		peer, ok := r.Mesh.Peer(mydcp.Identity(target.Network.Owner))
		if !ok || !peer.Member || peer.ID != target.Network.Node {
			return out, mydcp.ErrAdmission
		}
		reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "observe", Key: target.Source.Key, Latest: false})
		if err != nil {
			return out, err
		}
		raw = reply.Data
	}
	observation, err := schema.Decode[ModuleObservation](raw)
	if err != nil || observation.Schema != 1 || observation.Key != target.Source.Key || observation.Generation != target.Source.Generation || observation.Revision != target.Source.Revision {
		return out, mydcp.ErrAdmission
	}
	out.State = "pending"
	if observation.NetworkClosure != nil {
		out = *observation.NetworkClosure
	}
	if observation.Journal.GenerationFloor == target.Source.Generation {
		pins := uint64(max(0, observation.Journal.Consumers))
		out.PendingPins = &pins
	}
	if len(observation.Retirement) > 0 {
		proof, err := schema.Decode[tenancy.NetworkClosure](observation.Retirement)
		if err != nil || !target.VerifyClosure(r.controlPolicy.Cluster, proof) {
			return out, mydcp.ErrAdmission
		}
		out.State = "closed"
		out.Closure = &proof
		out.NativeGone = &proof.NativeGone
		out.PendingEndpoints = &proof.PendingEndpoints
		out.PendingFlows = &proof.PendingFlows
		out.PendingPins = &proof.PendingPins
	}
	return out, nil
}
