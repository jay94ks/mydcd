// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
)

// CollectAppTaskClosure signs only an original, positively settled native
// removal. It never removes a Task or releases shared references by itself.
// Retirement/down submits the original removal; this collector also works
// after current activation permissions have been revoked.
func (r *Runtime) CollectAppTaskClosure(ctx context.Context, request control.AppBindingRequest) (deployment.Observation, deployment.Closure, error) {
	r.inputLife.RLock()
	defer r.inputLife.RUnlock()
	var stopped deployment.Observation
	var proof deployment.Closure
	if r.ctx.Err() != nil || r.workload == nil || r.activations == nil {
		return stopped, proof, deployment.ErrInputs
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return stopped, proof, err
	}
	a, err := r.controlPolicy.Apps(v.State)
	if err != nil {
		return stopped, proof, err
	}
	b, ok := a.Binding(request.Task)
	source, found := a.BindingSource(request.Digest)
	if !ok || !found || b.Digest() != request.Digest || source.Task != request.Task || b.Needs().Use.NodeKey != r.Identity.Public {
		return stopped, proof, deployment.ErrInputs
	}
	claim, ok := a.Claim(b.Needs().Use.Tenant, b.Needs().Use.App, request.Task)
	stage := deployment.StageRecord{Key: claim.Step.Key, Command: &claim.Command, Result: &claim.Result, Observation: claim.Observation}
	if !ok || stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied || stage.Result.Generation != request.Task.Generation || stage.Result.Revision != request.Task.Revision {
		return stopped, proof, deployment.ErrInputs
	}
	// A Task whose command committed but whose container this owner never
	// created (or never observed) has no native ID to carry forward. The
	// closure still needs Gone below; it names that absence explicitly.
	native := deployment.NeverObservedNative
	if stage.Observation != nil {
		native = stage.Observation.Native
	}
	// A surged original runs from its parked record while the new
	// generation holds the main one; it closes on that record alone.
	parked, err := r.parkedOriginal(request.Task.Key, request.Task.Generation)
	if err != nil {
		return stopped, proof, err
	}
	if parked {
		if gone, err := r.workload.ParkedGone(ctx, request.Task.Key, request.Task.Generation); err != nil || !gone {
			return stopped, proof, deployment.ErrInputs
		}
	} else {
		row, err := r.workload.View(request.Task.Key)
		if err != nil {
			return stopped, proof, err
		}
		if row.State.Desired.Revision <= request.Task.Revision {
			return stopped, proof, deployment.ErrInputs
		}
		if gone, err := r.workload.Gone(ctx, request.Task.Key, row.State.Desired.Revision, request.Task.Generation); err != nil || !gone {
			return stopped, proof, deployment.ErrInputs
		}
	}
	if err = r.retireTaskCheckers(ctx, request.Task); err != nil {
		return stopped, proof, err
	}
	stopped, err = r.appObservation(control.AppView{Operation: deployment.OperationSummary{ID: source.Operation, Plan: source.Plan}}, stage, native, false)
	if err != nil {
		return stopped, proof, err
	}
	stopped.Applied = false
	stopped.Stopped = true
	stopped.Gone = true
	stopped.Released = true
	stopped.Signature = ed25519.Sign(r.Identity.Private, deployment.ObservationBytes(stopped))
	request.At = time.Now().Unix()
	if _, err = r.controlPolicy.AppInputClosure(v.State, r.commandIdentity().Public, request, stopped); err != nil {
		return deployment.Observation{}, proof, err
	}
	if source.Inputs.Key != "" {
		proof, err = r.retireAppInputs(ctx, request, stopped)
		if err != nil {
			return deployment.Observation{}, deployment.Closure{}, err
		}
	}
	if source.Inputs.Key == "" && len(b.SocketGrants()) != 0 {
		// An sfev.sock-only task has no projection store scope: its socket
		// grants close here, once the container is gone (checked above).
		if b.Needs().Use.NodeKey != r.Identity.Public || len(b.Grants()) != len(b.SocketGrants()) {
			return deployment.Observation{}, deployment.Closure{}, deployment.ErrInputs
		}
		for _, g := range b.SocketGrants() {
			u := g.Use
			gone := secrets.UseGone{Purpose: u.Purpose, Cluster: r.controlPolicy.Cluster, Realm: g.Realm, Tenant: u.Tenant, App: u.App, Deployment: u.Deployment, Consumer: g.Consumer, Generation: g.Generation, NodeKey: r.Identity.Public, Selection: g.Selection, Lifetime: g.Lifetime, Stopped: true, MountsGone: true}
			gone.Signature = ed25519.Sign(r.Identity.Private, secrets.UseGoneBytes(gone))
			proof.Secrets = append(proof.Secrets, gone)
		}
	}
	for _, pin := range b.Pins() {
		if pin.Consumer.Remote() {
			// A remote consumer runs here: its Gone is the runner's, after
			// the task's container is gone and its mount released.
			key, valid := pin.Consumer.GoneKey()
			runner, ok := r.nativeOwner(key)
			if !valid || !ok || r.remoteMounts == nil {
				return deployment.Observation{}, deployment.Closure{}, deployment.ErrInputs
			}
			gone, err := r.remoteMounts.Gone(pin.Scope, pin.Consumer, runner.Identity.Private)
			if err != nil {
				return deployment.Observation{}, deployment.Closure{}, err
			}
			proof.Volumes = append(proof.Volumes, gone)
			continue
		}
		owner, ok := r.nativeOwner(pin.Consumer.Owner.Key)
		if !ok || owner.activations == nil {
			return deployment.Observation{}, deployment.Closure{}, deployment.ErrInputs
		}
		gone, err := owner.activations.ConsumerGone(ctx, pin.Scope, pin.Consumer, source.Task.Key, source.Task.Generation, owner.Identity.Private)
		if err != nil {
			return deployment.Observation{}, deployment.Closure{}, err
		}
		proof.Volumes = append(proof.Volumes, gone)
	}
	return stopped, proof, nil
}
