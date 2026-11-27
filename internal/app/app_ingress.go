// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/schema"
)

func managedIngressID(key string, generation uint64, spec ingress.Spec) string {
	return ingress.ManagedNativeID(key, generation, spec)
}

func (r *Runtime) reconcileManagedIngress(v cluster.View, p control.ResourceProjection, apps control.Apps) (uint64, error) {
	if r.ingress == nil {
		return 0, nil
	}
	var observedFloor uint64
	keys := map[string]bool{}
	for key, g := range p.Goals {
		if g.Ingress != nil && g.Goal.Owner == r.Identity.Public {
			keys[key] = true
		}
	}
	for _, key := range r.ingress.Keys() {
		if !clusterAppIngressKey(key) {
			keys[key] = true
		}
	}
	for _, key := range desired.Sorted(keys) {
		o := v.State.Object(key)
		g, known := p.Goals[key]
		if !known || g.Ingress == nil {
			if o.Present {
				return 0, deployment.ErrInputs
			}
			if err := r.ingress.Reconcile(r.ctx, key, o.Revision, o.Generation, nil); err != nil {
				return 0, err
			}
			continue
		}
		if g.Goal.Owner != r.Identity.Public {
			return 0, deployment.ErrInputs
		}
		spec := *g.Ingress
		native, err := r.ingressNativeBinding(v.State, apps, g.Goal, key, o, spec, true)
		if err != nil {
			return 0, fmt.Errorf("ingress %s native binding: %w", key, err)
		}
		old, err := r.ingress.Observe(key)
		// Original serving/retirement can be observed and settled after rights
		// are revoked. Every new/restarted listener still needs current quorum.
		if !spec.Lifecycle.Drain && (err != nil || !old.Ready || r.ingress.NeedsBackendUpdate(key, spec)) {
			raw, _ := json.Marshal(control.NativeRequest{Source: deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}})
			reply, err := r.appCall(r.ctx, "app-native-permit", raw)
			if err != nil {
				return 0, fmt.Errorf("ingress %s current native permit: %w", key, err)
			}
			permit, err := schema.Decode[control.NativePermit](reply.Data)
			if err != nil || permit.Kind != "ingress" || permit.Native != native || permit.Source != (deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}) || permit.Owner != r.Identity.Public || permit.Spec != ingress.SpecDigest(spec) {
				return 0, fmt.Errorf("ingress %s permit mismatch (decode=%v kind=%q native=%t source=%t owner=%t spec=%t): %w", key, err, permit.Kind, permit.Native == native, permit.Source == (deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}), permit.Owner == r.Identity.Public, permit.Spec == ingress.SpecDigest(spec), deployment.ErrInputs)
			}
		}
		if err = r.ingress.Reconcile(r.ctx, key, o.Revision, o.Generation, &spec); err != nil {
			return 0, fmt.Errorf("ingress %s runtime reconcile: %w", key, err)
		}
		if !spec.Lifecycle.Drain {
			if err = r.ingress.BindNative(key, o.Generation, native); err != nil {
				return 0, fmt.Errorf("ingress %s persist native binding: %w", key, err)
			}
		}
		observed, err := r.ingress.Observe(key)
		if err != nil {
			return 0, err
		}
		if !observed.Ready && !spec.DynamicBackends {
			continue
		}
		for _, app := range apps.Records() {
			e, ok := apps.Execution(app.Tenant, app.App)
			if !ok {
				continue
			}
			stage, ok := e.Stage(key)
			if !ok || stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied {
				continue
			}
			backends, drained := ingressReplicaFacts(g.Goal, e, observed)
			if r.freshAppEvidence(stage, native, observed.Started, observed.Ready) && slices.Equal(stage.Observation.IngressBackends, backends) && slices.Equal(stage.Observation.IngressDrained, drained) {
				continue
			}
			observation, err := r.appObservation(app, stage, native, observed.Ready)
			if err != nil {
				return 0, err
			}
			observation.Pins = uint64(observed.Requests)
			observation.Applied = observed.Started
			observation.IngressBackends = backends
			observation.IngressDrained = drained
			observation.Signature = ed25519.Sign(r.Identity.Private, deployment.ObservationBytes(observation))
			index, err := r.sendAppProgressAt(r.ctx, r.newAppProgress(v, app, "observe", key, &observation))
			if err != nil {
				return 0, err
			}
			observedFloor = max(observedFloor, index)
			break
		}
	}
	return observedFloor, nil
}

// The runtime includes fixed and followed service backends. These optional
// transition facts belong only to the original explicit replica identity set;
// fixed Task health and the complete listener's Ready remain separate facts.
func ingressReplicaFacts(goal deployment.GoalCommand, execution deployment.Execution, observed ingress.Observation) (backends, drained []deployment.ObjectRef) {
	if observed.Ready {
		for _, backend := range observed.Backends {
			if slices.Contains(goal.Follow, backend.Task) {
				backends = append(backends, deployment.ObjectRef{Key: backend.Task, Generation: backend.Generation, Revision: backend.Revision})
			}
		}
	}
	for _, backend := range observed.DrainedBackends {
		if !slices.Contains(goal.Follow, backend.Task) {
			continue
		}
		task, exists := execution.Stage(backend.Task)
		if !exists || task.Previous == nil || task.Previous.Result.Generation != backend.Generation {
			continue
		}
		original := task.Previous.Result
		drained = append(drained, deployment.ObjectRef{Key: backend.Task, Generation: original.Generation, Revision: original.Revision})
	}
	return backends, drained
}

func (d ingressDependencies) managedDependency(ctx context.Context, b ingress.BackendSpec) (string, uint64, bool, error) {
	if strings.HasPrefix(b.Task, deployment.ClusterAppPrefix) {
		return d.clusterAppDependency(ctx, b)
	}
	v, err := d.r.Engine().Read(ctx, false)
	if err != nil {
		return "", 0, false, err
	}
	p, err := d.r.controlPolicy.ProjectResources(v.State)
	if err != nil {
		return "", 0, false, err
	}
	g, ok := p.Goals[b.Task]
	if !ok || g.Goal.Kind != "task" || v.State.Object(b.Task).Generation != b.Generation {
		return "", 0, false, deployment.ErrInputs
	}
	var service deployment.ComposeService
	if json.Unmarshal(g.Goal.Config, &service) != nil {
		return "", 0, false, deployment.ErrInputs
	}
	for alias, a := range service.Networks {
		if b.Address.String() != a.IPv4 && b.Address.String() != a.IPv6 {
			continue
		}
		refKey := deployment.ResourceKey("network-ref", g.Goal.Tenant, g.Goal.App, alias+"/"+g.Goal.Node)
		if reference, exists := p.Goals[refKey]; exists {
			var ref deployment.NetworkReference
			if json.Unmarshal(reference.Goal.Config, &ref) != nil || !slices.Contains(g.Goal.Dependencies, deployment.ObjectRef{Key: refKey, Revision: v.State.Object(refKey).Revision, Generation: v.State.Object(refKey).Generation}) {
				return "", 0, false, deployment.ErrInputs
			}
			name := ref.Namespace()
			if b.Network != name {
				continue
			}
			if _, err := deployment.ReferenceBridge(d.r.controlPolicy.Cluster, ref, v.State.Objects("")); err != nil {
				return "", 0, false, err
			}
			if d.r.acceptsResourceOwner(ctx, g.Goal.Node, g.Goal.Owner) {
				return ref.Source.Key, ref.Source.Generation, true, nil
			}
			for key, row := range p.ManagedSources {
				if row.Tunnel != nil && d.r.acceptsResourceOwner(ctx, row.Network.Node, row.Network.Owner) && row.Tunnel.Network == b.Network && !row.Tunnel.Lifecycle.Drain {
					return key, v.State.Object(key).Generation, false, nil
				}
			}
			return "", 0, false, deployment.ErrInputs
		}
		if b.Network != g.Goal.Tenant+"/"+g.Goal.App+"/"+alias {
			continue
		}
		key := deployment.ResourceKey("bridge", g.Goal.Tenant, g.Goal.App, alias+"/"+g.Goal.Node)
		if d.r.acceptsResourceOwner(ctx, g.Goal.Node, g.Goal.Owner) {
			o := v.State.Object(key)
			if !o.Present || !slices.Contains(g.Goal.Dependencies, deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}) {
				return "", 0, false, deployment.ErrInputs
			}
			return key, o.Generation, true, nil
		}
		for key, t := range p.Goals {
			if t.Tunnel != nil && d.r.acceptsResourceOwner(ctx, t.Goal.Node, t.Goal.Owner) && t.Tunnel.Network == b.Network {
				return key, v.State.Object(key).Generation, false, nil
			}
		}
	}
	return "", 0, false, deployment.ErrInputs
}

// Select the exact committed dependency's local journal. The current Ingress
// permit remains the admission gate; an archived key only identifies the
// original Bridge/TUN pin and never authenticates a new command.
func (d ingressDependencies) dependencyOwner(ctx context.Context, key string, generation uint64) (*Runtime, error) {
	v, err := d.r.Engine().Read(ctx, false)
	if err != nil || !v.State.Object(key).Present || v.State.Object(key).Generation != generation {
		return nil, deployment.ErrInputs
	}
	p, err := d.r.controlPolicy.ProjectResources(v.State)
	if err != nil {
		return nil, err
	}
	var node string
	var keyOwner [32]byte
	if goal, ok := p.Goals[key]; ok && (goal.Bridge != nil || goal.Tunnel != nil) {
		node, keyOwner = goal.Goal.Node, goal.Goal.Owner
	} else if source, ok := p.ManagedSources[key]; ok && (source.Bridge != nil || source.Tunnel != nil) {
		node, keyOwner = source.Network.Node, source.Network.Owner
	}
	if !d.r.acceptsResourceOwner(ctx, node, keyOwner) {
		return nil, deployment.ErrInputs
	}
	owner, found := d.r.nativeOwner(keyOwner)
	if !found {
		return nil, deployment.ErrInputs
	}
	return owner, nil
}
