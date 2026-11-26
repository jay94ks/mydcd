// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/desired"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

func (r *Runtime) reconcileManagedNetworkBridges(ctx context.Context, v cluster.View, projection control.ResourceProjection) error {
	for _, row := range projection.ManagedSources {
		if row.Closed == nil && row.Tunnel != nil && row.Network.Owner == r.Identity.Public && r.tunnel == nil {
			return errors.New("committed managed TUN requires enabled local tunnel module")
		}
	}
	if r.network == nil {
		for _, row := range projection.ManagedSources {
			if row.Closed == nil && row.Network.Owner == r.Identity.Public {
				return errors.New("managed network requires enabled local network module")
			}
		}
		return r.reconcileClosedManagedTunnels(ctx, v, projection)
	}
	keys := map[string]bool{}
	for key, row := range projection.ManagedSources {
		if row.Bridge != nil && row.Network.Owner == r.Identity.Public {
			keys[key] = true
		}
	}
	for _, key := range r.network.Keys() {
		if strings.HasPrefix(key, tenancy.ManagedNetworkSourcePrefix) {
			keys[key] = true
		}
	}
	for _, key := range desired.Sorted(keys) {
		row, exists := projection.ManagedSources[key]
		if !exists || row.Bridge == nil || row.Network.Owner != r.Identity.Public {
			return fmt.Errorf("local managed bridge %s has no exact committed source", key)
		}
		o := v.State.Object(key)
		spec := *row.Bridge
		spec.Lifecycle = schema.Lifecycle{}
		record, err := r.network.View(key)
		known := slices.Contains(r.network.Keys(), key)
		if known && err != nil {
			return err
		}
		if row.Closed != nil {
			if !known || o.Present || record.State.Pending != nil || record.State.Applied.Present || record.State.Desired.Present || len(record.Consumers) != 0 || record.State.GenerationFloor != o.Generation {
				return errors.New("fenced managed Bridge lost its original terminal journal")
			}
			if err := r.network.Desired(key, o.Revision, o.Generation, nil, record.Capacity); err != nil {
				return err
			}
			gone, err := r.network.Gone(ctx, key, o.Revision, o.Generation, spec)
			if err != nil || !gone {
				return errors.Join(err, errors.New("fenced managed Bridge native is not Gone"))
			}
			continue
		}
		capacity := record.Capacity
		if !row.Network.Draining && (!known || record.State.Pending == nil && !record.State.Applied.Present || record.State.Pending != nil && record.State.Pending.Phase == reconcile.Prepared) {
			request, _ := json.Marshal(control.NativeRequest{Source: deployment.ObjectRef{Key: key, Revision: o.Revision, Generation: o.Generation}})
			reply, err := r.appCall(ctx, "app-native-permit", request)
			if err != nil {
				return err
			}
			permit, err := schema.Decode[control.NativePermit](reply.Data)
			raw, _ := json.Marshal(spec)
			if err != nil || permit.Source.Key != key || permit.Source.Generation != o.Generation || permit.Source.Revision != o.Revision || permit.Owner != r.Identity.Public || permit.Kind != "bridge" || permit.Spec != sha256.Sum256(raw) || permit.MaxConsumers < 1 {
				return errors.New("managed bridge permit/source mismatch")
			}
			capacity = permit.MaxConsumers
		} else if !row.Network.Draining {
			// Applied Bridges also reflect current policy shrink. This local
			// view is diagnostic/staging input; every fresh Acquire separately
			// obtains a current quorum permit and syncs its capacity with the pin.
			global, gok := projection.Resources.Quotas.Limit("", row.Network.Node)
			scoped, sok := projection.Resources.Quotas.Limit(row.Network.Tenant, row.Network.Node)
			if gok && sok && global.Owner == r.Identity.Public && scoped.Owner == r.Identity.Public && min(global.MaxConsumers, scoped.MaxConsumers) > 0 {
				capacity = min(global.MaxConsumers, scoped.MaxConsumers)
			}
		}
		if capacity < 1 {
			if row.Network.Draining && !known {
				// There was no local operation to stop; the shared reservation is
				// retained until a separate terminal management proof is available.
				continue
			}
			return errors.New("managed bridge needs committed positive consumer policy")
		}
		active := &spec
		if row.Network.Draining {
			active = nil
		}
		if err = r.network.Desired(key, o.Revision, o.Generation, active, capacity); err != nil {
			return err
		}
		if err = r.network.Step(ctx, key); err != nil {
			if row.Network.Draining && errors.Is(err, reconcile.ErrPending) {
				continue // Original pins must be returned by their own cleanup.
			}
			return err
		}
	}
	return r.reconcileClosedManagedTunnels(ctx, v, projection)
}

// Closed sources retain their original terminal journal after membership
// removal. Excluding them from packet topology alone does not settle the
// local tombstone revision or prove that the original kernel object is gone.
func (r *Runtime) reconcileClosedManagedTunnels(ctx context.Context, v cluster.View, projection control.ResourceProjection) error {
	if r.tunnel == nil {
		return nil
	}
	for _, key := range desired.Sorted(projection.ManagedSources) {
		row := projection.ManagedSources[key]
		if row.Closed == nil || row.Tunnel == nil || row.Network.Owner != r.Identity.Public {
			continue
		}
		object := v.State.Object(key)
		record, err := r.tunnel.manager.View(key)
		if err != nil || object.Present || record.State.Pending != nil || record.State.Applied.Present || record.State.Desired.Present || len(record.Consumers) != 0 || record.State.GenerationFloor != object.Generation {
			return errors.Join(err, fmt.Errorf("fenced managed TUN %s lost its original terminal journal", key))
		}
		if err = r.tunnel.manager.Desired(key, object.Revision, object.Generation, nil, record.Capacity); err != nil {
			return err
		}
		gone, err := r.tunnel.manager.Gone(ctx, key, object.Revision, object.Generation, *row.Tunnel)
		if err != nil || !gone {
			return errors.Join(err, fmt.Errorf("fenced managed TUN %s native is not Gone", key))
		}
	}
	return nil
}

func (r *Runtime) observeManagedNetwork(ctx context.Context, key string, v cluster.View, projection control.ResourceProjection, source control.ManagedNetworkSource) (json.RawMessage, error) {
	if source.Network.Owner != r.Identity.Public {
		return nil, deployment.ErrInputs
	}
	o := v.State.Object(key)
	observation := ModuleObservation{Schema: 1, Key: key, Local: v.Local, Revision: o.Revision, Generation: o.Generation}
	if source.Closed != nil {
		// This is the already committed original closure, not a newly signed
		// observation or a permission to recreate the tombstoned source.
		observation.Retirement, _ = json.Marshal(source.Closed)
		var record reconcile.Record
		var err error
		if source.Bridge != nil && r.network != nil {
			record, err = r.network.View(key)
		} else if source.Tunnel != nil && r.tunnel != nil {
			record, err = r.tunnel.manager.View(key)
		} else {
			err = errors.New("closed managed network local module unavailable")
		}
		if err != nil {
			observation.Error = err.Error()
		} else {
			observation.Journal = compact(record)
		}
		return r.managedObservation(observation)
	}
	if source.Network.Draining {
		endpoints := control.PendingNetworkEndpoints(projection, source.Network)
		observation.NetworkClosure = &control.NetworkClosureStatus{State: "pending", PendingEndpoints: &endpoints}
		if source.Bridge != nil && r.network != nil {
			if gone, err := r.network.Gone(ctx, key, o.Revision, o.Generation, *source.Bridge); err == nil {
				observation.NetworkClosure.NativeGone = &gone
			}
		}
		proof, err := r.managedNetworkClosure(ctx, v, projection, source.Network)
		if err != nil {
			observation.Error = err.Error()
		} else if proof != nil {
			observation.Retirement, _ = json.Marshal(proof)
		}
		if source.Bridge != nil && r.network != nil {
			if record, err := r.network.View(key); err == nil {
				observation.Journal = compact(record)
			}
		} else if source.Tunnel != nil && r.tunnel != nil {
			if record, err := r.tunnel.manager.View(key); err == nil {
				observation.Journal = compact(record)
			}
		}
		if observation.Journal.GenerationFloor == o.Generation {
			pins := uint64(max(0, observation.Journal.Consumers))
			observation.NetworkClosure.PendingPins = &pins
		}
		if proof != nil && err == nil {
			observation.NetworkClosure = &control.NetworkClosureStatus{State: "closed", Closure: proof, NativeGone: &proof.NativeGone, PendingEndpoints: &proof.PendingEndpoints, PendingFlows: &proof.PendingFlows, PendingPins: &proof.PendingPins}
		}
		// Ready continues to mean active serving. Retirement is a separate
		// positive closure fact, never a fresh native use permission.
		return r.managedObservation(observation)
	}
	var record reconcile.Record
	var err error
	if source.Bridge != nil && r.network != nil {
		record, err = r.network.View(key)
		if err == nil {
			observation.NativeID, err = r.network.Inspect(ctx, key)
		}
	} else if source.Tunnel != nil && r.tunnel != nil {
		record, err = r.tunnel.manager.View(key)
		if err == nil {
			observation.NativeID, err = r.tunnel.manager.Inspect(ctx, key)
		}
		if err == nil {
			err = r.tunnel.Ready(key)
		}
		status, _ := r.tunnel.Observe(key)
		observation.Tunnel = &status
	} else {
		return nil, errors.New("managed native network module unavailable")
	}
	observation.Journal = compact(record)
	observation.Ready = err == nil && !source.Network.Draining && record.State.Pending == nil && record.State.Applied.Present && record.State.Applied.Generation == o.Generation && record.State.Desired.Revision == o.Revision
	if err != nil {
		observation.Error = err.Error()
	}
	return r.managedObservation(observation)
}

func networkReferenceConsumer(command string) string {
	digest := sha256.Sum256([]byte(command))
	return fmt.Sprintf("network-reference/%x", digest[:])
}

// Independent reference facts use the same observation target as Bridge/TUN facts.
// Publishing one must not starve later references or Ingress on a long pass.
// The caller reads through the exact returned command floor before continuing.
func (r *Runtime) reconcileAppNetworkReferences(ctx context.Context, v cluster.View, apps control.Apps) (uint64, error) {
	var observedFloor uint64
	for _, app := range apps.Records() {
		var wave deployment.RetirementView
		retiring := false
		if inventory, exists := apps.Inventory(app.Tenant, app.App); exists {
			wave, retiring = inventory.Retirement()
			if retiring && !wave.KeepExecution {
				continue
			}
		}
		e, ok := apps.Execution(app.Tenant, app.App)
		if !ok || e.Status() == "Paused" || e.Status() == "Stopping" || e.Status() == "Closed" || e.Status() == "Failed" {
			continue
		}
		for _, step := range e.Steps() {
			if step.Kind != "network-ref" || step.Owner != r.Identity.Public {
				continue
			}
			stage, _ := e.Stage(step.Key)
			if stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied {
				continue
			}
			if retiring && (!wave.Preserves(step.Key) || !stage.Noop) {
				continue
			}
			native, err := r.acquireAppNetworkReference(ctx, v, stage, retiring)
			if err != nil {
				return 0, err
			}
			if r.freshAppObservation(stage, native, false) {
				continue
			}
			o, err := r.appObservation(app, stage, native, false)
			if err != nil {
				return 0, err
			}
			index, err := r.sendAppProgressAt(ctx, r.newAppProgress(v, app, "observe", step.Key, &o))
			if err != nil {
				return 0, err
			}
			observedFloor = max(observedFloor, index)
		}
	}
	return observedFloor, nil
}

func (r *Runtime) acquireAppNetworkReference(ctx context.Context, v cluster.View, stage deployment.StageRecord, existingOnly bool) (string, error) {
	if stage.Command == nil || stage.Result == nil || r.network == nil {
		return "", deployment.ErrInputs
	}
	var goal deployment.GoalCommand
	var ref deployment.NetworkReference
	if json.Unmarshal([]byte(stage.Command.Value), &goal) != nil || json.Unmarshal(goal.Config, &ref) != nil || goal.Kind != "network-ref" || ref.Owner != r.Identity.Public || !ref.RetainSource {
		return "", deployment.ErrInputs
	}
	consumer := networkReferenceConsumer(stage.Command.Value)
	if native, held, err := r.inspectAppNetworkReference(ctx, ref, consumer, v.State.Objects("")); err != nil || held {
		return native, err
	}
	if existingOnly || stage.Observation != nil && (stage.Observation.Applied || stage.Observation.Native != "") {
		// An already observed native borrow cannot be recreated from missing
		// original pins, even if a current new-use permission would succeed.
		return "", reconcile.ErrLease
	}
	source := deployment.ObjectRef{Key: stage.Key, Generation: stage.Result.Generation, Revision: stage.Result.Revision}
	request, _ := json.Marshal(control.NativeRequest{Source: source})
	reply, err := r.appCall(ctx, "app-native-permit", request)
	if err != nil {
		return "", err
	}
	permit, err := schema.Decode[control.NativePermit](reply.Data)
	if err != nil || permit.Source != source || permit.Owner != r.Identity.Public || permit.Kind != "network-ref" || permit.Spec != sha256.Sum256(goal.Config) {
		return "", deployment.ErrInputs
	}
	bridge, err := r.network.Acquire(ctx, ref.Source.Key, consumer, ref.Source.Generation)
	if err != nil {
		return "", err
	}
	if bridge.Spec.Network != ref.Network || bridge.Spec.Owner != r.owner {
		return "", deployment.ErrInputs
	}
	if tun, exists := ref.LocalTunnel(); exists {
		if r.tunnel == nil {
			return "", errTunnelPending
		}
		if _, err = r.tunnel.manager.BorrowDependency(ctx, tun.Key, consumer, tun.Generation); err != nil {
			return "", err
		}
		if err = r.tunnel.Ready(tun.Key); err != nil {
			return "", err
		}
	}
	return "borrow/" + bridge.NetworkID + "/" + consumer, nil
}

// The original reference's dependents have positive closure before this is
// called. Only its own durable consumer pins are returned; Desired and the
// management source's native generation are never changed by app down.
func (r *Runtime) releaseAppNetworkReference(ctx context.Context, claim deployment.Claim) error {
	var goal deployment.GoalCommand
	var ref deployment.NetworkReference
	if r.network == nil || json.Unmarshal([]byte(claim.Command.Value), &goal) != nil || json.Unmarshal(goal.Config, &ref) != nil || goal.Kind != "network-ref" || ref.Owner != r.Identity.Public || !ref.RetainSource {
		return deployment.ErrInputs
	}
	consumer := networkReferenceConsumer(claim.Command.Value)
	if tun, exists := ref.LocalTunnel(); exists {
		if r.tunnel == nil {
			return errTunnelPending
		}
		record, err := r.tunnel.manager.View(tun.Key)
		if err != nil {
			if !errors.Is(err, storage.ErrMissing) || claim.Native != "" {
				return err
			}
		}
		if pin, exists := record.Consumers[consumer]; exists {
			if pin.Generation != tun.Generation {
				return reconcile.ErrLease
			}
			if err = r.tunnel.manager.Return(network.TunnelLease{Key: tun.Key, Consumer: consumer, Pin: pin}); err != nil {
				return err
			}
		}
	}
	err := r.network.ReturnConsumer(ref.Source.Key, consumer, ref.Source.Generation)
	if errors.Is(err, storage.ErrMissing) && claim.Native == "" {
		return nil
	}
	return err
}
