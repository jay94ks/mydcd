// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/moby/moby/client"
)

type containerRetirement struct {
	Schema                     uint8
	NativeID, Name, SpecDigest string
	StopSent                   bool `json:",omitempty"`
}

func (d *DockerDriver) RemoveCheckpoint(ctx context.Context, key string, op reconcile.Operation, receipt []byte, save func([]byte) error) (reconcile.Outcome, error) {
	if op.Kind != reconcile.Remove || op.Phase != reconcile.Dispatched && op.Phase != reconcile.RecoveryRequired {
		return reconcile.EffectUnknown, reconcile.ErrOperation
	}
	closed, err := d.Retire(ctx, key, op, receipt, save)
	if !closed || err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}

// Retire shares the ORIGINAL closure path between obsolete Apply and normal
// Remove. Missing unobserved creates stay Unknown; a positively observed native
// ID is retained before Stop/Remove. Apply compensation never claims readiness.
func (d *DockerDriver) Retire(ctx context.Context, key string, op reconcile.Operation, receipt []byte, save func([]byte) error) (bool, error) {
	s, id, err := d.parameters(key, op)
	valid := op.Kind == reconcile.Apply && op.Phase == reconcile.Retiring || op.Kind == reconcile.Remove && (op.Phase == reconcile.Dispatched || op.Phase == reconcile.RecoveryRequired)
	if err != nil || !valid || save == nil {
		return false, errors.Join(reconcile.ErrOperation, err)
	}
	var proof containerRetirement
	if len(receipt) > 0 {
		proof, err = schema.Decode[containerRetirement](receipt)
		decoded, decodeErr := hex.DecodeString(proof.NativeID)
		if err != nil || proof.Schema != 1 || decodeErr != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != proof.NativeID || proof.Name != id.Name || proof.SpecDigest != id.Labels["org.sfc.spec"] {
			return false, reconcile.ErrOperation
		}
	}
	lookup := proof.NativeID
	if lookup == "" && len(s.Volumes) == 0 && d.startCheckpoint != nil {
		c := d.startCheckpoint
		start, decodeErr := schema.Decode[containerStart](c.Data)
		if decodeErr != nil || start.Schema != 1 || !validStartNative(start.Native) || c.Operation == 0 || c.Target != op.Target || op.Kind == reconcile.Apply && c.Operation != op.ID || op.Kind == reconcile.Remove && c.Operation >= op.ID {
			return false, engine.ErrOwnership
		}
		// This exact native was positively observed and synced by the original
		// Start. Retain that fact even if it disappeared before retirement.
		proof = containerRetirement{Schema: 1, NativeID: start.Native, Name: id.Name, SpecDigest: id.Labels["org.sfc.spec"]}
		raw, _ := json.Marshal(proof)
		if err = save(raw); err != nil {
			return false, err
		}
		lookup = proof.NativeID
	}
	if lookup == "" {
		lookup = id.Name
	}
	got, err := d.Engine.API.ContainerInspect(ctx, lookup, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		if len(s.Volumes) > 0 {
			if err = d.retireVolumes(ctx, s, key, op); err != nil {
				return false, err
			}
			_, err = d.release(ctx, s, id, key, op.Target.Generation)
			return err == nil, err
		}
		if proof.NativeID == "" && op.Kind != reconcile.Remove {
			return false, nil
		}
		if proof.NativeID == "" && d.startCheckpoint == nil {
			// Legacy Applied records did not retain an immutable native ID.
			// Name absence alone would miss a renamed, still-running original.
			gone, goneErr := d.Engine.Gone(ctx, "container", key)
			if goneErr != nil || !gone {
				return false, errors.Join(reconcile.ErrPending, goneErr)
			}
		}
		_, err = d.release(ctx, s, id, key, op.Target.Generation)
		return err == nil, err
	}
	if err != nil {
		return false, err
	}
	if proof.NativeID != "" && got.Container.ID != proof.NativeID {
		return false, engine.ErrOwnership
	}
	lease, err := d.taskNetworkManager(s).InspectConsumer(ctx, s.Bridge, containerConsumer(id), s.BridgeGeneration)
	if err != nil {
		return false, err
	}
	inputs, err := d.inputLease(ctx, s, id, key, op.Target.Generation, "retire")
	if err != nil {
		return false, err
	}
	if !d.matchContainer(ctx, got.Container, s, id, lease, inputs.Files) {
		return false, engine.ErrOwnership
	}
	if proof.NativeID == "" {
		proof = containerRetirement{Schema: 1, NativeID: got.Container.ID, Name: id.Name, SpecDigest: id.Labels["org.sfc.spec"]}
		raw, _ := json.Marshal(proof)
		if err = save(raw); err != nil {
			return false, err
		}
	}
	if len(s.Volumes) > 0 {
		if err = d.retireVolumes(ctx, s, key, op); err != nil {
			return false, err
		}
		_, err = d.release(ctx, s, id, key, op.Target.Generation)
		return err == nil, err
	}
	if got.Container.State.Running {
		if proof.StopSent {
			return false, reconcile.ErrPending
		}
		policy, policyErr := engine.MatchStopPolicy(op.Target.Spec, got.Container.Config)
		if policyErr != nil {
			return false, policyErr
		}
		if err = engine.CheckStopBudget(ctx, policy); err != nil {
			return false, err
		}
		proof.StopSent = true
		raw, _ := json.Marshal(proof)
		if err = save(raw); err != nil {
			return false, err
		}
		if err = d.Engine.StopContainer(ctx, proof.NativeID, policy); err != nil {
			return false, err
		}
	}
	observed, err := d.Engine.API.ContainerInspect(ctx, proof.NativeID, client.ContainerInspectOptions{})
	if err != nil || !d.matchContainer(ctx, observed.Container, s, id, lease, inputs.Files) || observed.Container.ID != proof.NativeID {
		return false, errors.Join(reconcile.ErrPending, err)
	}
	if observed.Container.State.Running || observed.Container.State.Paused || observed.Container.State.Restarting {
		return false, reconcile.ErrPending
	}
	if _, err = d.Engine.API.ContainerRemove(ctx, proof.NativeID, client.ContainerRemoveOptions{}); err != nil {
		return false, err
	}
	if _, err = d.Engine.API.ContainerInspect(ctx, proof.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		return false, errors.Join(reconcile.ErrPending, err)
	}
	_, err = d.release(ctx, s, id, key, op.Target.Generation)
	return err == nil, err
}
