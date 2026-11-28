// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

// A surge (devel/design/zero-downtime-apply.md) starts a Task's new
// generation next to its original: the original's journal record is parked
// under workload.ParkedKey first, so the new generation starts from its own
// record and the original keeps running until the wave stops it.

// parkSurgedOriginal parks the original generation of a surged stage before
// its new generation is desired. Nothing is parked for an ordinary stage,
// for an original this server never created, or once the main record moved
// on.
func (r *Runtime) parkSurgedOriginal(stage deployment.StageRecord) error {
	if stage.Command == nil || !stage.Command.Renew || stage.Previous == nil || stage.Previous.Removed {
		return nil
	}
	key, generation := stage.Key, stage.Previous.Result.Generation
	if _, err := r.workload.Parked(key, generation); err == nil || !errors.Is(err, storage.ErrMissing) {
		return err
	}
	row, err := r.workload.View(key)
	if errors.Is(err, storage.ErrMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	if !row.State.Applied.Present || row.State.Applied.Generation != generation {
		return nil
	}
	return r.workload.Park(key, generation)
}

// parkedOriginal reports whether this server holds the parked original
// generation of key.
func (r *Runtime) parkedOriginal(key string, generation uint64) (bool, error) {
	if r.workload == nil {
		return false, nil
	}
	_, err := r.workload.Parked(key, generation)
	if errors.Is(err, storage.ErrMissing) {
		return false, nil
	}
	return err == nil, err
}

// retireSuperseded stops the original of a surge wave target on this
// server. Its new generation already holds the object, so only the original's
// native goes: the parked container stops, its bindings close, and the owner
// signs Gone over the drain value the inventory names.
func (r *Runtime) retireSuperseded(ctx context.Context, v cluster.View, apps control.Apps, app control.AppView, retirement deployment.RetirementView, i deployment.Inventory, c deployment.Claim) (bool, error) {
	key, generation := c.Step.Key, c.Result.Generation
	value, ok := i.SupersededDrain(key)
	if !ok {
		return false, deployment.ErrInputs
	}
	switch c.Step.Kind {
	case "task":
		if r.workload == nil {
			return false, nil
		}
		parked, err := r.parkedOriginal(key, generation)
		if err != nil {
			return false, err
		}
		if parked {
			if err = r.workload.RetireParked(ctx, key, v.State.Object(key).Revision, generation); err != nil {
				return false, err
			}
		}
		if gone, err := r.supersededGone(ctx, key, generation); err != nil || !gone {
			return false, errors.Join(deployment.ErrInputs, err)
		}
		// Without a parked record this server never created the original
		// (or never started it): nothing of that generation can run.
		ref := deployment.ObjectRef{Key: key, Generation: generation, Revision: c.Result.Revision}
		if b, exists := apps.Binding(ref); exists {
			observation, proof, err := r.CollectAppTaskClosure(ctx, control.AppBindingRequest{Task: ref, Digest: b.Digest()})
			if err != nil {
				return false, err
			}
			report := r.newAppProgress(v, app, "release-inputs", key, &observation)
			report.Release = &control.AppBindingRelease{Digest: b.Digest(), Proof: proof}
			return true, r.sendAppProgress(ctx, report)
		}
	case "inputs":
		ref, err := projectionClaimRef(c)
		if err != nil {
			return false, err
		}
		store, err := r.appProjectionStore()
		if err != nil {
			return false, err
		}
		gone, err := store.Gone(ref)
		if err != nil {
			return false, err
		}
		if !gone {
			if err = store.Drain(ctx, ref, v.State.Object(key).Revision); err != nil {
				return false, err
			}
			gone, err = store.Gone(ref)
		}
		if err != nil || !gone {
			return false, errors.Join(deployment.ErrInputs, err)
		}
	default:
		return false, deployment.ErrInputs
	}
	signature := ed25519.Sign(r.Identity.Private, schema.GoneBytes(r.controlPolicy.Cluster, key, generation, value))
	return true, r.retirementProgress(ctx, v, app, retirement, "retire-gone", key, control.AppRetirementProgress{Gone: signature})
}

// supersededGone reports whether the surged original generation of key is
// gone on this server: its parked record is stopped and absent, or there was
// none because this server never ran it.
func (r *Runtime) supersededGone(ctx context.Context, key string, generation uint64) (bool, error) {
	parked, err := r.parkedOriginal(key, generation)
	if err != nil || !parked {
		return !parked && err == nil, err
	}
	return r.workload.ParkedGone(ctx, key, generation)
}
