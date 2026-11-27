// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func (r *Runtime) retirementProgress(ctx context.Context, v cluster.View, app control.AppView, retirement deployment.RetirementView, action, key string, detail control.AppRetirementProgress) error {
	report := r.newAppProgress(v, app, action, key, nil)
	report.Operation = retirement.ID
	report.Retire = &detail
	return r.sendAppProgress(ctx, report)
}
func projectionClaimRef(claim deployment.Claim) (workload.InputRef, error) {
	var goal deployment.GoalCommand
	if claim.Step.Kind != "inputs" || json.Unmarshal([]byte(claim.Command.Value), &goal) != nil || !strings.HasPrefix(claim.Native, "projection/") {
		return workload.InputRef{}, deployment.ErrInputs
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(claim.Native, "projection/"))
	if err != nil || len(raw) != 32 {
		return workload.InputRef{}, deployment.ErrInputs
	}
	ref := workload.InputRef{Key: claim.Step.Key}
	copy(ref.Binding[:], raw)
	for _, dependency := range goal.Dependencies {
		if strings.HasPrefix(dependency.Key, "workload/task/") {
			if ref.Generation != 0 {
				return ref, deployment.ErrInputs
			}
			ref.Generation = dependency.Generation
		}
	}
	if ref.Generation == 0 {
		return ref, deployment.ErrInputs
	}
	return ref, nil
}

func (r *Runtime) reconcileAppRetirements(ctx context.Context, v cluster.View, apps control.Apps) (bool, error) {
	for _, app := range apps.Records() {
		i, ok := apps.Inventory(app.Tenant, app.App)
		if !ok {
			return false, deployment.ErrInputs
		}
		for _, claim := range i.Claims() {
			if claim.Removed && claim.Step.Kind == "inputs" && claim.Step.Owner == r.Identity.Public {
				ref, err := projectionClaimRef(claim)
				if err != nil {
					return false, err
				}
				store, err := r.appProjectionStore()
				if err != nil {
					return false, err
				}
				if err = store.ForgetRetired(ref, apps.Bindings(), i); err != nil {
					return false, err
				}
			}
		}
		retirement, ok := i.Retirement()
		if !ok {
			continue
		}
		allClosed := true
		for _, target := range retirement.Targets {
			if target.Closed {
				if c := target.Original; c.Step.Kind == "task" {
					allocations, err := apps.NetworkRetirementAllocations(app.Tenant, app.App, c.Step.Key)
					if err != nil {
						return false, err
					}
					if len(allocations) != 0 {
						allClosed = false
						if c.Step.Owner == r.Identity.Public {
							changed, err := r.retireNetworkAddresses(ctx, v, apps, app, retirement, c)
							if errors.Is(err, reconcile.ErrPending) {
								continue
							}
							if changed || err != nil {
								return changed, err
							}
						}
					}
				}
				continue
			}
			allClosed = false
			c := target.Original
			metadata := c.Step.Kind == "delivery" && c.Step.Owner == ([32]byte{}) && r.Engine().IsLeader()
			if !metadata && c.Step.Owner != r.Identity.Public || !i.CanRetire(c.Step.Key) {
				continue
			}
			if c.Step.Retain {
				if c.Step.Kind != "volume" || r.activations == nil {
					continue
				}
				registry, err := r.controlPolicy.Volumes(v.State)
				if err != nil {
					return false, err
				}
				id := c.Step.Key[strings.LastIndex(c.Step.Key, "/")+1:]
				ready, ok := registry.Native(app.Tenant, app.App, id)
				if !ok {
					return false, volumes.ErrActivation
				}
				volume, ok := registry.Volume(ready.Spec.Scope)
				if !ok || len(volume.Consumers()) != 0 {
					continue
				}
				if err = r.activations.RetainReady(ctx, volumes.NativeKey(ready.Spec), ready.Spec.Scope, ready.Owner); err != nil {
					return false, err
				}
				proof := deployment.RetainReceipt{Cluster: r.controlPolicy.Cluster, Retirement: retirement.ID, StopRevision: retirement.Revision, Key: c.Step.Key, Native: ready.Owner.Native, Owner: r.Identity.Public, Command: state.Digest(c.Command), Generation: c.Result.Generation, Revision: c.Result.Revision, Released: true, Stopped: true, Retained: true, Fenced: true}
				proof.Signature = ed25519.Sign(r.Identity.Private, deployment.RetainReceiptBytes(proof))
				return true, r.retirementProgress(ctx, v, app, retirement, "retire-retain", c.Step.Key, control.AppRetirementProgress{Retained: &proof})
			}
			if c.Step.Kind == "bridge" || c.Step.Kind == "network-ref" {
				changed, err := r.retireNetworkAddresses(ctx, v, apps, app, retirement, c)
				if errors.Is(err, reconcile.ErrPending) {
					continue
				}
				if changed || err != nil {
					return changed, err
				}
			}
			for _, phase := range []string{"drain", "proof", "delete"} {
				m, exists := i.Removal(c.Step.Key, phase)
				if !exists {
					continue
				}
				if m.Result != nil {
					if m.Result.Code != state.Applied {
						return false, fmt.Errorf("original retirement %s %s rejected: %d", c.Step.Key, phase, m.Result.Code)
					}
					continue
				}
				if m.Journal.Pending == nil {
					return false, deployment.ErrInputs
				}
				detail := control.AppRetirementProgress{Phase: phase}
				if m.Dispatchable() && m.Journal.Pending.Phase == reconcile.RecoveryRequired {
					// A late commit wins over an unused explicit replay grant.
					// Missing still means Unknown, never evidence of nonexecution.
					raw, err := state.EncodeCommand(m.Command)
					if err != nil {
						return false, err
					}
					reply, err := r.appCall(ctx, "app-result", raw)
					if err != nil {
						return false, err
					}
					found, err := schema.Decode[control.AppResult](reply.Data)
					if err != nil {
						return false, err
					}
					if found.Found && found.Result != nil {
						return true, r.retirementProgress(ctx, v, app, retirement, "retire-collect", c.Step.Key, detail)
					}
				}
				if m.Dispatchable() {
					if phase == "drain" && c.Step.Kind == "task" {
						waiting, err := r.reconcileTaskShutdown(ctx, v, apps, retirement, c)
						if waiting || err != nil {
							return waiting, err
						}
					}
					if err := r.retirementProgress(ctx, v, app, retirement, "retire-send", c.Step.Key, detail); err != nil {
						return true, err
					}
					raw, err := state.EncodeCommand(m.Command)
					if err != nil {
						return true, err
					}
					reply, err := r.appCall(ctx, "app-command", raw)
					if err != nil {
						// Preserve the first dispatch failure in process diagnostics.
						// A later successful result query may clear moduleError while
						// this exact original remains uncertain. Never log its body.
						_, leader := r.Engine().Leader()
						log.Printf("original app retirement dispatch failed: key=%s phase=%s request=%s leader=%s error=%v", c.Step.Key, phase, m.Command.RequestID, leader, err)
						return true, err
					}
					if reply.Committed == nil {
						return true, errors.New("original retirement command outcome unknown")
					}
					return true, nil
				}
				raw, err := state.EncodeCommand(m.Command)
				if err != nil {
					return false, err
				}
				reply, err := r.appCall(ctx, "app-result", raw)
				if err != nil {
					return false, err
				}
				found, err := schema.Decode[control.AppResult](reply.Data)
				if err != nil {
					return false, err
				}
				if found.Found && found.Result != nil {
					return true, r.retirementProgress(ctx, v, app, retirement, "retire-collect", c.Step.Key, detail)
				}
				if m.Journal.Pending.Phase == reconcile.Dispatched {
					return true, r.retirementProgress(ctx, v, app, retirement, "retire-unknown", c.Step.Key, detail)
				}
				break
			}
			if target.Drain == nil || target.Drain.Result == nil || target.Drain.Result.Code != state.Applied || target.Proof != nil {
				continue
			}
			goneDetail := control.AppRetirementProgress{}
			if c.Step.Kind == "network-ref" {
				if err := r.releaseAppNetworkReference(ctx, c); err != nil {
					return false, err
				}
			} else if c.Step.Kind == "dns" {
				changed, proof, err := r.retireAppDNS(ctx, v, apps, app, retirement, target)
				if changed || err != nil {
					return changed, err
				}
				goneDetail.DNS = proof
			} else if c.Step.Kind == "task" {
				if r.workload == nil {
					continue
				}
				row, err := r.workload.View(c.Step.Key)
				if errors.Is(err, storage.ErrMissing) {
					// The Task's command committed but this owner never created
					// its container (for example the image's process was refused
					// before the first native effect). Journal the retirement
					// from nothing so Gone can prove there is no container.
					row, err = reconcile.Record{Capacity: 1}, nil
				}
				if err != nil {
					return false, err
				}
				if err = r.workload.Desired(c.Step.Key, target.Drain.Result.Revision, c.Result.Generation, nil, row.Capacity); err == nil {
					err = r.workload.Step(ctx, c.Step.Key)
				}
				if err != nil {
					return false, err
				}
				if gone, err := r.workload.Gone(ctx, c.Step.Key, target.Drain.Result.Revision, c.Result.Generation); err != nil || !gone {
					return false, errors.Join(deployment.ErrInputs, err)
				}
				ref := deployment.ObjectRef{Key: c.Step.Key, Generation: c.Result.Generation, Revision: c.Result.Revision}
				if b, exists := apps.Binding(ref); exists {
					observation, proof, err := r.CollectAppTaskClosure(ctx, control.AppBindingRequest{Task: ref, Digest: b.Digest()})
					if err != nil {
						return false, err
					}
					report := r.newAppProgress(v, app, "release-inputs", c.Step.Key, &observation)
					report.Release = &control.AppBindingRelease{Digest: b.Digest(), Proof: proof}
					return true, r.sendAppProgress(ctx, report)
				}
			} else if c.Step.Kind == "inputs" {
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
					if err = store.Drain(ctx, ref, target.Drain.Result.Revision); err != nil {
						return false, err
					}
					gone, err = store.Gone(ref)
				}
				if err != nil || !gone {
					return false, errors.Join(deployment.ErrInputs, err)
				}
			} else if c.Step.Kind == "ingress" {
				if r.ingress == nil {
					continue
				}
				o := v.State.Object(c.Step.Key)
				spec, err := deployment.ResolveIngress(r.controlPolicy.Cluster, c.Step.Key, o, v.State.Objects(""))
				if err != nil {
					return false, err
				}
				if err = r.ingress.Reconcile(ctx, c.Step.Key, o.Revision, o.Generation, &spec); err != nil {
					return false, err
				}
				observed, err := r.ingress.Observe(c.Step.Key)
				if err != nil || !observed.Gone || observed.Requests != 0 {
					return false, errors.Join(deployment.ErrInputs, err)
				}
			} else if c.Step.Kind == "tunnel" {
				if r.tunnel == nil {
					continue
				}
				spec, err := deployment.ResolveTunnel(r.controlPolicy.Cluster, c.Step.Key, state.Object{Present: true, Value: c.Command.Value, Generation: c.Result.Generation, Revision: c.Result.Revision}, v.State.Objects(""))
				if err != nil {
					return false, err
				}
				if gone, err := r.tunnel.Drain(ctx, c.Step.Key, target.Drain.Result.Revision, c.Result.Generation, spec); err != nil || !gone {
					return false, errors.Join(deployment.ErrInputs, err)
				}
			} else if c.Step.Kind == "bridge" {
				if r.network == nil {
					continue
				}
				original, err := deployment.DecodeGoalResources(r.controlPolicy.Cluster, c.Step.Key, state.Object{Present: true, Value: c.Command.Value, Generation: c.Result.Generation, Revision: c.Result.Revision})
				if err != nil || original.Bridge == nil {
					return false, deployment.ErrInputs
				}
				row, err := r.network.View(c.Step.Key)
				if err != nil {
					return false, err
				}
				if err = r.network.Desired(c.Step.Key, target.Drain.Result.Revision, c.Result.Generation, nil, row.Capacity); err == nil {
					err = r.network.Step(ctx, c.Step.Key)
				}
				if err != nil {
					return false, err
				}
				if gone, err := r.network.Gone(ctx, c.Step.Key, target.Drain.Result.Revision, c.Result.Generation, *original.Bridge); err != nil || !gone {
					return false, errors.Join(deployment.ErrInputs, err)
				}
				goneDetail.Network, err = r.appBridgeNetworkClosure(v, apps, c)
				if err != nil {
					return false, err
				}
			} else {
				continue
			}
			signature := ed25519.Sign(r.Identity.Private, schema.GoneBytes(r.controlPolicy.Cluster, c.Step.Key, c.Result.Generation, []byte(target.Drain.Command.Value)))
			goneDetail.Gone = signature
			return true, r.retirementProgress(ctx, v, app, retirement, "retire-gone", c.Step.Key, goneDetail)
		}
		if allClosed && r.Engine().IsLeader() {
			return true, r.retirementProgress(ctx, v, app, retirement, "retire-finish", "", control.AppRetirementProgress{})
		}
	}
	return false, nil
}
