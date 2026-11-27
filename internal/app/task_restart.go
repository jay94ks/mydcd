// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

const taskRestartPrefix = "app/task-restart/"

type taskRestartReceipt struct {
	Schema         uint8
	Cluster, Owner [32]byte
	Control        checker.ContainerControl
}

func taskRestartKey(c checker.ContainerControl) string {
	return taskRestartPrefix + hex.EncodeToString(c.RequestDigest[:])
}
func (r *Runtime) readTaskRestartReceipt(initial checker.ContainerControl) (taskRestartReceipt, error) {
	p := taskRestartReceipt{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Control: initial}
	raw, err := r.reports.GetBounded(taskRestartKey(initial), 8192)
	if errors.Is(err, storage.ErrMissing) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	p, err = schema.Decode[taskRestartReceipt](raw)
	if err != nil || p.Schema != 1 || p.Cluster != r.controlPolicy.Cluster || p.Owner != r.Identity.Public || !initial.CanAdvanceTo(p.Control) {
		return p, checker.ErrContract
	}
	return p, nil
}
func (r *Runtime) saveTaskRestartReceipt(p taskRestartReceipt) error {
	if p.Schema != 1 || p.Cluster != r.controlPolicy.Cluster || p.Owner != r.Identity.Public || p.Control.Validate() != nil {
		return checker.ErrContract
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 8192 {
		return checker.ErrContract
	}
	// Write uses the same sync-on-commit private store as checker receipts. No
	// Raft RPC is attempted inside a sent-before-SDK save callback.
	return r.reports.Write(map[string][]byte{taskRestartKey(p.Control): raw})
}
func restartRequest(row control.TaskRestartRecord) control.TaskRestartPermitRequest {
	var change control.TaskRestartChange
	_ = json.Unmarshal(row.Origin.Change.Payload, &change)
	initial, _ := row.InitialControl()
	return control.TaskRestartPermitRequest{Tenant: row.Plan.Tenant, App: row.Plan.App, Operation: row.Operation(), Request: initial.RequestDigest, At: time.Now().Unix()}
}
func (r *Runtime) taskRestartPermit(ctx context.Context, row control.TaskRestartRecord) (bool, error) {
	raw, _ := json.Marshal(restartRequest(row))
	reply, err := r.appCall(ctx, "task-restart-permit", raw)
	if err != nil {
		return false, err
	}
	permit, err := schema.Decode[control.TaskRestartPermit](reply.Data)
	if err != nil || reply.Local || permit.Index == 0 || reply.CommandIndex < permit.Index {
		return false, sfcp.ErrAdmission
	}
	return permit.Allowed, nil
}
func (r *Runtime) taskRestartRead(key string, input []byte, v cluster.View) ([]byte, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.TaskRestartPermitRequest](input)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	if q.At != 0 && (!access.Recent(q.At, now, 30)) {
		return nil, sfcp.ErrAdmission
	}
	permit, err := r.controlPolicy.TaskRestartPermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(permit)
}

func (r *Runtime) advanceTaskRestarts(ctx context.Context, apps control.Apps) error {
	if r.workload == nil || r.reports == nil {
		return nil
	}
	r.checkerRunMu.Lock()
	defer r.checkerRunMu.Unlock()
	for _, row := range apps.TaskRestarts(r.Identity.Public) {
		// A pre-existing checker call/control settles before explicit user control;
		// new checker runs are held while this accepted request is pending.
		rows, err := r.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
		if err != nil {
			return err
		}
		busy := false
		for _, raw := range rows {
			p, err := schema.Decode[checkerObservation](raw)
			if err != nil || p.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil {
				return checker.ErrContract
			}
			if p.Task.Key == row.Plan.Container.Instance && (p.Checkpoint.Active != nil || p.Control != nil && !p.Control.Terminal()) {
				busy = true
				break
			}
		}
		if busy {
			continue
		}
		initial, err := row.InitialControl()
		if err != nil {
			return err
		}
		receipt, err := r.readTaskRestartReceipt(initial)
		if err != nil {
			return err
		}
		if row.Control != nil && !row.Control.CanAdvanceTo(receipt.Control) {
			return checker.ErrContract
		}
		if _, err = r.taskRestartPermit(ctx, row); err != nil {
			return err
		}
		// Persist identity before inspection/effects. Revocation is handled inside
		// the shared core so an unsent Volume start reservation is also canceled.
		if err = r.saveTaskRestartReceipt(receipt); err != nil {
			return err
		}
		runErr := r.workload.ControlContainerAction(ctx, receipt.Control, true, func(next checker.ContainerControl) error {
			if !receipt.Control.CanAdvanceTo(next) {
				return checker.ErrContract
			}
			updated := receipt
			updated.Control = next
			if err := r.saveTaskRestartReceipt(updated); err != nil {
				return err
			}
			receipt = updated
			return nil
		}, func(callctx context.Context) error {
			ok, err := r.taskRestartPermit(callctx, row)
			if err != nil {
				return err
			}
			if !ok {
				return sfcp.ErrAdmission
			}
			return nil
		})
		if row.Control == nil || *row.Control != receipt.Control {
			current, err := r.Engine().Read(ctx, false)
			if err != nil {
				return err
			}
			latest, err := r.controlPolicy.ReadApps(current.State)
			if err != nil {
				return err
			}
			q := restartRequest(row)
			saved, ok := latest.TaskRestart(q.Tenant, q.App, q.Operation)
			if !ok {
				return checker.ErrContract
			}
			if saved.Control == nil || *saved.Control != receipt.Control {
				report := control.TaskRestartReport{Schema: 1, Kind: "task-restart", Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Tenant: q.Tenant, App: q.App, Operation: q.Operation, Expected: saved.Revision, RootRevision: current.State.Object(control.AppsKey).Revision, Epoch: current.State.ModuleEpoch(), At: uint64(time.Now().Unix()), Control: receipt.Control}
				report.Signature = ed25519.Sign(r.commandIdentity().Private, control.TaskRestartReportBytes(report))
				raw, _ := json.Marshal(report)
				reply, err := r.appCall(ctx, "task-restart-report", raw)
				if err != nil {
					return err
				}
				if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
					return reconcile.ErrPending
				}
			}
		}
		if runErr != nil && !receipt.Control.Terminal() && !errors.Is(runErr, reconcile.ErrPending) {
			return runErr
		}
	}
	return nil
}
