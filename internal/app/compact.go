// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/maintenance"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

var errCompactCAS = errors.New("original compaction progress view changed")

const compactReceiptPrefix = "maintenance/compact/"

type compactReceipt struct {
	Schema                 uint8
	Cluster, Owner, Target [32]byte
	Operation              string
	Dispatch               *maintenance.CompactDispatch `json:",omitempty"`
	Result                 *maintenance.CompactResult   `json:",omitempty"`
	Code                   string                       `json:",omitempty"`
}

func compactReceiptKey(id string) string {
	hash := sha256.Sum256([]byte(id))
	return compactReceiptPrefix + hex.EncodeToString(hash[:])
}
func (r *Runtime) loadCompactReceipt(work control.CompactWork) (compactReceipt, error) {
	out := compactReceipt{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Target: work.Target, Operation: work.Operation}
	raw, err := r.reports.GetBounded(compactReceiptKey(work.Operation), 16<<10)
	if errors.Is(err, storage.ErrMissing) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if _, err = schema.Decode[compactReceipt](raw); err != nil {
		return out, err
	}
	if json.Unmarshal(raw, &out) != nil || out.Schema != 1 || out.Cluster != r.controlPolicy.Cluster || out.Owner != r.Identity.Public || out.Operation != work.Operation || out.Target != work.Target || out.Dispatch != nil && (out.Dispatch.Validate() != nil || out.Dispatch.Operation != work.Operation || out.Dispatch.Options != work.Options) || out.Result != nil && (out.Result.Validate() != nil || out.Dispatch == nil || out.Result.Dispatch != *out.Dispatch) {
		return out, maintenance.ErrCompact
	}
	return out, nil
}
func (r *Runtime) saveCompactReceipt(receipt compactReceipt) error {
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw) > 16<<10 {
		return maintenance.ErrCompact
	}
	return r.reports.Write(map[string][]byte{compactReceiptKey(receipt.Operation): raw})
}
func (r *Runtime) compactWork(ctx context.Context, operation string) (control.CompactWork, cluster.ManagementReply, error) {
	raw, _ := json.Marshal(control.CompactWorkRequest{Operation: operation})
	reply, err := r.appCall(ctx, "compact-work", raw)
	if err != nil {
		return control.CompactWork{}, reply, err
	}
	work, err := schema.Decode[control.CompactWork](reply.Data)
	if err != nil || work.Schema != 1 || work.Cluster != r.controlPolicy.Cluster || work.Owner != r.Identity.Public || work.Operation != operation || work.Index == 0 || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex < work.Index {
		return work, reply, mydcp.ErrAdmission
	}
	return work, reply, nil
}
func (r *Runtime) compactReport(ctx context.Context, report control.CompactReport) (cluster.ManagementReply, error) {
	report.Schema = 1
	report.Cluster = r.controlPolicy.Cluster
	report.Reporter = r.Identity.Public
	report.At = uint64(time.Now().Unix())
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.CompactReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "compact-report", raw)
	if err != nil {
		return reply, err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return reply, errCompactCAS
	}
	return reply, nil
}
func (r *Runtime) runCompaction(operation string) {
	defer r.wg.Done()
	defer func() { r.mu.Lock(); r.compactBusy = false; r.mu.Unlock() }()
	ctx := r.ctx
	work, _, err := r.compactWork(ctx, operation)
	if err != nil {
		return
	}
	if work.State == "queued" {
		action, leader, code := "begin", work.Leader, ""
		if !work.Allowed {
			action, leader, code = "cancel", "", "authority-revoked"
		} else if !work.CanBegin {
			return
		}
		_, err = r.compactReport(ctx, control.CompactReport{Operation: operation, Node: work.Node, Action: action, Leader: leader, Expected: work.NodeRevision, RootRevision: work.RootRevision, Epoch: work.Epoch, Code: code})
		if err != nil || action == "cancel" {
			return
		}
	}
	work, _, err = r.compactWork(ctx, operation)
	if err != nil || work.State != "running" {
		return
	}
	engine := r.Engine()
	if _, err = engine.ReadAtLeast(ctx, work.Index); err != nil {
		return
	}
	receipt, err := r.loadCompactReceipt(work)
	if err != nil {
		return
	}
	if receipt.Dispatch != nil && receipt.Result == nil {
		result, observed, recoverErr := engine.RecoverManualCompact(ctx, *receipt.Dispatch)
		if recoverErr != nil {
			return
		}
		if observed {
			receipt.Result = &result
			if err = r.saveCompactReceipt(receipt); err != nil {
				return
			}
		}
	}
	if receipt.Result == nil {
		if !work.Allowed {
			return
		} // an original unknown is not false non-execution
		work, _, err = r.compactWork(ctx, operation)
		if err != nil || !work.Allowed || work.State != "running" {
			return
		}
		local, readErr := engine.ReadAtLeast(ctx, work.Index)
		if readErr != nil {
			return
		}
		originalWasSent := receipt.Dispatch != nil
		result, runErr := engine.ManualCompact(ctx, operation, local.RaftIndex, work.Options, func(dispatch maintenance.CompactDispatch) error {
			receipt.Dispatch = &dispatch
			return r.saveCompactReceipt(receipt)
		})
		if result.Dispatch.Schema == 0 {
			if !originalWasSent && runErr != nil && ctx.Err() == nil {
				current, _, lookupErr := r.compactWork(ctx, operation)
				if lookupErr == nil && current.State == "running" {
					_, _ = r.compactReport(ctx, control.CompactReport{Operation: operation, Node: current.Node, Action: "finish", Expected: current.NodeRevision, RootRevision: current.RootRevision, Epoch: current.Epoch, Code: "dispatch-preflight-failed"})
				}
			}
			return
		}
		receipt.Result = &result
		if runErr != nil {
			receipt.Code = result.ErrorCode
			if receipt.Code == "" {
				receipt.Code = "snapshot-failed"
			}
		} else if !result.TargetMet {
			receipt.Code = "retention-not-met"
		}
		if err = r.saveCompactReceipt(receipt); err != nil {
			return
		}
	}
	if ctx.Err() != nil {
		return
	} // private terminal survives daemon stop/restart
	work, _, err = r.compactWork(ctx, operation)
	if err != nil || work.State != "running" {
		return
	}
	_, _ = r.compactReport(ctx, control.CompactReport{Operation: operation, Node: work.Node, Action: "finish", Expected: work.NodeRevision, RootRevision: work.RootRevision, Epoch: work.Epoch, Result: receipt.Result, Code: receipt.Code})
}

// Called by the existing tracked membership loop on every installed node. The
// SDK future runs in one tracked owner job, leaving native reconciliation live.
func (r *Runtime) advanceCompactions(ctx context.Context) {
	if r.reports == nil || ctx.Err() != nil {
		return
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return
	}
	jobs, err := r.controlPolicy.Compactions(view.State)
	if err != nil {
		return
	}
	_, leader := r.Engine().Leader()
	for _, record := range jobs.Records {
		if record.Job.Terminal() {
			continue
		}
		for _, node := range record.Job.Nodes {
			if node.Key != r.Identity.Public || node.State != "queued" && node.State != "running" {
				continue
			}
			if node.State == "queued" && !record.Job.CanBegin(node.Node, string(leader)) {
				preview, err := r.controlPolicy.CompactWork(view.State, r.Identity.Public, control.CompactWorkRequest{Operation: record.Job.Operation}, string(leader))
				if err != nil || preview.Allowed {
					continue
				}
			}
			r.mu.Lock()
			if !r.compactBusy && ctx.Err() == nil {
				r.compactBusy = true
				r.wg.Add(1)
				go r.runCompaction(record.Job.Operation)
			}
			r.mu.Unlock()
		}
		if !r.Engine().IsLeader() {
			continue
		}
		for _, node := range record.Job.Nodes {
			if node.Key == r.Identity.Public || node.State != "queued" || !record.Job.CanBegin(node.Node, string(leader)) {
				continue
			}
			peer, known := r.Mesh.Peer(mydcp.Identity(node.Key))
			reachable := false
			if known && peer.Member {
				probe, cancel := context.WithTimeout(ctx, 2*time.Second)
				response, probeErr := cluster.CallManagement(probe, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "status"})
				cancel()
				reachable = probeErr == nil || response.Code != "" // a valid error reply still proves reachability
			}
			if !reachable && r.Engine().IsLeader() && ctx.Err() == nil {
				_, _ = r.compactReport(ctx, control.CompactReport{Operation: record.Job.Operation, Node: node.Node, Action: "skip", Leader: string(leader), Expected: node.Revision, RootRevision: view.State.Object(control.CompactKey).Revision, Epoch: view.State.ModuleEpoch(), Code: "unreachable"})
			}
			return // one reachability probe per membership pass
		}
	}
}
