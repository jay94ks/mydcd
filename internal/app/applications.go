// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

var errNoAppLeader = errors.New("no current app leader")

// appLeaderWait bounds how long a request waits for a restarted follower to
// learn the leader. It is a few Raft heartbeat timeouts.
const appLeaderWait = 3 * time.Second

// awaitAppLeader returns once this node knows a leader, the wait bound
// passes, or ctx ends. The caller's request still decides the outcome.
func (r *Runtime) awaitAppLeader(ctx context.Context) {
	deadline := time.NewTimer(appLeaderWait)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, id := r.Engine().Leader(); id != "" {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-tick.C:
		}
	}
}

var errAppLeaderPeerUnavailable = fmt.Errorf("current app leader peer unavailable: %w", mydcp.ErrAdmission)

func (r *Runtime) appCommand(method, caller string, input []byte, v cluster.View) (state.Command, error) {
	key, err := identity.ParseKey(caller)
	if err != nil || v.Local {
		return state.Command{}, mydcp.ErrAdmission
	}
	if method == "image-build-cache-automatic-report" {
		cmd, err := r.controlPolicy.ResolveImageBuildCacheAutomaticReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.ImageBuildCacheAutomaticReport](input)
			now := uint64(time.Now().Unix())
			if err != nil || report.At > now || now-report.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "image-build-automatic-git-report" {
		cmd, err := r.controlPolicy.ResolveImageBuildAutomaticGitReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.ImageBuildAutomaticGitReport](input)
			now := uint64(time.Now().Unix())
			if err != nil || report.At > now || now-report.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "image-build-git-observation-report" {
		cmd, err := r.controlPolicy.ResolveImageBuildGitObservationReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.ImageBuildGitObservationReport](input)
			now := uint64(time.Now().Unix())
			if err != nil || report.At > now || now-report.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "image-build-cache-prune-report" {
		cmd, err := r.controlPolicy.ResolveImageBuildCachePruneReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.ImageBuildCachePruneReport](input)
			now := uint64(time.Now().Unix())
			if err != nil || report.At > now || now-report.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "image-build-job-report" {
		cmd, err := r.controlPolicy.ResolveImageBuildJobReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.ImageBuildJobReport](input)
			now := uint64(time.Now().Unix())
			if err != nil || report.At > now || now-report.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "image-build-owner-report" {
		report, err := schema.Decode[control.ImageBuildOwnerReport](input)
		now := time.Now().Unix()
		if err != nil || report.Part != nil && (report.Part.At > now || now-report.Part.At > 30) {
			return state.Command{}, mydcp.ErrAdmission
		}
		return r.controlPolicy.ResolveImageBuildOwnerReport(v.State, key, input)
	}
	if method == "registry-maintenance-report" {
		command, err := r.controlPolicy.ResolveRegistryMaintenanceReport(v.State, key, input)
		if err != nil {
			return command, err
		}
		if _, found := v.State.LookupResult(command); !found {
			report, err := schema.Decode[control.RegistryMaintenanceReport](input)
			now := uint64(time.Now().Unix())
			if err != nil || report.At > now || now-report.At > 30 {
				return command, mydcp.ErrAdmission
			}
		}
		return command, nil
	}
	if method == "image-cache-report" {
		command, err := r.controlPolicy.ResolveImageCacheReport(v.State, key, input)
		if err != nil {
			return command, err
		}
		if _, found := v.State.LookupResult(command); !found {
			report, err := schema.Decode[control.ImageCacheReport](input)
			now := uint64(time.Now().Unix())
			if err != nil || report.At > now || now-report.At > 30 {
				return command, mydcp.ErrAdmission
			}
		}
		return command, nil
	}
	if method == "tunnel-reconnect-report" {
		command, err := r.controlPolicy.ResolveTunnelReport(v.State, key, input)
		if err != nil {
			return command, err
		}
		if _, found := v.State.LookupResult(command); !found {
			report, err := schema.Decode[control.TunnelReport](input)
			now := uint64(time.Now().Unix())
			if err != nil || report.At > now || now-report.At > 30 {
				return command, mydcp.ErrAdmission
			}
		}
		return command, nil
	}
	if method == "compact-report" {
		report, err := schema.Decode[control.CompactReport](input)
		if err != nil {
			return state.Command{}, err
		}
		_, leader := r.Engine().Leader()
		if report.Action == "begin" || report.Action == "skip" {
			if report.Leader != string(leader) {
				return state.Command{}, mydcp.ErrAdmission
			}
		}
		command, err := r.controlPolicy.ResolveCompactReport(v.State, key, input)
		if err != nil {
			return command, err
		}
		if _, found := v.State.LookupResult(command); !found {
			now := uint64(time.Now().Unix())
			if report.At > now || now-report.At > 30 {
				return command, mydcp.ErrAdmission
			}
		}
		return command, nil
	}
	if method == "certificate-expiry-report" {
		cmd, err := r.controlPolicy.ResolveCertificateExpiry(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, e := schema.Decode[control.CertificateExpiryReport](input)
			now := uint64(time.Now().Unix())
			if e != nil || report.At > now || now-report.At > 60 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "standalone-policy-report" {
		cmd, err := r.controlPolicy.ResolveAppCommand(v.State, method, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			q, err := schema.Decode[control.StandalonePolicyReport](input)
			now := time.Now().Unix()
			if err != nil || q.At > now || now-q.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "task-restart-report" {
		cmd, err := r.controlPolicy.ResolveAppCommand(v.State, method, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.TaskRestartReport](input)
			now := uint64(time.Now().Unix())
			if err != nil || report.At > now || now-report.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "app-delivery-progress" {
		cmd, err := r.controlPolicy.ResolveAppCommand(v.State, method, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, decodeErr := schema.Decode[control.AppDeliveryProgress](input)
			now := time.Now().Unix()
			if decodeErr != nil || report.At > uint64(now) || uint64(now)-report.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "node-shell-report" {
		return r.controlPolicy.ResolveNodeShellReport(v.State, key, input)
	}
	if method == "member-report" {
		return r.controlPolicy.ResolveMemberReport(v.State, key, input)
	}
	if method == "tenant-retirement-report" {
		return r.controlPolicy.ResolveTenantRetirementReport(v.State, key, input)
	}
	if method == "node-storage-report" {
		return r.controlPolicy.ResolveNodeStorageReport(v.State, key, input)
	}
	if method == "external-registry-closed" {
		cmd, err := r.controlPolicy.ResolveExternalRegistryClose(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			q, err := schema.Decode[control.ExternalRegistryReaderClosed](input)
			now := time.Now().Unix()
			if err != nil || q.At > now || now-q.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "registry-report" {
		cmd, err := r.controlPolicy.ResolveRegistryReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.RegistryReport](input)
			now := time.Now().Unix()
			if err != nil || report.At > now || now-report.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "checker-build-report" {
		cmd, err := r.controlPolicy.ResolveCheckerBuildReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.CheckerBuildReport](input)
			now := time.Now().Unix()
			if err != nil || report.At > now || now-report.At > 30 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "volume-file-report" {
		return r.controlPolicy.ResolveVolumeFileReport(v.State, key, input)
	}
	if method == "volume-create-report" {
		cmd, err := r.controlPolicy.ResolveVolumeCreateReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.VolumeCreateReport](input)
			now := time.Now().Unix()
			if err != nil || report.At > now || now-report.At > 300 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "volume-delete-report" {
		cmd, err := r.controlPolicy.ResolveVolumeDeleteReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.VolumeDeleteReport](input)
			now := time.Now().Unix()
			if err != nil || report.At > now || now-report.At > 300 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "volume-backup-report" {
		cmd, err := r.controlPolicy.ResolveVolumeBackupReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.VolumeBackupReport](input)
			now := time.Now().Unix()
			if err != nil || report.At > now || now-report.At > 300 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "volume-move-report" {
		cmd, err := r.controlPolicy.ResolveVolumeMoveReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.VolumeMoveReport](input)
			now := time.Now().Unix()
			if err != nil || report.At > now || now-report.At > 300 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "volume-restore-report" {
		cmd, err := r.controlPolicy.ResolveVolumeRestoreReport(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.VolumeRestoreReport](input)
			now := time.Now().Unix()
			if err != nil || report.At > now || now-report.At > 300 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	if method == "vault-approve-command" {
		cmd, err := r.controlPolicy.ResolveVaultApprovalCommand(v.State, key, input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			report, err := schema.Decode[control.VaultApprovalReport]([]byte(cmd.Value))
			now := time.Now().Unix()
			if err != nil || report.At > now || now-report.At > 300 {
				return cmd, mydcp.ErrAdmission
			}
		}
		return cmd, nil
	}
	cmd, err := r.controlPolicy.ResolveAppCommand(v.State, method, key, input)
	if err != nil {
		return cmd, err
	}
	if method == "network-dns-progress" {
		report, err := schema.Decode[control.NetworkDNSProgress](input)
		if err != nil {
			return cmd, err
		}
		if report.Close != nil {
			if _, found := v.State.LookupResult(cmd); !found {
				now := uint64(time.Now().Unix())
				if report.At > now || now-report.At > 300 {
					return cmd, mydcp.ErrAdmission
				}
			}
		}
	}
	if method == "app-progress" {
		report, err := schema.Decode[control.AppProgress](input)
		if err != nil {
			return cmd, err
		}
		if _, found := v.State.LookupResult(cmd); !found {
			now := uint64(time.Now().Unix())
			if report.At > now || now-report.At > 300 {
				return cmd, mydcp.ErrAdmission
			}
		}
	}
	return cmd, nil
}
func (r *Runtime) appCall(ctx context.Context, method string, input []byte) (cluster.ManagementReply, error) {
	if r.Engine().IsLeader() {
		v, err := r.Engine().Read(ctx, true)
		if err != nil {
			return cluster.ManagementReply{}, err
		}
		reply := cluster.ManagementReply{Schema: 1, Code: "ok", Node: r.installation.record.Root.Self.ID, RaftIndex: v.RaftIndex, AppliedTerm: v.Term, CommandIndex: v.State.Index()}
		if _, report := cluster.ReportMethod(method); report {
			cmd, err := r.appCommand(method, r.commandIdentity().Actor(), input, v)
			if err != nil {
				return reply, err
			}
			committed, err := r.Engine().Submit(ctx, cmd)
			if err != nil {
				return reply, err
			}
			reply.Committed = &committed
			reply.RaftIndex, reply.AppliedTerm, reply.CommandIndex = committed.RaftIndex, committed.Term, committed.Result.Index
			return reply, nil
		}
		reply.Data, err = r.readModule(ctx, method, r.commandIdentity().Actor(), input, v)
		return reply, err
	}
	_, id := r.Engine().Leader()
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return cluster.ManagementReply{}, err
	}
	members, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return cluster.ManagementReply{}, err
	}
	entry, ok := members.Entry(string(id))
	if !ok {
		return cluster.ManagementReply{}, errNoAppLeader
	}
	key, err := identity.ParseKey(entry.CurrentPeer().Key)
	if err != nil {
		return cluster.ManagementReply{}, err
	}
	peer, ok := r.Mesh.Peer(mydcp.Identity(key))
	if !ok || !peer.Member {
		// A known leader without a current authenticated transport is not a
		// source-policy revocation. Keep admission failure identity for callers.
		return cluster.ManagementReply{}, errAppLeaderPeerUnavailable
	}
	return cluster.CallManagement(ctx, r.Mesh, r.commandIdentity(), r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: method, Latest: true, Input: input})
}
func (r *Runtime) appProgress(ctx context.Context, v cluster.View, app control.AppView, action, key string, observation *deployment.Observation) error {
	return r.sendAppProgress(ctx, r.newAppProgress(v, app, action, key, observation))
}
func (r *Runtime) newAppProgress(v cluster.View, app control.AppView, action, key string, observation *deployment.Observation) control.AppProgress {
	report := control.AppProgress{Schema: 1, Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Tenant: app.Tenant, App: app.App, Operation: app.Operation.ID, Key: key, Action: action, Expected: app.Revision, At: uint64(time.Now().Unix()), Observation: observation, Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.AppsKey).Revision}
	if control.StageReport(action) {
		report.Stage = r.controlPolicy.StageDigest(v.State, app.Tenant, app.App, key)
	}
	return report
}
func (r *Runtime) sendAppProgress(ctx context.Context, report control.AppProgress) error {
	_, err := r.sendAppProgressAt(ctx, report)
	return err
}

// The positive original receipt supplies a command ordinal, never a guessed
// count or permission. Batches consume it before reading later dependencies.
func (r *Runtime) sendAppProgressAt(ctx context.Context, report control.AppProgress) (uint64, error) {
	digest := sha256.Sum256(control.AppProgressBytes(report))
	report.RequestID = fmt.Sprintf("app/%x", digest)
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.AppProgressBytes(report))
	if report.Action == "observe" && report.Observation != nil {
		// An unchanged fact is renewed over MyDCP, never written to Raft.
		if renewed, err := r.renewAppObservation(ctx, report); renewed || err != nil {
			return 0, err
		}
	}
	if report.Action == "bind-inputs" {
		v, err := r.Engine().Read(ctx, false)
		if err != nil {
			return 0, err
		}
		if err = r.controlPolicy.CheckAppBinding(v.State, report); err != nil {
			return 0, fmt.Errorf("app binding awaits current reservation authority: %w", err)
		}
	}
	hold, holdable := appProgressHoldKey(report)
	if holdable && r.reportHeld(hold, time.Now()) {
		return 0, fmt.Errorf("app progress %s held after a rejection: %w", report.Action, reconcile.ErrPending)
	}
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "app-progress", raw)
	if err != nil {
		return 0, err
	}
	if !holdable {
		// A report carrying an observation is a new owner fact; it must not
		// wait behind an earlier, different fact's rejection.
	} else if reply.Committed != nil && reply.Committed.Result.Code != state.Applied {
		// Each rejected report is a Raft entry and a ledger receipt: space
		// out the same report instead of resending it on every pass.
		r.holdReport(hold, moveReportRejected{report.Action, reply.Committed.Result.Code}, time.Now())
	} else if reply.Committed != nil {
		r.holdReport(hold, nil, time.Now())
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied || reply.Committed.Result.Index == 0 {
		err = fmt.Errorf("app progress %s rejected (key=%s app_revision=%d root_revision=%d): %v", report.Action, report.Key, report.Expected, report.RootRevision, reply.Committed)
		if report.Action == "finish" && reply.Committed != nil {
			if v, readErr := r.Engine().Read(ctx, false); readErr == nil {
				if why := r.explainAppFinish(v.State, report); why != "" {
					err = fmt.Errorf("%w: reason=%s", err, why)
				}
			}
		}
		if report.Action == "retire-addresses" {
			// Result codes carry no reason; replay the reducer on the local
			// view so a repeating rejection names the failing condition.
			if v, readErr := r.Engine().Read(ctx, false); readErr == nil {
				if why := r.controlPolicy.ExplainAddressRetirement(v.State, report); why != "" {
					err = fmt.Errorf("%w: %s", err, why)
				}
			}
		}
		return 0, err
	}
	return reply.Committed.Result.Index, nil
}

// Collect durable command outcomes before native reconciliation. An adapter
// waiting for inputs must not prevent collecting the committed inputs result.
// This path only queries the original command and reports its existing result.
func (r *Runtime) collectAppResults(ctx context.Context, v cluster.View, apps control.Apps) (bool, error) {
	for _, app := range apps.Records() {
		e, ok := apps.Execution(app.Tenant, app.App)
		if !ok || e.Status() == "Succeeded" || e.Status() == "Closed" {
			continue
		}
		for _, step := range e.Steps() {
			metadata := step.Kind == "delivery" && step.Owner == ([32]byte{}) && step.Completion == deployment.Committed && r.Engine().IsLeader()
			if !metadata && step.Owner != r.Identity.Public {
				continue
			}
			stage, _ := e.Stage(step.Key)
			if stage.Command == nil && !e.ReplacementAllows(step.Key) {
				continue
			}
			if stage.Result != nil || stage.Command == nil || stage.Journal.Pending == nil || stage.Journal.Pending.Phase == reconcile.Prepared {
				continue
			}
			raw, err := state.EncodeCommand(*stage.Command)
			if err != nil {
				return false, err
			}
			reply, err := r.appCall(ctx, "app-result", raw)
			if err != nil {
				return false, err
			}
			result, err := schema.Decode[control.AppResult](reply.Data)
			if err != nil {
				return false, err
			}
			if result.Found && result.Result != nil {
				return true, r.appProgress(ctx, v, app, "collect", step.Key, nil)
			}
		}
	}
	return false, nil
}

// advanceApps never resubmits a Dispatched/Unknown mutation. Only this call's
// successful Prepared->Dispatched ACK permits the one original proposal. Later
// passes query the original result, then collect or preserve Unknown.
func (r *Runtime) advanceApps(ctx context.Context, v cluster.View, apps control.Apps) error {
	catalog, err := r.controlPolicy.Catalog(v.State)
	if err != nil {
		return err
	}
	resources, err := r.controlPolicy.Resources(v.State)
	if err != nil {
		return err
	}
	for _, app := range apps.Records() {
		e, ok := apps.Execution(app.Tenant, app.App)
		if !ok || e.Status() == "Succeeded" || e.Status() == "Closed" {
			continue
		}
		inventory, _ := apps.Inventory(app.Tenant, app.App)
		_, retiring := inventory.Retirement()
		for _, step := range e.Steps() {
			metadata := step.Kind == "delivery" && step.Owner == ([32]byte{}) && step.Completion == deployment.Committed && r.Engine().IsLeader()
			// Delivery metadata belongs to the consensus leader, including a
			// control with no local native modules. Native steps still require
			// their original owner and installed adapters.
			if !metadata && step.Owner != r.Identity.Public {
				continue
			}
			wait := func(format string, args ...any) {
				r.noteAppWait(app, e.Revision(), step.Key, fmt.Sprintf(format, args...))
			}
			if !metadata && (r.network == nil || step.Kind != "bridge" && step.Kind != "network-ref" && (r.ingress == nil || step.Kind != "ingress") && (r.tunnel == nil || step.Kind != "tunnel") && (r.dnsPath == "" || step.Kind != "dns") && (r.workload == nil || step.Kind != "volume" && step.Kind != "task" && step.Kind != "inputs")) {
				wait("this server has no %s adapter", step.Kind)
				continue
			}
			stage, _ := e.Stage(step.Key)
			if retiring && (stage.Command == nil || stage.Journal.Pending == nil || stage.Journal.Pending.Phase == reconcile.Prepared) && !(stage.Command == nil && e.ReplacementAllows(step.Key)) {
				wait("the app is retiring")
				continue
			}
			if stage.Result != nil {
				r.noteAppWait(app, e.Revision(), step.Key, "")
				continue
			}
			if stage.Command == nil || stage.Journal.Pending != nil && stage.Journal.Pending.Phase == reconcile.Prepared {
				if status := e.Status(); status == "Paused" || status == "Failed" {
					wait("the deploy is %s", strings.ToLower(status))
					continue
				}
				if err := r.controlPolicy.CheckAcceptedAppStep(v.State, apps, catalog, app.Tenant, app.App, step.Key); err != nil {
					wait("the accepted plan no longer admits this step: %v", err)
					continue
				}
			}
			if stage.Command == nil {
				global, gok := resources.Quotas.Limit("", step.Node)
				scoped, sok := resources.Quotas.Limit(app.Tenant, step.Node)
				if !metadata && (!gok || !sok || min(global.MaxConsumers, scoped.MaxConsumers) < 1) {
					wait("no connections allowed on %s (node limit %t, tenant limit %t, max consumers %d/%d)", step.Node, gok, sok, global.MaxConsumers, scoped.MaxConsumers)
					continue
				}
				if step.Kind == "tunnel" && (min(global.PacketQueuePackets, scoped.PacketQueuePackets) < 1 || min(global.PacketQueueBytes, scoped.PacketQueueBytes) < 1280+120) {
					wait("packet queue too small on %s (node %d/%d, tenant %d/%d)", step.Node, global.PacketQueuePackets, global.PacketQueueBytes, scoped.PacketQueuePackets, scoped.PacketQueueBytes)
					continue
				}
				if _, _, err = e.Prepare(catalog, e.Revision(), step.Key, v.State.Object(step.Key), uint64(time.Now().Unix())); err != nil {
					wait("prepare: %v%s", err, r.appDependencyWait(e, step.Key))
					continue
				}
				r.noteAppWait(app, e.Revision(), step.Key, "")
				return r.appProgress(ctx, v, app, "prepare", step.Key, nil)
			}
			if stage.Journal.Pending == nil {
				continue
			}
			if stage.Journal.Pending.Phase == reconcile.Prepared {
				if _, _, err = e.Send(catalog, e.Revision(), step.Key, uint64(time.Now().Unix())); err != nil {
					wait("send: %v%s", err, r.appDependencyWait(e, step.Key))
					continue
				}
				if err = r.appProgress(ctx, v, app, "send", step.Key, nil); err != nil {
					return err
				}
				raw, err := state.EncodeCommand(*stage.Command)
				if err != nil {
					return err
				}
				reply, err := r.appCall(ctx, "app-command", raw)
				if err != nil {
					return err
				} // The original shared Dispatched state survives.
				if reply.Committed == nil {
					return errors.New("app command outcome unknown")
				}
				return nil
			}
			raw, err := state.EncodeCommand(*stage.Command)
			if err != nil {
				return err
			}
			reply, err := r.appCall(ctx, "app-result", raw)
			if err != nil {
				return err
			}
			result, err := schema.Decode[control.AppResult](reply.Data)
			if err != nil {
				return err
			}
			if result.Found && result.Result != nil {
				return r.appProgress(ctx, v, app, "collect", step.Key, nil)
			}
			if stage.Journal.Pending.Phase == reconcile.Dispatched {
				return r.appProgress(ctx, v, app, "unknown", step.Key, nil)
			}
		}
		if _, err := e.Finish(e.Revision(), uint64(time.Now().Unix())); err == nil && !retiring {
			return r.appProgress(ctx, v, app, "finish", "", nil)
		}
	}
	return nil
}

func (r *Runtime) reconcileManaged(v cluster.View) error {
	// Scheduling previews are refreshed after successful owner/prerequisite
	// reports; every effect still obtains its own current authority.
	currentApps := func() (cluster.View, control.Apps, error) {
		current, err := r.Engine().Read(r.ctx, false)
		if err != nil {
			return current, control.Apps{}, err
		}
		apps, err := r.controlPolicy.ReadApps(current.State)
		return current, apps, err
	}
	return reconcileManagedPass(r.ctx,
		func() (bool, error) { return r.reconcileManagedOwners(v) },
		func() error {
			current, apps, err := currentApps()
			if err != nil {
				return err
			}
			_, err = r.reconcileAppDNS(r.ctx, current, apps)
			return err
		},
		func() error {
			if r.workload != nil {
				current, apps, err := currentApps()
				if err != nil {
					return err
				}
				if _, err = r.reconcileAppWorkloads(r.ctx, current, apps); err != nil {
					return fmt.Errorf("app workload reconciliation: %w", err)
				}
			}
			if err := r.advanceCurrentApps(r.ctx); err != nil {
				return fmt.Errorf("app advancement: %w", err)
			}
			current, apps, err := currentApps()
			if err != nil {
				return err
			}
			if err = r.expireAppObservations(r.ctx, current, apps); err != nil {
				return fmt.Errorf("app observation expiry: %w", err)
			}
			return nil
		})
}

func (r *Runtime) reconcileManagedOwners(v cluster.View) (dnsVisited bool, err error) {
	if err := r.recoverCheckerObservations(r.ctx); err != nil {
		return false, err
	}
	current, err := r.Engine().Read(r.ctx, false)
	if err != nil {
		return false, err
	}
	apps, err := r.controlPolicy.ReadApps(current.State)
	if err != nil {
		return false, err
	}
	if err := r.advanceVolumeFiles(r.ctx, current); err != nil {
		return false, err
	}
	if changed, err := r.advanceStandalonePolicies(r.ctx, current, apps); err != nil {
		return false, err
	} else if changed {
		// A connection sample is not completion of the owner pass. Otherwise
		// enough periodically sampled standalones can starve Task preparation
		// and retirement forever. Continue from the committed view, not stale CAS.
		current, err = r.Engine().Read(r.ctx, false)
		if err != nil {
			return false, err
		}
		apps, err = r.controlPolicy.ReadApps(current.State)
		if err != nil {
			return false, err
		}
	}
	if err = r.advanceTaskRestarts(r.ctx, apps); err != nil {
		return false, err
	}
	v, err = r.Engine().Read(r.ctx, false)
	if err != nil {
		return false, err
	}
	projection, err := r.controlPolicy.ProjectResources(v.State)
	if err != nil {
		return false, err
	}
	apps, err = r.controlPolicy.ReadApps(v.State)
	if err != nil {
		return false, err
	}
	refresh := func(floor uint64) error {
		var err error
		v, err = r.Engine().ReadAtLeast(r.ctx, floor)
		if err != nil {
			return err
		}
		projection, err = r.controlPolicy.ProjectResources(v.State)
		if err != nil {
			return err
		}
		apps, err = r.controlPolicy.ReadApps(v.State)
		return err
	}
	var observedFloor uint64
	if changed, err := r.collectAppResults(r.ctx, v, apps); changed || err != nil {
		return false, err
	}
	if changed, err := r.advanceDeliveryController(r.ctx, v, apps); changed || err != nil {
		return false, err
	}
	if changed, err := r.reconcileAppRetirements(r.ctx, v, apps); changed || err != nil {
		return false, err
	}
	if r.Engine().IsLeader() {
		for _, app := range apps.Records() {
			if inventory, exists := apps.Inventory(app.Tenant, app.App); exists && inventory.ReplacementReady(uint64(time.Now().Unix())) {
				return false, r.appProgress(r.ctx, v, app, "advance-wave", "", nil)
			}
			if operation, ready := apps.LogClearContinuation(app.Tenant, app.App); ready {
				allowed, err := r.controlPolicy.LogClearContinuationReady(v.State, r.Identity.Public, app.Tenant, app.App)
				if err != nil {
					return false, err
				}
				if !allowed {
					continue
				}
				report := r.newAppProgress(v, app, "recreate-continue", "", nil)
				report.Operation = operation
				return false, r.sendAppProgress(r.ctx, report)
			}
		}
	}
	if err := r.reconcileTenantIsolation(r.ctx, v, projection); err != nil {
		return false, err
	}
	if err = r.reconcileManagedNetworkBridges(r.ctx, v, projection); err != nil {
		return false, fmt.Errorf("managed Bridge sources: %w", err)
	}
	if r.tunnel != nil {
		if err = r.tunnel.stopRetiringRoutePlanes(v); err != nil {
			return false, fmt.Errorf("retiring route planes: %w", err)
		}
	}
	if err = r.prepareRouteOwners(r.ctx, v, projection); err != nil {
		return false, fmt.Errorf("route owners: %w", err)
	}
	if r.tunnel != nil {
		if err = r.tunnel.reconcileRoutePlanes(v, projection); err != nil {
			return false, fmt.Errorf("route planes: %w", err)
		}
	}
	if err = r.collectActiveRouteFlows(r.ctx, v, projection); err != nil {
		return false, fmt.Errorf("route flow collection: %w", err)
	}
	if r.network != nil {
		keys := r.network.Keys()
		for key, goal := range projection.Goals {
			if goal.Bridge != nil && goal.Goal.Owner == r.Identity.Public && !slices.Contains(keys, key) {
				keys = append(keys, key)
			}
		}
		slices.Sort(keys)
		for _, key := range keys {
			if strings.HasPrefix(key, tenancy.ManagedNetworkSourcePrefix) {
				continue // consumed above by the same native manager
			}
			goal, exists := projection.Goals[key]
			if !exists || goal.Bridge == nil || goal.Goal.Owner != r.Identity.Public {
				if old, err := r.network.View(key); err == nil && old.State.Pending == nil && !old.State.Applied.Present && !old.State.Desired.Present && len(old.Consumers) == 0 {
					continue
				}
				return false, fmt.Errorf("local bridge %s has no exact committed app source", key)
			}
			if inventory, exists := apps.Inventory(goal.Goal.Tenant, goal.Goal.App); exists {
				_, retiring := inventory.Retirement()
				_, executing := inventory.Execution()
				if retiring || !executing {
					continue
				}
			}
			o := v.State.Object(key)
			spec := *goal.Bridge
			spec.Lifecycle = schema.Lifecycle{}
			specRaw, _ := json.Marshal(spec)
			record, viewErr := r.network.View(key)
			known := slices.Contains(r.network.Keys(), key)
			if known && viewErr != nil {
				return false, viewErr
			}
			retiring := goal.Goal.Lifecycle != nil && goal.Goal.Lifecycle.Drain
			needCreate := !known || record.State.Pending == nil && !record.State.Applied.Present || record.State.Pending != nil && record.State.Pending.Phase == reconcile.Prepared
			capacity := record.Capacity
			if !retiring && needCreate {
				raw, _ := json.Marshal(control.NativeRequest{Source: deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}})
				reply, err := r.appCall(r.ctx, "app-native-permit", raw)
				if err != nil {
					return false, err
				}
				permit, err := schema.Decode[control.NativePermit](reply.Data)
				if err != nil || permit.Source.Key != key || permit.Source.Generation != o.Generation || permit.Source.Revision != o.Revision || permit.Owner != r.Identity.Public || permit.Kind != "bridge" || permit.Spec != sha256.Sum256(specRaw) || permit.MaxConsumers < 1 {
					return false, errors.New("app native permit/source mismatch")
				}
				capacity = permit.MaxConsumers
			} else {
				// Quota shrink retains original pins. Missing/revoked policy cannot erase
				// the old capacity or resource; new consumers require fresh authority.
				global, gok := projection.Resources.Quotas.Limit("", goal.Goal.Node)
				scoped, sok := projection.Resources.Quotas.Limit(goal.Goal.Tenant, goal.Goal.Node)
				if gok && sok && min(global.MaxConsumers, scoped.MaxConsumers) > 0 {
					capacity = min(global.MaxConsumers, scoped.MaxConsumers)
				}
			}
			if capacity < 1 {
				return false, errors.New("app bridge needs committed positive consumer policy")
			}
			active := &spec
			if retiring {
				active = nil
			}
			if err = r.network.Desired(key, o.Revision, o.Generation, active, capacity); err != nil {
				return false, err
			}
			if err = r.network.Step(r.ctx, key); err != nil {
				return false, err
			}
			if retiring {
				continue
			}
			native, err := r.network.Inspect(r.ctx, key)
			if err != nil {
				return false, err
			}
			for _, app := range apps.Records() {
				e, _ := apps.Execution(app.Tenant, app.App)
				stage, ok := e.Stage(key)
				if !ok || stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied {
					continue
				}
				now := uint64(time.Now().Unix())
				if old := stage.Observation; old != nil && old.Native == native && old.Generation == o.Generation && old.Revision == o.Revision && old.Applied && !old.Released && !old.Expired && old.At <= now && now-r.renewedAt(*old) < control.AppObservationMaxAge/2 {
					continue
				}
				sequence := uint64(1)
				if stage.Observation != nil {
					sequence = stage.Observation.Sequence + 1
					if sequence == 0 {
						return false, errors.New("app observation sequence exhausted")
					}
				}
				local, err := r.network.View(key)
				if err != nil {
					return false, err
				}
				observation := deployment.Observation{Cluster: r.controlPolicy.Cluster, Plan: app.Operation.Plan, Operation: app.Operation.ID, Key: key, Native: native, Owner: r.Identity.Public, Command: state.Digest(*stage.Command), Generation: o.Generation, Revision: o.Revision, Sequence: sequence, At: uint64(time.Now().Unix()), Applied: true, Pins: uint64(len(local.Consumers))}
				observation.Signature = ed25519.Sign(r.Identity.Private, deployment.ObservationBytes(observation))
				index, err := r.sendAppProgressAt(r.ctx, r.newAppProgress(v, app, "observe", key, &observation))
				if err != nil {
					return false, err
				}
				observedFloor = max(observedFloor, index)
				break
			}
		}
	}
	if r.tunnel != nil {
		if err = r.tunnel.ReconcileManaged(v); err != nil {
			return false, fmt.Errorf("managed TUN sources: %w", err)
		}
		for _, app := range apps.Records() {
			if inventory, ok := apps.Inventory(app.Tenant, app.App); ok {
				if _, retiring := inventory.Retirement(); retiring {
					continue
				}
			}
			e, ok := apps.Execution(app.Tenant, app.App)
			if !ok {
				continue
			}
			for _, step := range e.Steps() {
				if step.Kind != "tunnel" || step.Owner != r.Identity.Public {
					continue
				}
				stage, ok := e.Stage(step.Key)
				if !ok || stage.Command == nil || stage.Result == nil || stage.Result.Code != state.Applied {
					continue
				}
				if err = r.tunnel.Ready(step.Key); err != nil {
					return false, err
				}
				native, err := r.tunnel.manager.Inspect(r.ctx, step.Key)
				if err != nil {
					return false, err
				}
				if r.freshAppObservation(stage, native, false) {
					continue
				}
				observation, err := r.appObservation(app, stage, native, false)
				if err != nil {
					return false, err
				}
				row, err := r.tunnel.manager.View(step.Key)
				if err != nil {
					return false, err
				}
				observation.Pins = uint64(len(row.Consumers))
				observation.Signature = ed25519.Sign(r.Identity.Private, deployment.ObservationBytes(observation))
				index, err := r.sendAppProgressAt(r.ctx, r.newAppProgress(v, app, "observe", step.Key, &observation))
				if err != nil {
					return false, err
				}
				observedFloor = max(observedFloor, index)
				break
			}
		}
	}
	if observedFloor != 0 {
		if err := refresh(observedFloor); err != nil {
			return false, err
		}
	}
	referenceFloor, err := r.reconcileAppNetworkReferences(r.ctx, v, apps)
	if err != nil {
		return false, fmt.Errorf("app network references: %w", err)
	}
	if referenceFloor != 0 {
		if err := refresh(referenceFloor); err != nil {
			return false, err
		}
	}
	ingressFloor, err := r.reconcileManagedIngress(v, projection, apps)
	if err != nil {
		return false, err
	}
	if ingressFloor != 0 {
		if err := refresh(ingressFloor); err != nil {
			return false, err
		}
	}
	if changed, err := r.projectManagedDNS(r.ctx, v); changed || err != nil {
		return false, err
	}
	if changed, err := r.projectAppDNS(r.ctx, v, apps, projection); changed || err != nil {
		return false, err
	}
	if changed, err := r.reconcileAppDNS(r.ctx, v, apps); changed || err != nil {
		return true, err
	}
	return true, nil
}

// Native reconciliation can cross several committed owner reports. Prepare
// against a fresh local view, rather than signing the projection's old CAS.
// The reducer still checks the exact root/app CAS and current authority.
func (r *Runtime) advanceCurrentApps(ctx context.Context) error {
	current, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	apps, err := r.controlPolicy.ReadApps(current.State)
	if err != nil {
		return err
	}
	return r.advanceApps(ctx, current, apps)
}

func (r *Runtime) managedObservation(observation ModuleObservation) (json.RawMessage, error) {
	r.mu.RLock()
	if err := errors.Join(r.moduleError, r.compilerError, r.imageBuildError); err != nil {
		observation.ModuleError = err.Error()
	}
	if r.volumeBackupError != nil {
		observation.VolumeError = r.volumeBackupError.Error()
	}
	r.mu.RUnlock()
	return json.Marshal(observation)
}

func (r *Runtime) observeManaged(ctx context.Context, key string, v cluster.View) (json.RawMessage, error) {
	projection, err := r.controlPolicy.ProjectResources(v.State)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(key, services.ManagedDNSPrefix) {
		owner, err := r.managedDNSObservationOwner(v, key)
		if err != nil {
			return nil, err
		}
		return owner.observeAppDNS(ctx, key, v)
	}
	if owner, found := r.managedObservationOwner(v, projection, key); found && owner != r {
		return owner.observeManaged(ctx, key, v)
	}
	if source, exists := projection.ManagedSources[key]; exists {
		return r.observeManagedNetwork(ctx, key, v, projection, source)
	}
	goal, ok := projection.Goals[key]
	if !ok || goal.Goal.Owner != r.Identity.Public || r.network == nil {
		return nil, errors.New("local managed bridge unavailable")
	}
	o := v.State.Object(key)
	if goal.Goal.Kind == "dns" {
		return r.observeAppDNS(ctx, key, v)
	}
	if goal.Goal.Kind == "task" && r.workload != nil {
		record, e := r.workload.View(key)
		if e != nil {
			return nil, e
		}
		status, e := r.workload.Status(ctx, key)
		observation := ModuleObservation{Schema: 1, Key: key, Local: v.Local, Revision: o.Revision, Generation: o.Generation, NativeID: status.NativeID, Journal: compact(record)}
		observation.Ready = e == nil && status.Ready && record.State.Pending == nil && record.State.Applied.Present && record.State.Applied.Generation == o.Generation && record.State.Desired.Revision == o.Revision && (goal.Goal.Lifecycle == nil || !goal.Goal.Lifecycle.Drain)
		var diagnosticErr error
		observation.CheckerRuns, observation.CheckerRunsTotal, diagnosticErr = r.taskCheckerRuns(deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision})
		if diagnosticErr != nil {
			observation.CheckerError = "local checker diagnostic unavailable"
		}

		if e != nil {
			observation.Error = e.Error()
		}
		return r.managedObservation(observation)
	}
	if goal.Ingress != nil && r.ingress != nil {
		status, e := r.ingress.Observe(key)
		observation := ModuleObservation{Schema: 1, Key: key, Local: v.Local, Revision: o.Revision, Generation: o.Generation, Ingress: &status, Ready: e == nil && status.Ready && status.Revision == o.Revision && status.Generation == o.Generation}
		if e != nil {
			observation.Error = e.Error()
		} else {
			apps, readErr := r.controlPolicy.ReadApps(v.State)
			if readErr != nil {
				return nil, readErr
			}
			observation.NativeID, readErr = r.ingressNativeBinding(v.State, apps, goal.Goal, key, o, *goal.Ingress, false)
			if readErr != nil {
				return nil, readErr
			}
		}
		return r.managedObservation(observation)
	}
	if goal.Tunnel != nil && r.tunnel != nil {
		record, err := r.tunnel.manager.View(key)
		if err != nil {
			return nil, err
		}
		observation := ModuleObservation{Schema: 1, Key: key, Local: v.Local, Revision: o.Revision, Generation: o.Generation, Journal: compact(record)}
		observation.NativeID, err = r.tunnel.manager.Inspect(ctx, key)
		if err == nil {
			err = r.tunnel.Ready(key)
		}
		observation.Ready = err == nil
		if err != nil {
			observation.Error = err.Error()
		}
		status, _ := r.tunnel.Observe(key)
		observation.Tunnel = &status
		return r.managedObservation(observation)
	}
	if goal.Bridge == nil {
		return nil, errors.New("unsupported managed observation")
	}
	record, err := r.network.View(key)
	if err != nil {
		return nil, err
	}
	observation := ModuleObservation{Schema: 1, Key: key, Local: v.Local, Revision: o.Revision, Generation: o.Generation, Journal: compact(record)}
	observation.NativeID, err = r.network.Inspect(ctx, key)
	observation.Ready = err == nil
	if err != nil {
		observation.Error = err.Error()
	}
	return r.managedObservation(observation)
}

// appProgressHoldKey names one app's report stream for the rejection hold.
// A report with an observation (observe, release-inputs, volume-ready) is
// never held: each carries a fresh fact, not a resend of the same one.
func appProgressHoldKey(report control.AppProgress) (string, bool) {
	return "app/" + report.Tenant + "/" + report.App + "/" + report.Action + "/" + report.Key, report.Observation == nil
}

// explainAppFinish names why a finish report is refused on the local view:
// the finish branch first, then the module step or validator check.
func (r *Runtime) explainAppFinish(s state.State, report control.AppProgress) string {
	if why := r.controlPolicy.ExplainAppFinish(s, report); why != "" {
		return why
	}
	cmd, err := report.Command()
	if err != nil {
		return "REPORT_UNRESOLVED"
	}
	if why := r.explainModuleCommand(s, cmd); why != "" {
		return why
	}
	return "UNEXPLAINED"
}
