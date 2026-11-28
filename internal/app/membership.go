// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/reconcile"
)

func (r *Runtime) memberPolicy() control.Policy {
	record := r.installation.record
	return control.Policy{Cluster: record.Root.Cluster, BootstrapKey: record.Admin, TrustRoot: record.Root.TrustRoot, Genesis: record.Genesis}
}
func (r *Runtime) members(ctx context.Context, latest bool) (cluster.View, membership.Directory, error) {
	view, err := r.Engine().Read(ctx, latest)
	if err != nil {
		return view, membership.Directory{}, err
	}
	d, err := r.memberPolicy().Members(view.State)
	return view, d, err
}
func (r *Runtime) memberReport(ctx context.Context, view cluster.View, report control.MemberReport) error {
	report.Schema, report.Cluster, report.Reporter, report.Epoch = 1, r.installation.record.Root.Cluster, r.Identity.Public, view.State.ModuleEpoch()
	report.RootRevision = view.State.Object(control.MembersKey).Revision
	// A different payload/CAS can never reuse another signed report's A1 ID.
	digest := sha256.Sum256(control.MemberReportBytes(report))
	report.RequestID = fmt.Sprintf("member/%s/%s/%x", report.Node, report.Action, digest)
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.MemberReportBytes(report))
	cmd, err := report.Command()
	if err != nil {
		return err
	}
	if !r.Engine().IsLeader() {
		raw, _ := json.Marshal(report)
		reply, err := r.appCall(ctx, "member-report", raw)
		if err != nil {
			return err
		}
		if reply.Committed == nil {
			return fmt.Errorf("member report rejected: %v", reply.Committed)
		}
		return memberReportResult(reply.Committed.Result.Code)
	}
	committed, err := r.Engine().Submit(ctx, cmd)
	if err != nil {
		return err
	}
	return memberReportResult(committed.Result.Code)
}

// errMemberReportStale: the member directory changed between the read and
// the commit (another node's report moved its root revision), so the CAS
// refused the report. Nothing was written.
var errMemberReportStale = errors.New("member report rejected: the member directory changed")

func memberReportResult(code state.Code) error {
	switch code {
	case state.Applied:
		return nil
	case state.ConditionFailed:
		return errMemberReportStale
	}
	return fmt.Errorf("member report rejected: %d", code)
}
func memberTarget(entry membership.Entry) (config.Peer, error) {
	if entry.Job.Pending == nil {
		return config.Peer{}, membership.ErrMember
	}
	var target config.Peer
	if json.Unmarshal([]byte(entry.Job.Pending.Target.Spec), &target) != nil {
		return target, membership.ErrMember
	}
	return target, nil
}
func nativeHas(c cluster.InstalledConfiguration, target config.Peer) bool {
	for _, server := range c.Configuration.Servers {
		if string(server.ID) == target.ID {
			return string(server.Address) == target.Endpoint && (server.Suffrage == raft.Voter && target.Voter || server.Suffrage == raft.Nonvoter && !target.Voter)
		}
	}
	return false
}

// nativeNamed reports whether any server in c has id, whatever its
// address or suffrage.
func nativeNamed(c cluster.InstalledConfiguration, id string) bool {
	for _, server := range c.Configuration.Servers {
		if string(server.ID) == id {
			return true
		}
	}
	return false
}

// advanceMember serializes effects locally. Only THIS invocation that commits a
// Prepared->Dispatched transition may call the SDK, once. All later invocations
// inspect the original effect and never invoke it again, even after a restart.
func (r *Runtime) advanceMember(ctx context.Context, id string, joining bool) error {
	r.memberMu.Lock()
	defer r.memberMu.Unlock()
	view, d, err := r.members(ctx, true)
	if err != nil {
		return err
	}
	entry, ok := d.Entry(id)
	if !ok {
		return membership.ErrMember
	}
	if entry.Job.Pending == nil {
		return nil
	}
	target, err := memberTarget(entry)
	if err != nil {
		return err
	}
	var nativeErr error
	if entry.Job.Pending.Phase == reconcile.Prepared {
		if entry.Phase == membership.Invited && !joining {
			return nil
		}
		if entry.Voting != nil {
			if err := r.memberPolicy().CheckVotingEffect(view.State, id); err != nil {
				return err
			}
			if entry.Phase == membership.Demoting && id == r.installation.record.Root.Self.ID {
				topology, err := d.Topology()
				if err != nil {
					return err
				}
				for _, member := range topology.Configuration().Members {
					if member.ID == id || !member.Voter || !topology.AdmitWork(member.ID) {
						continue
					}
					peer, found := d.Entry(member.ID)
					if found {
						return r.Engine().TransferLeadership(ctx, member.ID, peer.Peer.Endpoint)
					}
				}
				return errors.New("no active installed voter can receive leadership before demotion")
			}
		}
		installed, err := r.Engine().InstalledConfiguration(ctx, true)
		if err != nil {
			return err
		}
		if nativeHas(installed, target) {
			return errors.New("prepared member target already exists outside its dispatch")
		}
		if err = r.memberReport(ctx, view, control.MemberReport{Action: "dispatch", Node: id, Expected: entry.Revision, JobID: entry.Job.Pending.ID, ConfigurationIndex: installed.Index}); err != nil {
			return err
		}
		// Dispatch success grants one call here; an uncertain Submit never does.
		// This context belongs to runtime work, not the client's stream lifetime.
		if entry.Phase == membership.Demoting {
			nativeErr = r.Engine().DemoteMember(ctx, target.ID, installed.Index)
		} else {
			nativeErr = r.Engine().ChangeMember(ctx, target, installed.Index)
		}
	}
	// Success is established by actual installed bytes/index, not the SDK return.
	view, d, err = r.members(ctx, true)
	if err != nil {
		return err
	}
	entry, ok = d.Entry(id)
	if !ok || entry.Job.Pending == nil {
		return nil
	}
	installed, err := r.Engine().InstalledConfiguration(ctx, true)
	if err == nil && installed.Index > entry.BaseIndex && nativeHas(installed, target) {
		return r.memberReport(ctx, view, control.MemberReport{Action: "observe", Node: id, Expected: entry.Revision, JobID: entry.Job.Pending.ID, ConfigurationIndex: installed.Index, Peer: target})
	}
	// A join whose result is unknown, and whose server is not in the
	// committed configuration read behind a barrier, never happened: the
	// add was conditioned on BaseIndex and is sent once. Settle it so the
	// join can be retried or the invitation cancelled (else the name and
	// every later membership change wait forever).
	if err == nil && entry.Phase == membership.Invited && entry.Job.Pending.Phase == reconcile.RecoveryRequired && installed.Index >= entry.BaseIndex && !nativeNamed(installed, target.ID) {
		return r.memberReport(ctx, view, control.MemberReport{Action: "absent", Node: id, Expected: entry.Revision, JobID: entry.Job.Pending.ID, ConfigurationIndex: installed.Index})
	}
	if entry.Job.Pending.Phase == reconcile.Dispatched {
		if reportErr := r.memberReport(ctx, view, control.MemberReport{Action: "unknown", Node: id, Expected: entry.Revision, JobID: entry.Job.Pending.ID}); reportErr != nil {
			return reportErr
		}
	}
	return fmt.Errorf("%w: native=%v; observation=%v; installed=%d; original=%d", cluster.ErrUnknown, nativeErr, err, installed.Index, entry.BaseIndex)
}
func (r *Runtime) memberLoop() {
	defer r.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
		case <-r.Engine().Changes():
		}
		var rotationErr error
		timedMemberStep("identity rotation", func() { rotationErr = r.advanceIdentityRotation(r.ctx) })
		if rotationErr != nil {
			r.recordIdentityFailure(r.ctx)
		}
		select {
		case <-r.identityRestart:
			return
		default:
		}
		// These steps share one loop: a step that blocks holds back every
		// later one (builtin vault upkeep included), so a slow step is logged.
		timedMemberStep("image cache", func() { r.advanceImageCache(r.ctx) })
		timedMemberStep("registry maintenance", func() { r.advanceRegistryMaintenance(r.ctx) })
		timedMemberStep("tunnel reconnects", func() { r.advanceTunnelReconnects(r.ctx) })
		timedMemberStep("compactions", func() { r.advanceCompactions(r.ctx) })
		masterCtx, masterCancel := context.WithTimeout(r.ctx, 10*time.Second)
		r.advanceCertificateMaster(masterCtx)
		masterCancel()
		vaultCtx, vaultCancel := context.WithTimeout(r.ctx, 30*time.Second)
		timedMemberStep("builtin vault upkeep", func() { r.advanceBuiltinVault(vaultCtx) })
		vaultCancel()
		if !r.Engine().IsLeader() {
			continue
		}
		ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
		r.advanceNodeDrains(ctx)
		_, d, err := r.members(ctx, false)
		if err == nil {
			for _, entry := range d.Entries {
				if entry.Job.Pending != nil && (entry.Phase == membership.Promoting || entry.Phase == membership.Demoting || entry.Phase == membership.Moving || entry.Job.Pending.Phase != reconcile.Prepared) {
					_ = r.advanceMember(ctx, entry.Peer.ID, false)
				}
				if ctx.Err() != nil {
					break
				}
			}
			for _, entry := range d.Entries {
				if entry.Abort != nil && ctx.Err() == nil {
					if err := r.advanceAbortJoin(ctx, entry.Peer.ID); err != nil {
						log.Printf("membership: abort join of %s: %v", entry.Peer.ID, err)
					}
				}
			}
			if ctx.Err() == nil {
				_ = r.syncMemberConfiguration(ctx)
			}
			// Refresh after join/configuration reports; a removal always consumes
			// the current original job and the actually installed voting prefix.
			if ctx.Err() == nil {
				_, current, readErr := r.members(ctx, false)
				if readErr == nil && current.Runtime != nil {
					for _, operation := range current.Runtime.Operations {
						if operation.Job.Pending != nil {
							_ = r.advanceNodeRemoval(ctx, operation.ID)
						}
						if ctx.Err() != nil || !r.Engine().IsLeader() {
							break
						}
					}
				}
			}
		}
		cancel()
	}
}

// advanceAbortJoin removes an aborting learner from Raft, then reports the
// committed configuration without it so its entry and name are forgotten.
func (r *Runtime) advanceAbortJoin(ctx context.Context, id string) error {
	r.memberMu.Lock()
	defer r.memberMu.Unlock()
	view, d, err := r.members(ctx, true)
	if err != nil {
		return err
	}
	entry, ok := d.Entry(id)
	if !ok || entry.Abort == nil {
		return nil
	}
	installed, err := r.Engine().InstalledConfiguration(ctx, true)
	if err != nil {
		return err
	}
	if nativeNamed(installed, id) {
		// The previous-index CAS keeps this to the configuration just read.
		if err := r.Engine().RemoveMember(ctx, id, installed.Index); err != nil {
			return err
		}
		if installed, err = r.Engine().InstalledConfiguration(ctx, true); err != nil {
			return err
		}
		if nativeNamed(installed, id) {
			return errors.New("still in the Raft configuration")
		}
	}
	if installed.Index <= entry.NativeIndex {
		return nil
	}
	return r.memberReport(ctx, view, control.MemberReport{Action: "join-aborted", Node: id, Expected: entry.Revision, ConfigurationIndex: installed.Index})
}

// memberStepSlow is how long one member-loop step may take before it is
// logged as holding back the steps after it.
const memberStepSlow = 45 * time.Second

func timedMemberStep(name string, step func()) {
	started := time.Now()
	// A step that never returns is reported while it still runs.
	slow := time.AfterFunc(memberStepSlow, func() {
		log.Printf("member loop: %s still running after %s; later steps wait", name, memberStepSlow)
	})
	step()
	if !slow.Stop() {
		log.Printf("member loop: %s took %s", name, time.Since(started).Round(time.Second))
	}
}
