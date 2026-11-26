// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/reconcile"
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
		if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
			return fmt.Errorf("member report rejected: %v", reply.Committed)
		}
		return nil
	}
	committed, err := r.Engine().Submit(ctx, cmd)
	if err != nil {
		return err
	}
	if committed.Result.Code != state.Applied {
		return fmt.Errorf("member report rejected: %d", committed.Result.Code)
	}
	return nil
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
		if err := r.advanceIdentityRotation(r.ctx); err != nil {
			r.recordIdentityFailure(r.ctx)
		}
		select {
		case <-r.identityRestart:
			return
		default:
		}
		r.advanceImageCache(r.ctx)
		r.advanceRegistryMaintenance(r.ctx)
		r.advanceTunnelReconnects(r.ctx)
		r.advanceCompactions(r.ctx)
		masterCtx, masterCancel := context.WithTimeout(r.ctx, 10*time.Second)
		r.advanceCertificateMaster(masterCtx)
		masterCancel()
		if !r.Engine().IsLeader() {
			continue
		}
		ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
		r.advanceNodeDrains(ctx)
		_, d, err := r.members(ctx, false)
		if err == nil {
			for _, entry := range d.Entries {
				if entry.Job.Pending != nil && (entry.Phase == membership.Promoting || entry.Phase == membership.Demoting || entry.Job.Pending.Phase != reconcile.Prepared) {
					_ = r.advanceMember(ctx, entry.Peer.ID, false)
				}
				if ctx.Err() != nil {
					break
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
