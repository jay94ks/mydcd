// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// IdentityRestart becomes readable only after the original shared activation
// and durable local Root/key selection. The daemon closes its old transport and
// opens that selector again; no caller can install a supplied replacement key.
func (r *Runtime) IdentityRestart() <-chan struct{} { return r.identityRestart }
func (r *Runtime) advanceIdentityRotation(ctx context.Context) error {
	if r.installation == nil || r.historicalOwner {
		return nil
	}
	view, d, err := r.members(ctx, false)
	if err != nil {
		return err
	}
	for _, row := range d.Rotations {
		if row.Node != r.installation.record.Root.Self.ID || row.Phase == "Installed" {
			continue
		}
		switch row.Phase {
		case "Preparing":
			if err = r.controlPolicy.CheckIdentityEffect(view.State, row); err != nil {
				return err
			}
			proof, err := bootstrap.PrepareIdentityRotation(r.installation.config, row.Operation)
			if err != nil {
				return err
			}
			return r.memberReport(ctx, view, control.MemberReport{Action: "identity-prepared", Node: row.Node, Operation: row.Operation, Expected: d.Revision, Identity: &proof})
		case "Prepared":
			if r.Engine().IsLeader() {
				topology, err := d.Topology()
				if err != nil {
					return err
				}
				if topology.Configuration().Voters() > 1 {
					for _, member := range topology.Configuration().Members {
						if member.ID == row.Node || !member.Voter || !topology.AdmitWork(member.ID) {
							continue
						}
						entry, ok := d.Entry(member.ID)
						if ok {
							return r.Engine().TransferLeadership(ctx, member.ID, entry.Peer.Endpoint)
						}
					}
					return control.ErrCatalog
				}
			}
			if err = r.controlPolicy.CheckIdentityEffect(view.State, row); err != nil {
				return err
			}
			submitErr := r.memberReport(ctx, view, control.MemberReport{Action: "identity-activate", Node: row.Node, Operation: row.Operation, Expected: d.Revision})
			if r.Engine().IsLeader() {
				return submitErr
			}
			// The leader revokes the old TLS key when activation commits. The
			// follower may still have only Prepared because commit notification
			// uses that now-revoked connection. Recover with the prepared NEW key.
			if recoverErr := r.recoverIdentityActivation(ctx, row); recoverErr != nil {
				return errors.Join(submitErr, recoverErr)
			}
			return nil
		case "Activated":
			if row.Proof.New == r.Identity.Public {
				// The new runtime has opened the committed Root, native owner namespaces
				// and TLS certificate before attesting installed.
				return r.memberReport(ctx, view, control.MemberReport{Action: "identity-installed", Node: row.Node, Operation: row.Operation, Expected: d.Revision})
			}
			// Shared activation can precede a crash/lost report response. The original
			// local preparation receipt and committed prefix recover that same switch.
			if _, err = bootstrap.ActivateIdentityRotation(r.installation.config, *row.Proof, row.ActivatedIndex); err != nil {
				return err
			}
			r.identityRestartOnce.Do(func() { close(r.identityRestart) })
		}
	}
	return nil
}

func (r *Runtime) recordIdentityFailure(ctx context.Context) {
	view, d, err := r.members(ctx, false)
	if err != nil {
		return
	}
	for _, row := range d.Rotations {
		if row.Node != r.installation.record.Root.Self.ID || row.Phase != "Preparing" && row.Phase != "Prepared" {
			continue
		}
		code := "IDENTITY_PREPARE_FAILED"
		if row.Phase == "Prepared" {
			code = "IDENTITY_ACTIVATE_FAILED"
		}
		if row.Failure != code {
			_ = r.memberReport(ctx, view, control.MemberReport{Action: "identity-failed", Node: row.Node, Operation: row.Operation, Expected: d.Revision, IdentityFailure: code})
		}
		return
	}
}
