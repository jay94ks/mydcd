// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

type AppDeliveryWorkRequest struct {
	Tenant, App string
	At          uint64
	TargetCAS   bool `json:",omitempty"`
}
type AppDeliveryWork struct {
	Schema                        uint8
	Cluster, Reader               [32]byte
	Tenant, App, Action, Reason   string
	RootRevision, Revision, Epoch uint64
	Choice                        *AppDeliveryChoice `json:",omitempty"`
	Target                        *[32]byte          `json:",omitempty"`
}

// AppDeliverySyncWork previews the SAME deterministic transition the report
// reducer will apply. Known blocked/stale/healthy conditions propose no denied
// log entries; this read is not a grant to submit native work directly.
func (p Policy) AppDeliverySyncWork(s state.State, caller [32]byte, q AppDeliveryWorkRequest) (AppDeliveryWork, error) {
	out := AppDeliveryWork{Schema: 1, Cluster: p.Cluster, Reader: caller, Tenant: q.Tenant, App: q.App, RootRevision: s.Object(AppsKey).Revision, Epoch: s.ModuleEpoch()}
	members, err := p.Members(s)
	if err != nil || !members.WorkKey(caller) || q.At == 0 || q.At > math.MaxInt64 {
		return out, ErrCatalog
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return out, err
	}
	entry, exists := a.entries[appKey(q.Tenant, q.App)]
	if !exists || entry.Delivery == nil {
		return out, ErrCatalog
	}
	d := *entry.Delivery
	out.Revision = d.Revision()
	if q.TargetCAS {
		target := appSyncTarget(entry)
		out.Target = &target
	}
	if entry.PendingSync != nil && entry.PendingSync.Recreate != nil {
		out.Reason = "explicit-user-recreation"
		return out, nil
	}
	if t, pending := d.Transition(); pending {
		if t.Phase == "ready" {
			if _, err := p.continueCDSync(s, entry, q.At); err == nil {
				out.Action = "continue"
			} else {
				out.Reason = "transition-blocked"
			}
		} else {
			out.Reason = "retiring-original"
		}
		return out, nil
	}
	if d.Rejected() {
		out.Reason = "candidate-rejected"
		return out, nil
	}
	if (d.Policy().Sync.Mode != "automatic" && entry.CDDecision == nil) || d.Paused() || d.SourceError() != "" || entry.Down != nil {
		out.Reason = "awaiting-explicit-policy"
		return out, nil
	}
	volumes, err := p.Volumes(s)
	if err != nil || volumes.appMovePending(q.Tenant, q.App) {
		out.Reason = "explicit-volume-move"
		return out, nil
	}
	c, ctx, err := p.appDeliveryAccessFromApps(s, a, entry)
	if err != nil {
		out.Reason = "current-authority"
		return out, nil
	}
	if d.Policy().Sync.Mode != "automatic" && !acceptedCDApproval(c, entry) {
		out.Reason = "awaiting-candidate-approval"
		return out, nil
	}
	selected, candidate := d.CandidateSelection()
	if !candidate || selected.Commit == "" {
		out.Reason = "awaiting-git-source"
		return out, nil
	}
	status, err := d.Status(c, ctx, q.At)
	if err != nil {
		out.Reason = "current-inputs"
		return out, nil
	}
	if status.EffectiveSync == "InSync" && d.CandidateApplied() {
		out.Reason = "in-sync"
		return out, nil
	}
	if e, active := entry.Inventory.Execution(); active {
		if e.Status() != "Succeeded" || status.Health != "Healthy" {
			out.Reason = "original-health-or-work"
			return out, nil
		}
	} else if !entry.Inventory.Quiescent() {
		out.Reason = "original-not-closed"
		return out, nil
	}
	// A semantic report selects the original source intent and rebases its
	// incidental coordinates inside the SAME accepted transaction. Legacy
	// requests retain their original two-pass replan behavior and identities.
	preview := d
	if q.TargetCAS {
		preview, err = d.RebaseCandidate(d.Revision(), c, ctx)
		if err != nil {
			if _, replanErr := d.Replan(d.Revision(), c, ctx); replanErr == nil {
				out.Action = "replan"
			} else {
				out.Reason = "source-or-policy"
			}
			return out, nil
		}
	} else {
		replanned, replanErr := d.Replan(d.Revision(), c, ctx)
		if replanErr != nil {
			out.Reason = "source-or-policy"
			return out, nil
		}
		if replanned.Revision() != d.Revision() {
			out.Action = "replan"
			return out, nil
		}
	}
	registration := appRegistrationDigest(entry.Origin)
	raw, _ := json.Marshal(struct {
		Registration, Candidate [32]byte
		Epoch                   uint64
	}{registration, selected.Candidate, s.ModuleEpoch()})
	id := sha256.Sum256(append([]byte("sfc-automatic-sync-1\x00"), raw...))
	choice := AppDeliveryChoice{Operation: "cd-" + hex.EncodeToString(id[:24]), Candidate: selected.Candidate, Registration: registration}
	// The preview needs an original signed member report for acceptance; the
	// immutable core can be checked directly here without forging that proof.
	b, _ := preview.CandidateBlueprint()
	identity, err := appExecutionOrigin(entry.Origin, entry.Sync, entry.Inventory.Scope())
	if err != nil || p.authorizeCDSelection(s, c, entry, b, nil, entry.Local) != nil {
		out.Reason = "source-scope"
		return out, nil
	}
	if p.checkCDGroupApprovals(s, c, entry, b, int64(q.At)) != nil {
		out.Reason = "group-approval"
		return out, nil
	}
	if _, err = preview.SyncAutomatic(preview.Revision(), c, ctx, choice.Operation, identity.Submitter, s.ModuleEpoch()); err != nil {
		out.Reason = "explicit-recovery-or-closure"
		return out, nil
	}
	out.Action, out.Choice = "auto-sync", &choice
	return out, nil
}
