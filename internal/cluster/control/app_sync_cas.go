// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/deployment"
)

// AppSyncCASAllowed derives the mode from the signed payload. An absent Target
// remains the original strict revision/root CAS; no operation is upgraded when
// it is loaded from a journal or replayed from a snapshot.
func AppSyncCASAllowed(change Change) bool {
	var q AppCDChange
	return (change.Action == "sync-app" || change.Action == "recover-app") && change.Expected > 0 &&
		canonical(change.Payload, &q) == nil && q.Target != nil && *q.Target != ([32]byte{}) &&
		q.Tenant != "" && q.App != "" && q.Choice != nil && q.Policy == nil && q.PolicyRevision == 0
}

// AppCDTargetCASAllowed uses the same signed intent target for configuration
// and explicit reconsideration of the selected candidate.
// Configuration still requires its exact policy revision; source/health counters
// cannot turn an otherwise unchanged intent into a competing policy writer.
func AppCDTargetCASAllowed(change Change) bool {
	if AppSyncCASAllowed(change) {
		return true
	}
	var q AppCDChange
	if change.Expected == 0 || canonical(change.Payload, &q) != nil || q.Target == nil || *q.Target == ([32]byte{}) || q.Tenant == "" || q.App == "" || q.Choice != nil {
		return false
	}
	return change.Action == "configure-app-cd" && q.Policy != nil && q.PolicyRevision > 0 ||
		change.Action == "replan-app" && q.Policy == nil && q.PolicyRevision == 0
}

// appSyncTarget captures selection and execution/lifetime intent, never source
// tickets, freshness reports or their revision counters. Admission still uses
// the current authority, placement, claims and writer gates in acceptCDSync.
func appSyncTarget(entry appEntry) [32]byte {
	if entry.Delivery == nil {
		return [32]byte{}
	}
	d := *entry.Delivery
	var target struct {
		Decision                         *[32]byte `json:",omitempty"`
		Registration                     [32]byte
		Sync, Pending                    *AppDeliverySync
		Down                             *UserOperation
		Policy                           deployment.DeliveryDeclaration
		PolicyRevision, OverrideRevision uint64
		Paused, Quiescent                bool
		Candidate, Running               *deployment.DeliverySelection
		Transition                       *deployment.DeliveryTransition
		Active, Compacted                *deployment.OperationSummary
		Retirement                       *struct {
			ID, Actor, Submitter string
			Epoch                uint64
			Down                 bool
		}
	}
	if entry.CDDecision != nil {
		digest := entry.CDDecision.digest()
		target.Decision = &digest
	}
	target.Registration = appRegistrationDigest(entry.Origin)
	target.Sync, target.Pending, target.Down = entry.Sync, entry.PendingSync, entry.Down
	target.Policy, target.PolicyRevision, target.OverrideRevision = d.Policy(), d.PolicyRevision(), d.OverrideRevision()
	target.Paused, target.Quiescent = d.Paused(), entry.Inventory.Quiescent()
	if v, ok := d.CandidateSelection(); ok {
		target.Candidate = &v
	}
	if v, ok := d.Selection(); ok {
		target.Running = &v
	}
	if v, ok := d.Transition(); ok {
		target.Transition = &v
	}
	if v, ok := entry.Inventory.Active(); ok {
		v.CompletedAt = 0
		target.Active = &v
	}
	if entry.Compacted != nil {
		v := *entry.Compacted
		v.CompletedAt = 0
		target.Compacted = &v
	}
	if v, ok := entry.Inventory.Retirement(); ok {
		target.Retirement = &struct {
			ID, Actor, Submitter string
			Epoch                uint64
			Down                 bool
		}{v.ID, v.Actor, v.Submitter, v.Epoch, v.Down}
	}
	raw, err := json.Marshal(target)
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(append([]byte("sfc-app-sync-target-1\x00"), raw...))
}
