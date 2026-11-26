// SPDX-License-Identifier: Apache-2.0

package mydc

import "github.com/jay94ks/mydcd/internal/cluster/control"

// CD events in the events cursor (the fake's fixture), approve/reject of a
// candidate with a signed reason, and a per-app approver grant for the
// web's delegated approval account. Events and reasons never hold secret or
// environment values.

// FixtureEvent kinds (FixtureEvent.Kind; FixtureEvent.CD holds the details).
const (
	EventCDCandidateCreated = "cd-candidate-created"
	EventCDApprovalRequired = "cd-approval-required"
	EventCDApproved         = "cd-approved"
	EventCDRejected         = "cd-rejected"
	EventCDSyncStarted      = "cd-sync-started"
	EventCDSyncSucceeded    = "cd-sync-succeeded"
	EventCDSyncFailed       = "cd-sync-failed"
	EventCDDriftDetected    = "cd-drift-detected"
	EventCDPaused           = "cd-paused"
	EventCDResumed          = "cd-resumed"
	EventCDRolledBack       = "cd-rolled-back"
)

// CDEvent: the common part of a cd-* event. From/To are the running and
// candidate commits.
type CDEvent struct {
	CandidateID string // hex of AppCD.CandidateDigest
	Commit      string
	FromVersion string `json:",omitempty"`
	ToVersion   string `json:",omitempty"`
	Actor       string `json:",omitempty"` // username
	Code        string `json:",omitempty"`
	Reason      string `json:",omitempty"`
}

const (
	ActionApproveAppCD    = "cd-approve"
	ActionRejectAppCD     = "cd-reject"
	ActionGrantCDApprover = "grant-cd-approver"
	ActionDropCDApprover  = "revoke-cd-approver"
)

// CDRejected: a history row result; the commit does not come back as the
// candidate until a new commit or replan-app.
const CDRejected = "rejected"

// CDDecision: cd-approve / cd-reject. Expected = the CD revision (Strict:
// exactly it); Candidate = AppCD.CandidateDigest, Target = AppCD.Target.
// The reason is the signed op's reason (≤ 512). Permission: ManageCD, or a
// per-app approver (AppCD.Approvers) who can read the tenant. mydcd runs an
// approved candidate itself.
type CDDecision = control.AppCDDecisionChange

// CDApproverGrant: grant-cd-approver / revoke-cd-approver (ManageCD).
// Expected = the CD revision; User is a user ID. The grant allows
// approve/reject of this app's candidates and nothing else (no vault
// approvals, no sync or pause).
type CDApproverGrant = control.AppCDApproverChange
