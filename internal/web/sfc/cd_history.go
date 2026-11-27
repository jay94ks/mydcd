// SPDX-License-Identifier: Apache-2.0

package sfc

import "encoding/json"

// REQ-46 (mock): CD candidate/run history, a field's Git and current
// values, and what the candidate changes. Read-only; tenant Read on the app.

// Results of a CD history row.
const (
	CDCandidate = "candidate" // planned, not applied
	CDRunning   = "running"
	CDSucceeded = "succeeded"
	CDFailed    = "failed"
	CDAbandoned = "abandoned"
	CDBlocked   = "blocked" // Reason = AppCD.Blocked
)

// CDHistoryRow: one candidate, newest first.
type CDHistoryRow struct {
	Commit          string
	CandidateDigest [32]byte
	PlannedAt       int64
	Result          string
	Reason          string `json:",omitempty"`
	Operation       string `json:",omitempty"` // deploy operation that applied it
	FinishedAt      int64  `json:",omitempty"`
	Actor           string `json:",omitempty"` // REQ-25 approver / rejecter
	Note            string `json:",omitempty"` // REQ-25 approve reason (reject: Reason)
}

// CDFieldValues: one overridable field (the app-cd-field path) in Git at
// the running and candidate commits, and the value now in force (the
// override's when there is one). A value that comes from a secret
// projection is never returned: Secrets names the selectors instead.
type CDFieldValues struct {
	Tenant, App  string
	Path         []string
	Running      string          `json:",omitempty"` // commit
	Candidate    string          `json:",omitempty"`
	GitRunning   json.RawMessage `json:",omitempty"` // absent: not in Git
	GitCandidate json.RawMessage `json:",omitempty"`
	Current      json.RawMessage `json:",omitempty"`
	Overridden   bool
	Secrets      []string `json:",omitempty"` // secrets_from selectors
}

// CDChanges: running commit → candidate.
type CDChanges struct {
	Tenant, App        string
	Running, Candidate string
	Services           []CDServiceChange
	Added, Removed     []string // services
	Count              int      // = AppCD.ChangeCount
}

type CDServiceChange struct {
	Service string
	Fields  []CDFieldChange
}

type CDFieldChange struct {
	Path          []string        // from the document root (services, <svc>, ...)
	Before, After json.RawMessage `json:",omitempty"` // absent: added / removed
}
