// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

const maxCDHistory = 128
const maxCDSnapshot = 16 << 20

// Candidate history is bounded public metadata in the same app checkpoint.
// It is not an execution receipt, event journal or retained source artifact.
type AppCDHistoryRecord struct {
	LocalRevision                        uint64 `json:",omitempty"`
	LocalActor                           string `json:",omitempty"`
	Sequence                             uint64
	Identity, Candidate, LatestCandidate [32]byte
	Artifact, Intent                     [32]byte
	Commit, Operation, Status, Code      string
	Actor, Reason                        string
	PlannedAt, CompletedAt               uint64 // Unix seconds; zero means original time unavailable
}

func cdHistoryIdentity(d deployment.Delivery, v deployment.DeliverySelection) [32]byte {
	raw, _ := json.Marshal(struct {
		Artifact, Intent [32]byte
		Commit           string
	}{v.Artifact, v.Intent, v.Commit})
	return sha256.Sum256(append([]byte("sfc-cd-history-intent-1\x00"), raw...))
}

func captureCDHistory(entry, prior appEntry, at uint64) (appEntry, error) {
	if entry.Delivery == nil {
		return entry, nil
	}
	d := *entry.Delivery
	entry.CDHistory = slices.Clone(entry.CDHistory)
	current, selected := d.CandidateSelection()
	running, executing := d.Selection()
	// Terminal operation facts survive later down/prune/metadata-only polls.
	for i := range entry.CDHistory {
		row := &entry.CDHistory[i]
		if row.Operation != "" {
			if result, ok := entry.Inventory.Operation(row.Operation); ok {
				switch {
				case result.Failed || result.Status == "Failed":
					row.Status = "failed"
				case result.CompletedAt != 0:
					row.Status = "succeeded"
				default:
					row.Status = "executing"
				}
				if row.CompletedAt == 0 && result.CompletedAt != 0 {
					row.CompletedAt = result.CompletedAt
				}
			}
		} else if row.Status == "candidate" || row.Status == "blocked" {
			row.Status, row.Code = "discarded", "SUPERSEDED_CANDIDATE"
		}
	}
	ensure := func(v deployment.DeliverySelection, operation string, candidate bool) error {
		identity := cdHistoryIdentity(d, v)
		index := -1
		for i := len(entry.CDHistory) - 1; i >= 0; i-- {
			row := entry.CDHistory[i]
			if row.Identity == identity && (row.Operation == operation || row.Operation == "" && operation != "") {
				index = i
				break
			}
		}
		if index < 0 {
			if entry.CDHistoryNext == ^uint64(0) {
				return ErrCatalog
			}
			entry.CDHistoryNext++
			planned := at
			// A pre-existing candidate discovered while upgrading is not newly
			// planned at the time of this unrelated signed change.
			if prior.Delivery != nil {
				if old, ok := prior.Delivery.CandidateSelection(); ok && old.Candidate == v.Candidate {
					planned = 0
				}
				if old, ok := prior.Delivery.Selection(); ok && old.Candidate == v.Candidate {
					planned = 0
				}
			}
			entry.CDHistory = append(entry.CDHistory, AppCDHistoryRecord{Sequence: entry.CDHistoryNext, Identity: identity, Candidate: v.Candidate, LatestCandidate: v.Candidate, Artifact: v.Artifact, Intent: v.Intent, Commit: v.Commit, PlannedAt: planned, Status: "candidate"})
			index = len(entry.CDHistory) - 1
		}
		row := &entry.CDHistory[index]
		row.LatestCandidate = v.Candidate
		if candidate && entry.LocalEdit != nil && row.Operation == "" {
			row.LocalRevision, row.LocalActor = d.LocalRevision(), entry.LocalEdit.Session.User
		}
		if decision := entry.CDDecision; decision != nil && decision.Selection.Artifact == v.Artifact && decision.Selection.Intent == v.Intent && decision.Selection.Commit == v.Commit {
			row.Actor = decision.Origin.Session.User
			if decision.Origin.Reason != nil {
				row.Reason = decision.Origin.Reason.Text
			}
		}
		if operation != "" {
			row.Operation = operation
			row.Status, row.Code = "executing", ""
			if result, ok := entry.Inventory.Operation(operation); ok {
				if result.Failed || result.Status == "Failed" {
					row.Status = "failed"
				} else if result.CompletedAt != 0 {
					row.Status, row.CompletedAt = "succeeded", result.CompletedAt
				}
			}
		} else if candidate && row.Operation == "" {
			row.Status, row.Code = "candidate", ""
			if d.Rejected() {
				row.Status, row.Code = "blocked", "CD_CANDIDATE_REJECTED"
			} else if d.SourceError() != "" {
				row.Status, row.Code = "blocked", d.SourceError()
			}
		}
		return nil
	}
	if executing {
		if err := ensure(running, running.Operation, false); err != nil {
			return entry, err
		}
	}
	if selected {
		operation := ""
		if executing && cdHistoryIdentity(d, current) == cdHistoryIdentity(d, running) {
			operation = running.Operation
		}
		if err := ensure(current, operation, true); err != nil {
			return entry, err
		}
	}
	if len(entry.CDHistory) > maxCDHistory {
		entry.CDHistory = slices.Clone(entry.CDHistory[len(entry.CDHistory)-maxCDHistory:])
	}
	return entry, nil
}

func validCDHistory(entry appEntry) bool {
	if len(entry.CDHistory) > maxCDHistory || entry.Delivery == nil && len(entry.CDHistory) != 0 {
		return false
	}
	previous := uint64(0)
	for _, row := range entry.CDHistory {
		if (row.LocalRevision == 0) != (row.LocalActor == "") || row.LocalActor != "" && !lifecycle.ValidID(row.LocalActor) {
			return false
		}
		if row.Actor != "" && !lifecycle.ValidID(row.Actor) || !(OperationReason{Text: row.Reason}).Valid() || row.Status == "succeeded" && (row.Operation == "" || row.CompletedAt == 0) {
			return false
		}
		if row.Sequence <= previous || row.Sequence > entry.CDHistoryNext || row.Identity == ([32]byte{}) || row.Candidate == ([32]byte{}) || row.LatestCandidate == ([32]byte{}) || row.Artifact == ([32]byte{}) || row.Intent == ([32]byte{}) || row.Commit != "" && (len(row.Commit) != 40 || !lowerHex(row.Commit)) || row.Operation != "" && !lifecycle.ValidID(row.Operation) || len(row.Code) > 128 {
			return false
		}
		switch row.Status {
		case "candidate", "executing", "succeeded", "failed", "discarded", "blocked":
		default:
			return false
		}
		previous = row.Sequence
	}
	return true
}

type AppCDReadRequest struct {
	App    string
	Part   int
	Digest [32]byte
}

func (q AppCDReadRequest) Valid(history bool) bool {
	return lifecycle.ValidID(q.App) && q.Part >= 0 && q.Part < (maxCDSnapshot+deployment.ArtifactPartBytes-1)/deployment.ArtifactPartBytes && (!history || q.Part == 0 && q.Digest == ([32]byte{})) && (q.Part == 0 || q.Digest != ([32]byte{}))
}

type AppCDHistoryPage struct {
	Schema      uint8
	Tenant, App string
	Records     []AppCDHistoryRecord
	Next        string
	First, Last uint64
	Truncated   bool // older metadata was evicted, not missing execution receipts
}

type AppCDSnapshotPart struct {
	Schema       uint8
	Tenant, App  string
	Kind         string
	Part, Length int
	Digest       [32]byte
	Data         []byte
}

func cdSnapshotPart(tenant, app, kind string, q AppCDReadRequest, value any) (AppCDSnapshotPart, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxCDSnapshot || !q.Valid(false) {
		return AppCDSnapshotPart{}, access.ErrInvalid
	}
	digest := sha256.Sum256(raw)
	if q.Digest != ([32]byte{}) && q.Digest != digest {
		return AppCDSnapshotPart{}, access.ErrConflict
	}
	start := q.Part * deployment.ArtifactPartBytes
	if start >= len(raw) {
		return AppCDSnapshotPart{}, access.ErrInvalid
	}
	return AppCDSnapshotPart{Schema: 1, Tenant: tenant, App: app, Kind: kind, Part: q.Part, Length: len(raw), Digest: digest, Data: bytes.Clone(raw[start:min(start+deployment.ArtifactPartBytes, len(raw))])}, nil
}

func (p Policy) AppDeliveryHistory(s state.State, session access.Session, at int64, tenant string, q AppCDReadRequest, after string) (AppCDHistoryPage, error) {
	if !q.Valid(true) {
		return AppCDHistoryPage{}, access.ErrInvalid
	}
	entry, err := p.appSourceEntry(s, session, at, tenant, AppSourceSelection{App: q.App})
	if err != nil || entry.Delivery == nil {
		return AppCDHistoryPage{}, access.ErrDenied
	}
	basisBytes, _ := json.Marshal(struct {
		User, Tenant, App string
		Catalog, Members  uint64
		History           []AppCDHistoryRecord
	}{session.User, tenant, q.App, s.Object(CatalogKey).Revision, s.Object(MembersKey).Revision, entry.CDHistory})
	basis := sha256.Sum256(append([]byte("sfc-cd-history-page-1\x00"), basisBytes...))
	offset, err := taskCursor(after, basis)
	if err != nil || uint64(offset) > uint64(len(entry.CDHistory)) {
		return AppCDHistoryPage{}, access.ErrInvalid
	}
	page := AppCDHistoryPage{Schema: 1, Tenant: tenant, App: q.App, Records: []AppCDHistoryRecord{}, Last: entry.CDHistoryNext}
	if len(entry.CDHistory) != 0 {
		page.First = entry.CDHistory[0].Sequence
		page.Truncated = page.First > 1
	}
	end := min(int(offset)+16, len(entry.CDHistory))
	for i := int(offset); i < end; i++ {
		page.Records = append(page.Records, entry.CDHistory[len(entry.CDHistory)-1-i])
	}
	if end < len(entry.CDHistory) {
		page.Next = nextTaskCursor(basis, uint32(end))
	}
	return page, nil
}

type AppCDDiff struct {
	Schema      uint8
	Tenant, App string
	Candidate   deployment.DeliverySelection
	Running     *deployment.DeliverySelection `json:",omitempty"`
	Changes     []deployment.ServiceFieldChange
	ChangeCount int
	Replacement *deployment.ReplacementPlan `json:",omitempty"`
}

func (p Policy) AppDeliveryDiff(s state.State, session access.Session, at int64, tenant string, q AppCDReadRequest) (AppCDSnapshotPart, error) {
	if !q.Valid(false) {
		return AppCDSnapshotPart{}, access.ErrInvalid
	}
	entry, err := p.appSourceEntry(s, session, at, tenant, AppSourceSelection{App: q.App})
	if err != nil || entry.Delivery == nil {
		return AppCDSnapshotPart{}, access.ErrDenied
	}
	d := *entry.Delivery
	candidate, ok := d.CandidateSelection()
	if !ok {
		return AppCDSnapshotPart{}, access.ErrDenied
	}
	changes, err := d.ServiceChanges()
	if err != nil {
		return AppCDSnapshotPart{}, err
	}
	out := AppCDDiff{Schema: 1, Tenant: tenant, App: q.App, Candidate: candidate, Changes: changes, ChangeCount: len(changes)}
	blueprint, ok := d.CandidateBlueprint()
	if !ok {
		return AppCDSnapshotPart{}, ErrCatalog
	}
	out.Replacement, err = entry.Inventory.ReplacementPlan(blueprint, d.Policy().Sync.Prune)
	if err != nil {
		return AppCDSnapshotPart{}, err
	}
	if running, ok := d.Selection(); ok {
		out.Running = &running
	}
	return cdSnapshotPart(tenant, q.App, "diff", q, out)
}
