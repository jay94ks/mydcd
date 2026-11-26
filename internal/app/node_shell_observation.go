// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/storage"
)

type nodeShellObservationTrace struct {
	Schema                           uint8
	Cluster, Owner, Origin, Instance [32]byte
	Node, SessionID, Outcome         string
	Report                           control.NodeShellReport
	Result                           *state.Result `json:",omitempty"`
}

func nodeShellObservationTraceKey(report control.NodeShellReport) string {
	session := sha256.Sum256([]byte(report.SessionID))
	raw, _ := json.Marshal(report)
	digest := sha256.Sum256(raw)
	return "node-shell/observation/" + hex.EncodeToString(session[:]) + "/" + hex.EncodeToString(digest[:])
}

// Rejected means only that THIS current validation did not submit the old
// report. It does not prove a prior delivery was NotSent: that delivery remains
// unknown in its immutable trace until its actual result is separately known.
func nodeShellObservationReplaceable(view nodeShellOwnerSnapshot, result *state.Result) bool {
	return result != nil && result.Code != state.Applied || result == nil && view.Rejected
}

// The owner serializes this boundary with admission/receipt updates. Archiving
// an exceptional superseded delivery and replacing Pending use ONE DB commit.
// This is immutable provenance, not a queue or automatic replay mechanism.
func saveNodeShellObservationReplacement(db *storage.DB, before, after nodeShellReceipt, result *state.Result) error {
	if before.Pending == nil {
		return control.ErrCatalog
	}
	a, b := before, after
	a.Pending, b.Pending = nil, nil
	if a != b {
		return control.ErrCatalog
	}
	trace := nodeShellObservationTrace{Schema: 1, Cluster: before.Cluster, Owner: before.Owner, Origin: before.Origin, Instance: before.Instance, Node: before.Node, SessionID: before.SessionID, Outcome: "unknown", Report: *before.Pending, Result: result}
	key, raw, err := nodeShellObservationTraceBytes(db, trace)
	if err != nil {
		return err
	}
	pending, err := json.Marshal(after)
	if err != nil || len(pending) > 8192 {
		return control.ErrCatalog
	}
	return db.Write(map[string][]byte{key: raw, nodeShellReceiptKey(after.SessionID): pending})
}

func nodeShellObservationTraceBytes(db *storage.DB, trace nodeShellObservationTrace) (string, []byte, error) {
	result := trace.Result
	if result != nil {
		trace.Outcome = "terminal"
	}
	raw, err := json.Marshal(trace)
	if err != nil || len(raw) > 8192 {
		return "", nil, control.ErrCatalog
	}
	key := nodeShellObservationTraceKey(trace.Report)
	old, err := db.GetBounded(key, 8192)
	if err == nil && !bytes.Equal(old, raw) {
		return "", nil, control.ErrCatalog
	}
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return "", nil, err
	}
	return key, raw, nil
}

func saveNodeShellReadyRetirement(db *storage.DB, report control.NodeShellReport, result *state.Result) error {
	trace := nodeShellObservationTrace{Schema: 1, Cluster: report.Cluster, Owner: report.Reporter, Node: report.Node, Outcome: "unknown", Report: report, Result: result}
	key, raw, err := nodeShellObservationTraceBytes(db, trace)
	if err != nil {
		return err
	}
	return db.Write(map[string][]byte{key: raw, nodeShellReadyReceiptKey: nil})
}

// nodeShellNextObservation rebuilds only an owner observation after current
// rejection or a known terminal result. A prior delivery may remain unknown
// in its immutable trace. This consumes the original positive native receipt
// and current record; it never authorizes or starts another SSH effect.
func nodeShellNextObservation(p nodeShellReceipt, view nodeShellOwnerSnapshot, reporter [32]byte, at int64) (control.NodeShellReport, bool, error) {
	row, found := view.Book.Record(p.SessionID)
	if !found || !p.valid(view.Book.Cluster, row) || at < row.Session.CreatedAt || at < p.LastActivity {
		return control.NodeShellReport{}, false, control.ErrCatalog
	}
	if row.Session.State == "closed" {
		if p.Phase != "closed" {
			return control.NodeShellReport{}, false, reconcile.ErrPending
		}
		return control.NodeShellReport{}, false, nil
	}
	sequence := uint64(1)
	if row.Report != nil {
		if row.Report.Sequence == ^uint64(0) {
			return control.NodeShellReport{}, false, control.ErrCatalog
		}
		sequence = row.Report.Sequence + 1
	}
	report := control.NodeShellReport{SessionID: p.SessionID, At: at, LastActivity: p.LastActivity, BytesIn: p.BytesIn, BytesOut: p.BytesOut, Sequence: sequence}
	switch p.Phase {
	case "opened":
		if row.Owner != reporter {
			return control.NodeShellReport{}, false, reconcile.ErrPending
		}
		switch row.Session.State {
		case "queued":
			// The actual Open happened at this frozen time, not at retry time.
			report.Kind, report.At, report.LastActivity = "opened", p.OpenedAt, p.OpenedAt
			report.BytesIn, report.BytesOut = 0, 0
		case "opened":
			if row.Session.OpenedAt != p.OpenedAt {
				return control.NodeShellReport{}, false, control.ErrCatalog
			}
			if row.Session.BytesIn == p.BytesIn && row.Session.BytesOut == p.BytesOut {
				return control.NodeShellReport{}, false, nil
			}
			report.Kind = "activity"
		default:
			// A closing intent still needs the ORIGINAL live transport closed
			// before the receipt can support a closed observation.
			return control.NodeShellReport{}, false, reconcile.ErrPending
		}
	case "closed":
		report.Kind, report.Code, report.Reason = "closed", p.Code, p.Reason
		if row.Session.State == "closing" {
			if row.Session.End == nil {
				return control.NodeShellReport{}, false, control.ErrCatalog
			}
			// ClosedBy is never supplied by the observation. The reducer uses
			// the immutable, signed close/policy intent already in the record.
			report.Reason = row.Session.End.Reason
		} else if report.Reason != "exit" && report.Reason != "idle" {
			return control.NodeShellReport{}, false, reconcile.ErrPending
		}
	default:
		// Sent/unknown is not positive opening or closing evidence.
		return control.NodeShellReport{}, false, reconcile.ErrPending
	}
	return report, true, nil
}
