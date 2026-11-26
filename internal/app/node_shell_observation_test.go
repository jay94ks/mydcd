// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

func nodeShellObservationFixture() (control.NodeShellRecord, nodeShellReceipt, nodeShellOwnerSnapshot, ed25519.PrivateKey) {
	row, p := nodeShellReceiptFixture()
	oldKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	row.Owner = [32]byte(oldKey.Public().(ed25519.PublicKey))
	p.Owner = row.Owner
	old := control.NodeShellReport{Schema: 1, Cluster: p.Cluster, Reporter: row.Owner, Node: p.Node, SessionID: p.SessionID, Kind: "opened", At: 11, LastActivity: 11, Sequence: 1, Epoch: 1, RequestID: "original-observation"}
	old.Signature = ed25519.Sign(oldKey, control.NodeShellReportBytes(old))
	p.Phase, p.OpenedAt, p.LastActivity, p.BytesIn, p.BytesOut, p.Pending = "closed", 11, 12, 3, 8, &old
	p.Reason = "exit"
	p.Code = 7
	view := nodeShellOwnerSnapshot{Book: control.NodeShellBook{Schema: 1, Cluster: p.Cluster, Records: []control.NodeShellRecord{row}}, Epoch: 2, RootRevision: 9, Rejected: true}
	view.Book.Policy.Revision = 4
	return row, p, view, oldKey
}

func TestNodeShellObservationUnknownNeedsPositiveRejectionAndKeepsOriginalTrace(t *testing.T) {
	_, p, view, _ := nodeShellObservationFixture()
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = saveNodeShellReceipt(db, p); err != nil {
		t.Fatal(err)
	}
	view.Rejected = false
	if nodeShellObservationReplaceable(view, nil) {
		t.Fatal("missing result/changed epoch replaced unknown original")
	}
	before, _ := db.GetBounded(nodeShellReceiptKey(p.SessionID), 8192)
	// A lost reply remains pending with its exact signed report and actual
	// effect receipt. No helper interprets the changed epoch as NotSent.
	if raw, _ := db.GetBounded(nodeShellReceiptKey(p.SessionID), 8192); !bytes.Equal(raw, before) {
		t.Fatal("unknown observation changed")
	}
	view.Rejected = true
	if !nodeShellObservationReplaceable(view, nil) {
		t.Fatal("explicit current pre-submit rejection not handled")
	}
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	current := [32]byte(newKey.Public().(ed25519.PublicKey))
	seed, needed, err := nodeShellNextObservation(p, view, current, 13)
	if err != nil || !needed || seed.Kind != "closed" || seed.SessionID != p.SessionID || seed.BytesIn != 3 || seed.BytesOut != 8 || seed.Sequence != 1 {
		t.Fatal("positive original closure lost", seed, needed, err)
	}
	r := &Runtime{Identity: &identity.Identity{Private: newKey, Public: current}, nodeShell: &nodeShellRuntime{node: p.Node}, controlPolicy: control.Policy{Cluster: p.Cluster}}
	report := r.signNodeShellReport(view, seed)
	next := p
	next.Pending = &report
	if err = saveNodeShellObservationReplacement(db, p, next, nil); err != nil {
		t.Fatal(err)
	}
	traceRaw, err := db.GetBounded(nodeShellObservationTraceKey(*p.Pending), 8192)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := schema.Decode[nodeShellObservationTrace](traceRaw)
	if err != nil || trace.Outcome != "unknown" || trace.Result != nil || trace.Report.RequestID != p.Pending.RequestID || !bytes.Equal(trace.Report.Signature, p.Pending.Signature) || trace.Origin != p.Origin || trace.Instance != p.Instance {
		t.Fatal("original unknown delivery trace lost", trace, err)
	}
	storedRaw, _ := db.GetBounded(nodeShellReceiptKey(p.SessionID), 8192)
	stored, err := schema.Decode[nodeShellReceipt](storedRaw)
	if err != nil || stored.Origin != p.Origin || stored.Owner != p.Owner || stored.Instance != p.Instance || stored.Pending.Epoch != 2 || stored.Pending.Reporter != current || stored.Pending.RootRevision != 9 || stored.Phase != "closed" {
		t.Fatal("replaced effect instead of observation", stored, err)
	}
	// The trace key is immutable: a conflicting previous payload cannot be
	// overwritten while publishing another Pending observation.
	if err = db.Write(map[string][]byte{nodeShellObservationTraceKey(*p.Pending): []byte("conflict")}); err != nil {
		t.Fatal(err)
	}
	if err = saveNodeShellObservationReplacement(db, p, next, nil); err == nil {
		t.Fatal("immutable trace collision accepted")
	}
	if raw, _ := db.GetBounded(nodeShellReceiptKey(p.SessionID), 8192); !bytes.Equal(raw, storedRaw) {
		t.Fatal("collision changed pending effect receipt")
	}
}

func TestNodeShellObservationUsesAcceptedSequenceCountersAndSignedCloseIntent(t *testing.T) {
	row, p, view, key := nodeShellObservationFixture()
	row.Session.State = "opened"
	row.Session.OpenedAt = 11
	row.Session.LastActivity = 12
	row.Session.BytesIn = 2
	row.Session.BytesOut = 6
	row.Report = &control.NodeShellReport{Sequence: 5}
	view.Book.Records = []control.NodeShellRecord{row}
	seed, needed, err := nodeShellNextObservation(p, view, row.Owner, 13)
	if err != nil || !needed || seed.Sequence != 6 || seed.BytesIn != 3 || seed.BytesOut != 8 {
		t.Fatal("current accepted sequence not consumed", seed, err)
	}
	row.Session.State = "closing"
	row.Session.End = &control.NodeShellEnd{Reason: "policy", ClosedBy: &control.NodeShellUser{User: "admin", Username: "operator"}}
	view.Book.Records = []control.NodeShellRecord{row}
	seed, needed, err = nodeShellNextObservation(p, view, row.Owner, 13)
	if err != nil || !needed || seed.Reason != "policy" || seed.Code != 7 {
		t.Fatal("exact signed closing intent lost", seed, err)
	}
	if row.Session.End.ClosedBy.User != "admin" {
		t.Fatal("observation mutated closing actor")
	}
	p.Phase, p.Code, p.Reason = "opened", 0, ""
	if _, _, err = nodeShellNextObservation(p, view, row.Owner, 13); err == nil {
		t.Fatal("live transport fabricated policy closure")
	}
	row.Session.State = "opened"
	row.Session.End = nil
	row.Session.BytesIn = 3
	row.Session.BytesOut = 8
	view.Book.Records = []control.NodeShellRecord{row}
	if _, needed, err = nodeShellNextObservation(p, view, row.Owner, 13); err != nil || needed {
		t.Fatal("already accepted counters repeated", needed, err)
	}
	if nodeShellObservationReplaceable(view, &state.Result{Code: state.Applied}) {
		t.Fatal("applied observation treated as terminal rejection")
	}
	if !nodeShellObservationReplaceable(view, &state.Result{Code: state.ConditionFailed}) {
		t.Fatal("known terminal rejection not replaceable")
	}
	// Original signature remains untouched by every pure reconstruction.
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), control.NodeShellReportBytes(*p.Pending), p.Pending.Signature) {
		t.Fatal("original observation changed")
	}
}

func TestNodeShellObservationKnownRejectionIsNotUnknown(t *testing.T) {
	_, p, _, _ := nodeShellObservationFixture()
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	next := p
	next.Pending = nil
	result := &state.Result{Code: state.ConditionFailed, Index: 9}
	if err = saveNodeShellObservationReplacement(db, p, next, result); err != nil {
		t.Fatal(err)
	}
	raw, err := db.GetBounded(nodeShellObservationTraceKey(*p.Pending), 8192)
	if err != nil {
		t.Fatal(err)
	}
	trace, err := schema.Decode[nodeShellObservationTrace](raw)
	if err != nil || trace.Outcome != "terminal" || trace.Result == nil || *trace.Result != *result {
		t.Fatal("known terminal result relabeled unknown", trace, err)
	}
}
