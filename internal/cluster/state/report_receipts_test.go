// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func reportFixture() (State, Reducer, ModuleAuthorizer) {
	s, _ := New("admin")
	return s, func(_ State, c Command) (map[string][]byte, Code) {
			if c.Value == "denied" {
				return nil, Forbidden
			}
			return map[string][]byte{c.Key: []byte(c.Value)}, Applied
		}, func(_ State, c Command) bool {
			return c.Actor == "node/reporter" && (c.Kind == ModuleReport || c.Kind == Module)
		}
}

func checkpoint(s State, key, value string) Command {
	c := Command{Kind: ModuleReport, Actor: "node/reporter", Epoch: 1, Key: key, Expected: s.Object(key).Revision, Value: value}
	c.RequestID = ReportRequestID(c)
	return c
}

func TestReportLedgerCollectsOnlySupersededCheckpointCAS(t *testing.T) {
	s, reduce, admit := reportFixture()
	var first, prior, last Command
	var priorResult Result
	for i := 0; i < LedgerLimit*3; i++ {
		c := checkpoint(s, "control/reports", fmt.Sprint(i))
		n, r, e := ApplyAdmitted(s, s.Index()+1, c, nil, reduce, admit)
		if e != nil || r.Code != Applied || n.ReceiptCount() > LedgerLimit {
			t.Fatal(i, r, e)
		}
		if i == 0 {
			first = c
		}
		if i == LedgerLimit-1 {
			prior, priorResult = c, r
		}
		if i == LedgerLimit {
			if got, ok := n.LookupResult(prior); !ok || got != priorResult {
				t.Fatal("lost final ACK cannot read latest original result")
			}
			replay, original, e := ApplyAdmitted(n, n.Index()+1, prior, nil, nil, nil)
			if e != nil || original != priorResult || replay.Object(c.Key) != n.Object(c.Key) {
				t.Fatal("retained latest receipt replay changed", original, e)
			}
		}
		s, last = n, c
	}
	if !s.ModuleExpired(first) {
		t.Fatal("reclaimed report has no replay fence")
	}
	if _, ok := s.LookupResult(first); ok {
		t.Fatal("reclaimed result fabricated")
	}
	before := s.Object(last.Key)
	n, r, e := ApplyAdmitted(s, s.Index()+1, first, nil, reduce, admit)
	if e != nil || r.Code != Expired || n.Object(last.Key) != before {
		t.Fatal("old report executed", r, e)
	}
	changed := first
	changed.Expected, changed.Value = before.Revision, "changed"
	_, r, e = ApplyAdmitted(s, s.Index()+1, changed, nil, reduce, admit)
	if e != nil || r.Code != Invalid {
		t.Fatal("retired ID reused with new CAS", r, e)
	}
	var raw bytes.Buffer
	if e = EncodeTo(&raw, s); e != nil {
		t.Fatal(e)
	}
	restored, e := Decode(raw.Bytes())
	if e != nil || !restored.ModuleExpired(first) {
		t.Fatal("report fence lost on Snapshot", e)
	}
	if original, ok := restored.LookupResult(last); !ok || original.Code != Applied {
		t.Fatal("latest original result lost on Snapshot")
	}
	if s.ModuleEpoch() != 1 || restored.ModuleEpoch() != 1 {
		t.Fatal("implicit epoch rotation")
	}
}

func TestFullReportLedgerPublishesNoFailedCandidateOrLegacyEviction(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			s, reduce, admit := reportFixture()
			for i := 0; i < LedgerLimit; i++ {
				c := checkpoint(s, "control/reports", fmt.Sprint(i))
				if legacy {
					c.Kind = Module
					c.RequestID = fmt.Sprint(i)
				}
				var r Result
				var e error
				s, r, e = ApplyAdmitted(s, s.Index()+1, c, nil, reduce, admit)
				if e != nil || r.Code != Applied {
					t.Fatal(r, e)
				}
			}
			before := s.Object("control/reports")
			c := checkpoint(s, "control/reports", "denied")
			n, r, e := ApplyAdmitted(s, s.Index()+1, c, nil, reduce, admit)
			if e != nil || r.Code != LedgerFull || n.Object(c.Key) != before || n.ReceiptCount() != s.ReceiptCount() || len(n.reportFloors) != 0 {
				t.Fatal("failed candidate reclaimed receipts", r, e)
			}
			if legacy {
				c = checkpoint(s, "control/reports", "valid")
				n, r, e = ApplyAdmitted(s, s.Index()+1, c, nil, reduce, admit)
				if e != nil || r.Code != LedgerFull || n.Object(c.Key) != before || len(n.reportFloors) != 0 {
					t.Fatal("unclassified receipts evicted or patch published", r, e)
				}
			}
		})
	}
}

func TestReportRootsBoundAndSnapshotMetadataValidation(t *testing.T) {
	s, reduce, admit := reportFixture()
	for i := 0; i < maxReportRoots; i++ {
		c := checkpoint(s, fmt.Sprintf("control/root%d", i), "value")
		var r Result
		var e error
		s, r, e = ApplyAdmitted(s, s.Index()+1, c, nil, reduce, admit)
		if e != nil || r.Code != Applied {
			t.Fatal(r, e)
		}
	}
	c := checkpoint(s, "control/excess", "value")
	n, r, e := ApplyAdmitted(s, s.Index()+1, c, nil, reduce, admit)
	if e != nil || r.Code != LedgerFull || n.Object(c.Key).Present {
		t.Fatal("unbounded report roots", r, e)
	}
	var raw bytes.Buffer
	if e = EncodeTo(&raw, s); e != nil {
		t.Fatal(e)
	}
	var disk snapshot
	if e = json.Unmarshal(raw.Bytes(), &disk); e != nil {
		t.Fatal(e)
	}
	disk.Reports[0].Expected = s.Index() + 1
	bad, _ := json.Marshal(disk)
	if _, e = Decode(bad); e == nil {
		t.Fatal("future report metadata accepted")
	}
}

func TestReportCollectionPreservesNonReportOriginalResults(t *testing.T) {
	s, reduce, admit := reportFixture()
	legacy := Command{Kind: Module, Actor: "node/reporter", Epoch: 1, RequestID: "original-member", Key: "control/member", Value: "original"}
	var saved Result
	var e error
	s, saved, e = ApplyAdmitted(s, s.Index()+1, legacy, nil, reduce, admit)
	if e != nil || saved.Code != Applied {
		t.Fatal(saved, e)
	}
	for i := 0; i < LedgerLimit+2; i++ {
		c := checkpoint(s, "control/reports", fmt.Sprint(i))
		var r Result
		s, r, e = ApplyAdmitted(s, s.Index()+1, c, nil, reduce, admit)
		if e != nil || r.Code != Applied {
			t.Fatal(i, r, e)
		}
	}
	if r, ok := s.LookupResult(legacy); !ok || r != saved {
		t.Fatal("protected original result evicted")
	}
	if _, ok := s.reportReceipts.get(requestKey{legacy.Actor, legacy.RequestID}.String()); ok {
		t.Fatal("legacy result silently classified")
	}
}

func TestReportCommandCodecPreservesFullContentIdentity(t *testing.T) {
	s, _, _ := reportFixture()
	c := checkpoint(s, "control/reports", "signed public report payload")
	raw, e := EncodeCommand(c)
	if e != nil || raw[0] != 1 {
		t.Fatal("report schema changed", e)
	}
	got, e := DecodeCommand(raw)
	if e != nil || got != c || ReportRequestID(got) != got.RequestID {
		t.Fatal("report content identity lost", e)
	}
	for _, change := range []func(*Command){func(q *Command) { q.Expected++ }, func(q *Command) { q.Actor = "node/other" }, func(q *Command) { q.Value = "different" }, func(q *Command) { q.Key = "control/other" }, func(q *Command) { q.Epoch++ }} {
		q := c
		change(&q)
		if ReportRequestID(q) == c.RequestID {
			t.Fatal("report ID omits authority or contents")
		}
	}
}

// An idle root never moves, so rejected reports at its current CAS must still
// be reclaimable once a report applies, or the ledger stays full for good.
func TestRejectedReportsAtCurrentCASAreReclaimed(t *testing.T) {
	s, _, admit := reportFixture()
	reduce := func(_ State, c Command) (map[string][]byte, Code) {
		if strings.HasPrefix(c.Value, "denied") {
			return nil, Forbidden
		}
		return map[string][]byte{c.Key: []byte(c.Value)}, Applied
	}
	var e error
	var r Result
	if s, r, e = ApplyAdmitted(s, s.Index()+1, checkpoint(s, "control/apps", "seed"), nil, reduce, admit); e != nil || r.Code != Applied {
		t.Fatal(r, e)
	}
	var last Command
	for i := 0; s.ReceiptCount() < LedgerLimit; i++ {
		last = checkpoint(s, "control/volumes", fmt.Sprint("denied-", i))
		if s, r, e = ApplyAdmitted(s, s.Index()+1, last, nil, reduce, admit); e != nil || r.Code != Forbidden {
			t.Fatal(i, r, e)
		}
	}
	lastResult, _ := s.LookupResult(last)
	if !s.ReportLedgerFull("node/reporter", "control/volumes") {
		t.Fatal("ledger not full")
	}
	c := checkpoint(s, "control/volumes", "denied-again")
	if _, r, e = ApplyAdmitted(s, s.Index()+1, c, nil, reduce, admit); e != nil || r.Code != LedgerFull {
		t.Fatal("rejected report at the limit was stored", r, e)
	}
	c = checkpoint(s, "control/volumes", "activate")
	n, r, e := ApplyAdmitted(s, s.Index()+1, c, nil, reduce, admit)
	if e != nil || r.Code != Applied || n.Object(c.Key).Value != "activate" {
		t.Fatal("full ledger of rejected reports blocks an applying report", r, e)
	}
	if n.ReceiptCount() != 3 {
		t.Fatal("rejected receipts kept", n.ReceiptCount())
	}
	if got, ok := n.LookupResult(last); !ok || got != lastResult {
		t.Fatal("newest rejected result lost", got, ok)
	}
	// The oldest rejected report (CAS 0) was reclaimed with its result.
	first := checkpoint(State{}, "control/volumes", "denied-0")
	if _, ok := n.LookupResult(first); ok {
		t.Fatal("reclaimed rejected result fabricated")
	}
}
