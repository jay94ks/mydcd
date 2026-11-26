// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"math"
	"testing"
	"time"
)

func sessionRecordTarget() Target {
	return Target{Cluster: [32]byte{1}, Owner: [32]byte{2}, Binding: [32]byte{3}, Tenant: "tenant", App: "app", Service: "web", Node: "node-a", Instance: "workload/task/tenant/app/web", Generation: 1, Revision: 1, NativeID: "original", StartedAt: "2026-01-01T00:00:00Z"}
}

func TestContainerSessionRecordsBindReceiptAndRequireRealLogMetadata(t *testing.T) {
	target := sessionRecordTarget()
	q := SessionSpec{Kind: "exec", Exec: &ExecSpec{Argv: []string{"tool"}}}
	receipt := ExecReceipt{Schema: 1, Intent: [32]byte{1}, Phase: ExecCreating}
	r := SessionRecord{Schema: 1, Sequence: 1, Kind: "receipt", Receipt: &receipt}
	if _, err := (SessionFlow{Intent: [32]byte{2}}).Accept(q, target, r, false); err == nil {
		t.Fatal("receipt of another exec accepted")
	}
	if _, err := (SessionFlow{Intent: receipt.Intent}).Accept(q, target, r, false); err != nil {
		t.Fatal(err)
	}
	query := Query{Schema: 1, Selection: Selection{App: "app", Service: "web"}, Kind: "logs", Tail: 1, Stdout: true, Stderr: true, MaxBytes: 16384}
	q = SessionSpec{Kind: "logs", Query: &query}
	data := SessionRecord{Schema: 1, Sequence: 1, Kind: "stdout", Data: []byte("output")}
	if _, err := (SessionFlow{}).Accept(q, target, data, false); err == nil {
		t.Fatal("follow data arrived before actual TTY/driver metadata")
	}
	meta := Result{Schema: 1, Kind: "logs", Target: target, ObservedAt: time.Unix(1, 0), LogDriver: "local"}
	state, err := (SessionFlow{}).Accept(q, target, SessionRecord{Schema: 1, Sequence: 1, Kind: "sample", Sample: &meta}, false)
	if err != nil {
		t.Fatal(err)
	}
	data.Sequence = 2
	if _, err = state.Accept(q, target, data, false); err != nil {
		t.Fatal("data after verified metadata", err)
	}
	if _, err = state.Accept(q, target, SessionRecord{Schema: 1, Sequence: 2, Kind: "sample", Sample: &meta}, false); err == nil {
		t.Fatal("follow metadata rebound within one stream")
	}
}

func TestContainerSessionRecordsPreserveHalfCloseAndDirections(t *testing.T) {
	q := SessionSpec{Kind: "exec", Exec: &ExecSpec{Argv: []string{"custom-cli"}, Stdin: true}}
	target := sessionRecordTarget()
	var in, out SessionFlow
	var err error
	in, err = in.Accept(q, target, SessionRecord{Schema: 1, Sequence: 1, Kind: "stdin", Data: []byte("hello")}, true)
	if err != nil {
		t.Fatal(err)
	}
	in, err = in.Accept(q, target, SessionRecord{Schema: 1, Sequence: 2, Kind: "stdin-eof"}, true)
	if err != nil || !in.InputEOF || in.Ended {
		t.Fatal("stdin EOF closed output", err)
	}
	if _, err := in.Accept(q, target, SessionRecord{Schema: 1, Sequence: 3, Kind: "stdin", Data: []byte("after EOF")}, true); err == nil {
		t.Fatal("stdin after half-close")
	}
	out, err = out.Accept(q, target, SessionRecord{Schema: 1, Sequence: 1, Kind: "stdout", Data: []byte("after stdin EOF")}, false)
	if err != nil {
		t.Fatal("reverse output closed prematurely", err)
	}
	out, err = out.Accept(q, target, SessionRecord{Schema: 1, Sequence: 2, Kind: "output-eof"}, false)
	if err != nil || !out.OutputEOF || out.Ended {
		t.Fatal("output EOF invented process completion", err)
	}
	if _, err := out.Accept(q, target, SessionRecord{Schema: 1, Sequence: 3, Kind: "stdout", Data: []byte("after output EOF")}, false); err == nil {
		t.Fatal("output after EOF")
	}
	in, err = in.Accept(q, target, SessionRecord{Schema: 1, Sequence: 3, Kind: "cancel"}, true)
	if err != nil || !in.Ended {
		t.Fatal(err)
	}
	if _, err := in.Accept(q, target, SessionRecord{Schema: 1, Sequence: 4, Kind: "ping"}, true); err == nil {
		t.Fatal("data after cancellation")
	}
}

func TestContainerSessionRecordsRejectMixingReplayOverflowAndUnboundedData(t *testing.T) {
	q := SessionSpec{Kind: "exec", Exec: &ExecSpec{Argv: []string{"custom-cli"}, Stdin: true}}
	for _, record := range []SessionRecord{
		{Schema: 1, Sequence: 1, Kind: "stdout", Data: []byte("client forged output")},
		{Schema: 1, Sequence: 2, Kind: "stdin", Data: []byte("gap")},
		{Schema: 1, Sequence: 1, Kind: "stdin", Data: make([]byte, SessionChunkBytes+1)},
		{Schema: 1, Sequence: 1, Kind: "stdin"},
		{Schema: 1, Sequence: 1, Kind: "ping", Rows: 1},
		{Schema: 1, Sequence: 1, Kind: "resize", Rows: 1, Cols: 1},
		{Schema: 1, Sequence: 1, Kind: "stdin-eof", Code: "denied"},
	} {
		if _, err := (SessionFlow{}).Accept(q, sessionRecordTarget(), record, true); err == nil {
			t.Fatal("malformed client record", record.Kind)
		}
	}
	if _, err := (SessionFlow{Sequence: math.MaxUint64}).Accept(q, sessionRecordTarget(), SessionRecord{Schema: 1, Sequence: 0, Kind: "ping"}, true); err == nil {
		t.Fatal("ordinal wrapped")
	}
	q.Exec.TTY, q.Exec.Rows, q.Exec.Cols = true, 24, 80
	if _, err := (SessionFlow{}).Accept(q, sessionRecordTarget(), SessionRecord{Schema: 1, Sequence: 1, Kind: "stderr", Data: []byte("false TTY stderr")}, false); err == nil {
		t.Fatal("fabricated TTY stderr")
	}
}
