// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestCommandCanonicalBytesAndTruncation(t *testing.T) {
	c := command("request", "task", strings.Repeat("\x00", 64*1024), 12)
	b, err := EncodeCommand(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCommand(b)
	if err != nil || got != c || Digest(got) != Digest(c) {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 19, 20, 23, 24, len(b) - 1} {
		if _, err := DecodeCommand(b[:n]); err == nil {
			t.Fatal("truncated command", n)
		}
	}
	if _, err := DecodeCommand(append(b, 0)); err == nil {
		t.Fatal("trailing data")
	}
	b[3] = 3
	if _, err := DecodeCommand(b); err == nil {
		t.Fatal("invalid delete byte")
	}
	// Renew is delete byte 2: a Mutate only, never with Delete, and part of
	// the digest only when set.
	b[3] = 2
	renewed, err := DecodeCommand(b)
	if err != nil || !renewed.Renew || renewed.Delete || Digest(renewed) == Digest(c) {
		t.Fatal("renew byte", err)
	}
	if again, err := EncodeCommand(renewed); err != nil || !bytes.Equal(again, b) {
		t.Fatal("renew encoding", err)
	}
	b[3] = 0
	for _, bad := range []Command{{Kind: Mutate, Key: "k", Renew: true, Delete: true}, {Kind: SetRights, Target: "user/a", Renew: true}} {
		if _, err := EncodeCommand(bad); err == nil {
			t.Fatal("renew outside a plain Mutate")
		}
	}
	c.Value += "x"
	if _, err := EncodeCommand(c); err == nil {
		t.Fatal("oversized command")
	}
}

type snapshotWriter struct {
	bytes.Buffer
	maximum int
}

func (w *snapshotWriter) Write(b []byte) (int, error) {
	if len(b) > w.maximum {
		w.maximum = len(b)
	}
	return w.Buffer.Write(b)
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestSnapshotStreamingPreservesCanonicalBytesAndLargeState(t *testing.T) {
	s, _ := New("admin")
	for i := 0; i < 100; i++ {
		c := command(fmt.Sprint(i), fmt.Sprint(i), strings.Repeat("x", 64<<10), 0)
		if r := mustApply(t, &s, c); r.Code != Applied {
			t.Fatal(r)
		}
	}
	var output snapshotWriter
	if err := EncodeTo(&output, s); err != nil {
		t.Fatal(err)
	}
	if output.Len() <= 8<<20 || output.maximum > 128<<10 {
		t.Fatal("state total and individual write were conflated", output.Len(), output.maximum)
	}
	legacy, err := json.Marshal(rows(s))
	if err != nil || !bytes.Equal(legacy, output.Bytes()) {
		t.Fatal("schema=1 canonical bytes changed", err)
	}
	restored, err := DecodeFrom(bytes.NewReader(output.Bytes()))
	if err != nil || restored.Index() != 100 || restored.Object("workload/99") != s.Object("workload/99") {
		t.Fatal("large state roundtrip", err)
	}
	if _, err = Decode(append(append([]byte(nil), output.Bytes()...), '\n')); err == nil {
		t.Fatal("noncanonical trailing whitespace accepted")
	}
	if err = EncodeTo(failingWriter{}, s); err == nil {
		t.Fatal("writer error ignored")
	}
	t.Logf("canonical bytes=%d, largest write=%d", output.Len(), output.maximum)
}

func TestSnapshotPreservesBinaryValues(t *testing.T) {
	s, _ := New("admin")
	c := command("binary", "task", string([]byte{0xff, 0xfe, 0, 1}), 0)
	if r := mustApply(t, &s, c); r.Code != Applied {
		t.Fatal(r)
	}
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(b)
	if err != nil || restored.Object(c.Key).Value != c.Value {
		t.Fatal("snapshot corrupted non-UTF8 bytes", err)
	}
	c.RequestID = string([]byte{0xff})
	if r := mustApply(t, &s, c); r.Code != Invalid {
		t.Fatal("invalid identity bytes", r)
	}
}

func TestRenewGivesPresentObjectNewGeneration(t *testing.T) {
	s := initial()
	s, r, err := Apply(s, s.Index()+1, Command{Actor: "admin", Epoch: 1, RequestID: "1", Key: "workload/k", Value: "v1"})
	if err != nil || r.Code != Applied {
		t.Fatal(err, r)
	}
	first := s.Object("workload/k")
	s, r, err = Apply(s, s.Index()+1, Command{Actor: "admin", Epoch: 1, RequestID: "2", Key: "workload/k", Value: "v2", Expected: first.Revision})
	if err != nil || r.Code != Applied || s.Object("workload/k").Generation != first.Generation {
		t.Fatal("plain mutate changed the generation", err, r)
	}
	second := s.Object("workload/k")
	s, r, err = Apply(s, s.Index()+1, Command{Actor: "admin", Epoch: 1, RequestID: "3", Key: "workload/k", Value: "v3", Expected: second.Revision, Renew: true})
	if err != nil || r.Code != Applied || r.Generation <= second.Generation || s.Object("workload/k").Generation != r.Generation || !s.Object("workload/k").Present {
		t.Fatal("renew kept the generation", err, r)
	}
	if _, r, _ = Apply(s, s.Index()+1, Command{Actor: "admin", Epoch: 1, RequestID: "4", Key: "workload/k", Expected: s.Object("workload/k").Revision, Renew: true, Delete: true}); r.Code == Applied {
		t.Fatal("renewing delete applied")
	}
}
