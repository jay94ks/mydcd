// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"testing"
)

func TestNodeShellPurposeAndFlowBindOriginalDirectionAndBoundedEnd(t *testing.T) {
	if NodeShell != 19 || ContainerSession != 15 || VolumeFile != 18 {
		t.Fatal("legacy purpose numbering changed")
	}
	key := Identity{1}
	for _, tc := range []struct {
		kind    uint8
		policy  Policy
		allowed bool
	}{{1, Policy{Key: key, UserAuth: true}, true}, {1, Policy{Key: key, Member: true}, false}, {3, Policy{Key: key, Member: true}, true}, {3, Policy{Key: key, UserAuth: true}, false}, {2, Policy{Key: key, Respond: true}, true}, {5, Policy{Key: key, UserAuth: true}, true}} {
		gate := Gate{key: key, authenticated: true}
		if got := gate.Admit(Frame{Purpose: NodeShell, Kind: tc.kind}, tc.policy, false, false) == nil; got != tc.allowed {
			t.Fatal("wrong current role", tc.kind)
		}
	}
	flow := NodeShellFlow{}
	var err error
	for _, r := range []NodeShellRecord{{Schema: 1, Sequence: 1, Kind: "stdin", Data: []byte("input")}, {Schema: 1, Sequence: 2, Kind: "resize", Cols: 80, Rows: 24}, {Schema: 1, Sequence: 3, Kind: "half-close"}, {Schema: 1, Sequence: 4, Kind: "ping"}} {
		flow, err = flow.Accept(r, true)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = flow.Accept(NodeShellRecord{Schema: 1, Sequence: 5, Kind: "stdin", Data: []byte("after eof")}, true); err == nil {
		t.Fatal("stdin after half close")
	}
	for _, r := range []NodeShellRecord{{Schema: 1, Sequence: 1, Kind: "stdout", Data: []byte("x")}, {Schema: 1, Sequence: 1, Kind: "stdin", Data: make([]byte, NodeShellChunkBytes+1)}, {Schema: 1, Sequence: 1, Kind: "resize", Cols: 1001, Rows: 24}, {Schema: 1, Sequence: 1, Kind: "ping", Data: []byte("hidden transcript")}, {Schema: 1, Sequence: 2, Kind: "ping"}} {
		if _, err = (NodeShellFlow{}).Accept(r, true); err == nil {
			t.Fatal("invalid client shape accepted", r.Kind)
		}
	}
	end := NodeShellEnd{Reason: "closed", Code: 0, ClosedBy: &NodeShellActor{User: "bob", Username: "bob"}}
	server, err := (NodeShellFlow{}).Accept(NodeShellRecord{Schema: 1, Sequence: 1, Kind: "end", End: &end}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.Accept(NodeShellRecord{Schema: 1, Sequence: 2, Kind: "ping"}, false); err == nil {
		t.Fatal("record after end")
	}
	end.Reason = "exit"
	if end.Valid() {
		t.Fatal("natural exit fabricated closed actor")
	}
	end.Reason = "policy"
	end.ClosedBy.Username = "bob\nforged"
	if end.Valid() {
		t.Fatal("control character in end actor")
	}
}
func TestNodeShellRecordPurposeRequestBindingAndCanonicalShape(t *testing.T) {
	record := NodeShellRecord{Schema: 1, Sequence: 1, Kind: "stdout", Data: []byte("output")}
	binding := [32]byte{2}
	var wire bytes.Buffer
	if WriteNodeShellRecord(&wire, 17, binding, record) != nil {
		t.Fatal("encode")
	}
	raw := bytes.Clone(wire.Bytes())
	got, err := ReadNodeShellRecord(&wire, 17, binding)
	if err != nil || !bytes.Equal(got.Data, record.Data) {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		request uint64
		binding [32]byte
	}{{18, binding}, {17, [32]byte{3}}} {
		if _, err = ReadNodeShellRecord(bytes.NewReader(raw), tc.request, tc.binding); err == nil {
			t.Fatal("foreign original accepted")
		}
	}
	f, _ := ReadFrame(bytes.NewReader(raw), 128<<10)
	f.Purpose = ContainerSession
	foreign, _ := Encode(f)
	if _, err = ReadNodeShellRecord(bytes.NewReader(foreign), 17, binding); err == nil {
		t.Fatal("container purpose became node shell")
	}
	f.Purpose = NodeShell
	f.Fields[0].Value = []byte(`{"Schema":1,"Sequence":1,"Kind":"stdout","Data":"eA==","Token":"hidden"}`)
	foreign, _ = Encode(f)
	if _, err = ReadNodeShellRecord(bytes.NewReader(foreign), 17, binding); err == nil {
		t.Fatal("unknown secret/transcript metadata field")
	}
}
