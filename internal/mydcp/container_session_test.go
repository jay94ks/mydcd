// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"testing"

	"github.com/jay94ks/mydcd/internal/containerops"
)

func TestContainerSessionFramesPinIntentRequestAndPurpose(t *testing.T) {
	intent := [32]byte{1}
	want := containerops.SessionRecord{Schema: 1, Sequence: 1, Kind: "stdin", Data: []byte{0, 1, 255}}
	var wire bytes.Buffer
	if err := WriteSessionRecord(&wire, 17, intent, want); err != nil {
		t.Fatal(err)
	}
	raw := bytes.Clone(wire.Bytes())
	got, err := ReadSessionRecord(&wire, 17, intent)
	if err != nil || !bytes.Equal(got.Data, want.Data) || got.Sequence != want.Sequence {
		t.Fatal("binary session framing", err)
	}
	for _, test := range []struct {
		id     uint64
		digest [32]byte
	}{{18, intent}, {17, [32]byte{2}}, {0, intent}, {17, [32]byte{}}} {
		if _, err := ReadSessionRecord(bytes.NewReader(raw), test.id, test.digest); err == nil {
			t.Fatal("record crossed original intent", test.id)
		}
	}
	for _, size := range []int{0, 1, len(raw) - 1} {
		if _, err := ReadSessionRecord(bytes.NewReader(raw[:size]), 17, intent); err == nil {
			t.Fatal("partial record accepted", size)
		}
	}
	f := Frame{Purpose: User, Kind: 2, Request: 17, Fields: []Field{{Tag: 1, Required: true, Value: []byte("{}")}, {Tag: 2, Required: true, Value: intent[:]}}}
	var other bytes.Buffer
	if err := WriteFrame(&other, f); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSessionRecord(&other, 17, intent); err == nil {
		t.Fatal("ordinary User reply became a session record")
	}
}
