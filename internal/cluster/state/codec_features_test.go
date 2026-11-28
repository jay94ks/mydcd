// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/buildinfo"
)

// An entry without features encodes exactly as before; one with features
// adds a trailing block that round-trips and is accepted only in canonical
// form.
func TestCommandFeatures(t *testing.T) {
	plain := Command{Actor: "a", RequestID: "r", Key: "k", Value: "v", Target: "t", Epoch: 3}
	before, err := EncodeCommand(plain)
	if err != nil {
		t.Fatal(err)
	}
	if before[len(before)-1] != 't' {
		t.Fatal("an entry without features grew a block")
	}
	v2 := buildinfo.Feature{Group: buildinfo.GroupNetwork, Set: buildinfo.SetNetworkTransit, Version: 2}
	used := plain
	used.Features = buildinfo.MustFeatures(buildinfo.NetworkTransitV1, v2)
	b, err := EncodeCommand(used)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b[:len(before)], before) || !bytes.Equal(b[len(before):], []byte{2, 1, 0, 1, 1, 2, 0, 1, 1}) {
		t.Fatalf("feature block %x", b[len(before):])
	}
	got, err := DecodeCommand(b)
	if err != nil || got != used {
		t.Fatal("round trip", got, err)
	}
	if !got.Uses(buildinfo.From(v2)) || !got.Uses(buildinfo.From(buildinfo.NetworkTransitV1)) || plain.Uses(buildinfo.From(buildinfo.NetworkTransitV1)) {
		t.Fatal("uses")
	}
	if _, err := EncodeCommand(Command{Features: buildinfo.MustFeatures(buildinfo.Feature{Group: 1, Set: 1, Version: 1, Postfix: "preview"})}); !errors.Is(err, ErrCommand) {
		t.Fatal("a postfixed feature was written into Raft")
	}
	many := make([]buildinfo.Feature, MaxCommandFeatures+1)
	for i := range many {
		many[i] = buildinfo.Feature{Group: 1, Set: 1, Version: uint16(i + 1)}
	}
	if _, err := EncodeCommand(Command{Features: buildinfo.MustFeatures(many...)}); !errors.Is(err, ErrCommand) {
		t.Fatal("too many features")
	}
	if commandDigest(used) == commandDigest(plain) {
		t.Fatal("a retry with other features would replay the first result")
	}
	for name, tail := range map[string][]byte{
		"empty block":  {0},
		"short":        {1, 1, 0, 1},
		"long":         {1, 1, 0, 1, 1, 0},
		"not sorted":   {2, 2, 0, 1, 1, 1, 0, 1, 1},
		"duplicate":    {2, 1, 0, 1, 1, 1, 0, 1, 1},
		"version zero": {1, 0, 0, 1, 1},
	} {
		if _, err := DecodeCommand(append(bytes.Clone(before), tail...)); !errors.Is(err, ErrCommand) {
			t.Errorf("%s accepted", name)
		}
	}
}

// Applied entries add their features to the state's record; rejected ones
// do not, and no command may write the record itself.
func TestStateRecordsFeaturesUsed(t *testing.T) {
	s := initial()
	if used, ok := s.FeaturesUsed(); !ok || !used.Empty() {
		t.Fatal("new state", used, ok)
	}
	v1 := buildinfo.MustFeatures(buildinfo.NetworkTransitV1)
	c := command("1", "a", "x", 0)
	c.Features = v1
	if r := mustApply(t, &s, c); r.Code != Applied {
		t.Fatal(r)
	}
	if used, ok := s.FeaturesUsed(); !ok || used != v1 {
		t.Fatal("after an applied entry", used, ok)
	}
	v2 := buildinfo.MustFeatures(buildinfo.Feature{Group: 1, Set: 1, Version: 2})
	stale := command("2", "a", "y", 0) // "a" exists: expected 0 fails
	stale.Features = v2
	if r := mustApply(t, &s, stale); r.Code == Applied {
		t.Fatal("stale write applied")
	}
	if used, _ := s.FeaturesUsed(); used != v1 {
		t.Fatal("a rejected entry recorded its features", used)
	}
	both, _ := v1.Or(v2)
	next := command("3", "b", "z", 0)
	next.Features = v2
	mustApply(t, &s, next)
	if used, _ := s.FeaturesUsed(); used != both {
		t.Fatal("union", used)
	}
	forge := Command{Actor: "admin", Epoch: 1, RequestID: "4", Key: FeaturesUsedKey, Value: "00"}
	if r := mustApply(t, &s, forge); r.Code == Applied {
		t.Fatal("a command wrote the feature record")
	}
	if used, _ := s.FeaturesUsed(); used != both {
		t.Fatal("record changed", used)
	}
}
