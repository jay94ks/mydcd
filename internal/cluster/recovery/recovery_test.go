// SPDX-License-Identifier: Apache-2.0

package recovery

import (
	"crypto/sha256"
	"errors"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"reflect"
	"testing"
)

type fakeStore struct {
	node Node
	fail bool
	acks int
}

func (s *fakeStore) publish(candidate Node) error {
	if s.fail {
		return errors.New("injected sync failure")
	}
	s.node = candidate
	return nil
}
func cmd(id, key, value string, expected uint64) state.Command {
	return state.Command{Actor: "admin", Epoch: 1, RequestID: id, Key: "workload/" + key, Value: value, Expected: expected}
}
func fixture(t *testing.T) (Node, Verified, []byte) {
	t.Helper()
	s, _ := state.New("admin")
	n := Node{Shared: s, CurrentTerm: 7, Vote: "original-vote", Local: map[string]string{"private": "keep", "journal": "unknown"}}
	var err error
	n, err = Add(n, []Entry{{1, 1, cmd("one", "task", "old", 0)}, {2, 1, cmd("two", "task", "new", 1)}, {3, 2, cmd("three", "other", "suffix", 0)}})
	if err != nil {
		t.Fatal(err)
	}
	n, err = Replay(n, 2)
	if err != nil {
		t.Fatal(err)
	}
	m, b, err := Build(n.Shared, n.AppliedTerm, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := Begin(m)
	if err := r.Append(0, b); err != nil {
		t.Fatal(err)
	}
	v, err := r.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return n, v, b
}
func TestStagingCrashAtomicInstallAndSuffixReplay(t *testing.T) {
	n, v, b := fixture(t)
	target, _ := state.New("admin")
	store := fakeStore{node: Node{Shared: target, CurrentTerm: 9, Vote: "local", Local: map[string]string{"key": "secret"}, Log: n.Log}}
	r, _ := Begin(v.meta)
	half := len(b) / 2
	if err := r.Append(0, b[:half]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Finish(); err == nil {
		t.Fatal("partial installed")
	}
	if err := r.Append(1, b[:1]); err == nil {
		t.Fatal("conflicting overlap")
	}
	if err := r.Append(0, b[:half]); err != nil {
		t.Fatal("exact retransmit denied")
	}
	r, err := Resume(v.meta, r.Prefix())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Append(half, b[half:]); err != nil {
		t.Fatal(err)
	}
	verified, err := r.Finish()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := Install(store.node, verified)
	if err != nil {
		t.Fatal(err)
	}
	store.fail = true
	if store.publish(candidate) == nil {
		t.Fatal("missing sync failure")
	}
	if store.node.Shared.Index() != 0 || store.acks != 0 {
		t.Fatal("ack/partial active state before sync")
	}
	store.fail = false
	if err := store.publish(candidate); err != nil {
		t.Fatal(err)
	}
	store.acks++
	if _, err := Install(store.node, verified); err != nil {
		t.Fatal("same durable snapshot reinstall", err)
	}
	if store.node.CurrentTerm != 9 || store.node.Vote != "local" || store.node.Local["key"] != "secret" || len(store.node.Log) != 1 {
		t.Fatal("local original/suffix replaced")
	}
	store.node, err = Replay(store.node, 3)
	if err != nil || store.node.Shared.Object("workload/other").Value != "suffix" {
		t.Fatal("suffix replay", err)
	}
	if _, err := Install(store.node, v); err == nil {
		t.Fatal("installed stale snapshot")
	}
}
func TestCheckpointGCReplayGapsAndCorruption(t *testing.T) {
	n, v, b := fixture(t)
	before := n
	candidate, err := Checkpoint(n, v)
	if err != nil || len(candidate.Log) != 1 || candidate.Installed.Index != 2 {
		t.Fatal(err)
	}
	if len(n.Log) != 3 || !reflect.DeepEqual(n, before) {
		t.Fatal("prefix removed before publication")
	}
	candidate, err = Replay(candidate, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(candidate, 4); err == nil {
		t.Fatal("missing committed suffix accepted")
	}
	if _, err := Add(n, []Entry{{5, 2, cmd("gap", "a", "x", 0)}}); err == nil {
		t.Fatal("gap accepted")
	}
	if _, err := Add(n, []Entry{{3, 2, cmd("conflict", "a", "x", 0)}}); err == nil {
		t.Fatal("divergent duplicate")
	}
	if got, err := Add(n, n.Log); err != nil || len(got.Log) != 3 {
		t.Fatal("same log replay", err)
	}
	for _, mutate := range []func(*Metadata, []byte){func(m *Metadata, b []byte) { b[0] ^= 1 }, func(m *Metadata, b []byte) { m.Index++ }, func(m *Metadata, b []byte) { m.Schema = 2 }, func(m *Metadata, b []byte) { m.Configuration = [32]byte{} }} {
		m := v.meta
		data := append([]byte(nil), b...)
		mutate(&m, data)
		r, err := Begin(m)
		if err == nil {
			_ = r.Append(0, data)
			_, err = r.Finish()
		}
		if err == nil {
			t.Fatal("corrupted snapshot accepted")
		}
	}
	wrong := v
	wrong.meta.Term = 8
	fresh, _ := state.New("admin")
	out, err := Install(Node{Shared: fresh, Log: n.Log}, wrong)
	if err != nil || len(out.Log) != 0 {
		t.Fatal("kept mismatched suffix", err)
	}
	if _, err := Install(Node{Shared: fresh}, Verified{}); err == nil {
		t.Fatal("unverified install")
	}
	m := v.meta
	m.Digest = sha256.Sum256([]byte("bad"))
	if _, err := Resume(m, make([]byte, m.Size+1)); err == nil {
		t.Fatal("oversized stage")
	}
}

func TestMissingAppliedLogAndWrongTermAreRejected(t *testing.T) {
	n, _, _ := fixture(t)
	bad := n
	bad.Log = nil
	if _, err := Replay(bad, 2); err == nil {
		t.Fatal("lost applied prefix accepted without snapshot")
	}
	bad = n
	bad.AppliedTerm = 2
	if _, err := Replay(bad, 2); err == nil {
		t.Fatal("wrong applied term accepted")
	}
}
