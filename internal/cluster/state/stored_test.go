// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"testing"
)

// store is what the FSM keeps on disk: rows under StoredPrefix plus a head.
type store struct {
	head []byte
	rows map[string][]byte
}

func (st *store) write(t *testing.T, s State, c *Changes) {
	t.Helper()
	writes := map[string][]byte{}
	head, err := StoredWrites(s, c, writes)
	if err != nil {
		t.Fatal(err)
	}
	st.head = head
	for k, v := range writes {
		if v == nil {
			delete(st.rows, k)
		} else {
			st.rows[k] = v
		}
	}
}

func (st *store) load(t *testing.T) State {
	t.Helper()
	s, err := DecodeStored(st.head, st.rows)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sameState(t *testing.T, a, b State, why string) {
	t.Helper()
	x, err := Encode(a)
	y, err2 := Encode(b)
	if err != nil || err2 != nil || !bytes.Equal(x, y) {
		t.Fatal(why, err, err2)
	}
}

// Random commands: writes, deletes, stale CAS, unknown actors, rights changes
// and ledger rotations. After each, only the touched rows are written; the
// stored state must equal the in-memory one, and so must a restart from it.
func TestStoredRowsFollowEveryApply(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	s := initial()
	st := &store{rows: map[string][]byte{}}
	all := NewChanges()
	all.AddAll(s)
	st.write(t, s, all)
	for i := 0; i < 600; i++ {
		key := fmt.Sprintf("workload/k%d", r.Intn(12))
		var c Command
		switch r.Intn(6) {
		case 0, 1:
			c = Command{Actor: "admin", Epoch: s.epoch("admin"), RequestID: fmt.Sprint("put-", i), Key: key, Value: fmt.Sprint(i), Expected: s.Object(key).Revision}
		case 2:
			c = Command{Actor: "admin", Epoch: s.epoch("admin"), RequestID: fmt.Sprint("del-", i), Key: key, Delete: true, Expected: s.Object(key).Revision}
		case 3:
			c = Command{Actor: "admin", Epoch: s.epoch("admin"), RequestID: fmt.Sprint("stale-", i), Key: key, Value: "x", Expected: s.Object(key).Revision + 1}
		case 4:
			c = Command{Actor: "admin", Epoch: s.epoch("admin"), RequestID: fmt.Sprint("rights-", i), Kind: SetRights, Target: "writer", Rights: Rights(r.Intn(4)), Expected: s.revision("writer")}
		case 5:
			c = Command{Actor: "admin", Epoch: s.epoch("admin"), RequestID: fmt.Sprint("rotate-", i), Kind: RotateLedger, Target: "admin", Expected: s.revision("admin")}
		}
		n, _, err := Apply(s, s.Index()+1, c)
		if err != nil {
			t.Fatal(err)
		}
		changes := NewChanges()
		changes.Add(n)
		st.write(t, n, changes)
		s = n
		if i%50 == 0 {
			sameState(t, st.load(t), s, fmt.Sprint("stored rows diverged at ", i))
		}
	}
	sameState(t, st.load(t), s, "stored rows diverged")
}

func (s State) epoch(actor string) uint64    { return s.principals[actor].Epoch }
func (s State) revision(actor string) uint64 { return s.principals[actor].Revision }

func TestStoredLastWriteOfOneKeyWins(t *testing.T) {
	s := clone(initial())
	s.index = 3
	s.putObject("workload/a", Object{Revision: 1, Generation: 1, Value: "one", Present: true})
	s.dropObject("workload/a")
	s.putObject("workload/a", Object{Revision: 3, Generation: 3, Value: "three", Present: true})
	st := &store{rows: map[string][]byte{}}
	c := NewChanges()
	c.Add(s)
	st.write(t, s, c)
	if got := st.load(t).Object("workload/a"); got.Value != "three" || c.Len() != 1 {
		t.Fatal("last write lost", got, c.Len())
	}
}

func TestStoredRejectedValidationKeepsRowsAndReader(t *testing.T) {
	s := initial()
	mustApply(t, &s, command("first", "a", "before", 0))
	reader := s
	deny := func(before, after State, c Command) error { return errors.New("policy") }
	n, result, err := ApplyChecked(s, s.Index()+1, command("second", "a", "after", s.Object("workload/a").Revision), deny)
	if err != nil || result.Code != Invalid || n.Object("workload/a").Value != "before" {
		t.Fatal("rejected write changed the object", result, err)
	}
	st := &store{rows: map[string][]byte{}}
	all := NewChanges()
	all.AddAll(s)
	st.write(t, s, all)
	c := NewChanges()
	c.Add(n)
	st.write(t, n, c)
	sameState(t, st.load(t), n, "rejected apply stored a different state")
	mustApply(t, &n, command("third", "a", "later", n.Object("workload/a").Revision))
	if reader.Object("workload/a").Value != "before" || n.Object("workload/a").Value != "later" {
		t.Fatal("an older State saw a later apply")
	}
}

// After a snapshot restore the FSM rewrites every row of the old and new
// states; rows only the old state had are deleted.
func TestStoredRewriteDropsRowsOfTheReplacedState(t *testing.T) {
	old := initial()
	mustApply(t, &old, command("gone", "only-old", "x", 0))
	next := initial()
	mustApply(t, &next, command("kept", "only-new", "y", 0))
	st := &store{rows: map[string][]byte{}}
	c := NewChanges()
	c.AddAll(old)
	st.write(t, old, c)
	c = NewChanges()
	c.AddAll(old)
	c.AddAll(next)
	st.write(t, next, c)
	sameState(t, st.load(t), next, "rewrite kept rows of the old state")
}

func TestStoredRowsRejectMisplacedOrUnknownRows(t *testing.T) {
	s := initial()
	mustApply(t, &s, command("a", "a", "x", 0))
	st := &store{rows: map[string][]byte{}}
	c := NewChanges()
	c.AddAll(s)
	st.write(t, s, c)
	for name, mutate := range map[string]func(map[string][]byte){
		"moved":   func(rows map[string][]byte) { rows[storedObjects+"workload/b"] = rows[storedObjects+"workload/a"] },
		"unknown": func(rows map[string][]byte) { rows[StoredPrefix+"x/y"] = []byte("{}") },
		"field": func(rows map[string][]byte) {
			rows[storedObjects+"workload/a"] = []byte(`{"Key":"workload/a","Extra":1}`)
		},
	} {
		rows := map[string][]byte{}
		for k, v := range st.rows {
			rows[k] = v
		}
		mutate(rows)
		if _, err := DecodeStored(st.head, rows); err == nil {
			t.Fatal(name, "accepted")
		}
	}
}
