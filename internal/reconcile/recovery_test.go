// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"encoding/json"
	"testing"
)

func TestPinRestartAndPreparedAbort(t *testing.T) {
	b, _ := NewLeases(1, 2)
	l, _ := b.Acquire()
	b.Drain()
	data, _ := json.Marshal(b.Checkpoint())
	var j LeaseJournal
	if err := json.Unmarshal(data, &j); err != nil {
		t.Fatal(err)
	}
	r, err := RestoreLeases(j)
	if err != nil {
		t.Fatal(err)
	}
	if r.CanRetire() || r.Replace(2) == nil {
		t.Fatal("restart dropped live pin")
	}
	if _, err := r.Acquire(); err == nil {
		t.Fatal("restart forgot drain")
	}
	if err := r.Release(l); err != nil {
		t.Fatal(err)
	}
	if err := r.Replace(2); err != nil {
		t.Fatal(err)
	}
	newLease, _ := r.Acquire()
	if newLease.Token <= l.Token || r.Release(l) == nil {
		t.Fatal("stale pin became valid")
	}
	j.Active = append(j.Active, j.Active[0])
	if _, err := RestoreLeases(j); err == nil {
		t.Fatal("duplicate pin accepted")
	}
	s := desired(t, State{}, 1, 1, "old")
	s, op, _ := Plan(s)
	s = Stop(s)
	s, err = AbortPrepared(s, op.ID)
	if err != nil || s.Pending != nil {
		t.Fatal(err)
	}
	s, err = Resume(s)
	if err != nil {
		t.Fatal(err)
	}
	s, call := dispatched(t, s)
	if _, err := AbortPrepared(s, call.ID); err == nil {
		t.Fatal("aborted possible native effect")
	}
	bad := copyState(s)
	bad.Pending.ID = call.ID - 1
	if Validate(bad) == nil {
		t.Fatal("old operation accepted")
	}
}
