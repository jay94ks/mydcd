// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func windowFixture(t *testing.T) (State, Command, Reducer, ModuleAuthorizer) {
	t.Helper()
	s, _ := New("legacy-admin")
	s = clone(s)
	s.index = 300
	for i := 0; i < ModuleActorLimit-1; i++ {
		s.principals[fmt.Sprint("user/", i)] = principal{Epoch: 1, Revision: 1}
	}
	for i := 0; i < LedgerLimit; i++ {
		s.putRequest(requestKey{"user/0", fmt.Sprint(i)}, receipt{result: Result{Code: Applied, Index: 1}})
	}
	s.putRequest(requestKey{"legacy-admin", "original"}, receipt{result: Result{Code: Applied, Index: 2}})
	s.putObject("workload/held", Object{Revision: 3, Generation: 3, Value: "original-native-owner/pin", Present: true})
	c := Command{Kind: ModuleWindow, Actor: "user/new-admin-session", Epoch: 1, RequestID: "rotate", Key: "control/storage", Value: "signed-maintenance"}
	reduce := func(_ State, input Command) (map[string][]byte, Code) {
		return map[string][]byte{input.Key: []byte("window")}, Applied
	}
	admit := func(_ State, input Command) bool { return input.Value == c.Value }
	return s, c, reduce, admit
}

func TestModuleWindowReclaimsFullBudgetsAndFencesRetiredActors(t *testing.T) {
	s, c, reduce, admit := windowFixture(t)
	n, result, err := ApplyAdmitted(s, 301, c, nil, reduce, admit)
	if err != nil || result.Code != Applied || n.ModuleEpoch() != 2 || len(n.principals) != 1 || n.ReceiptCount() != 1 || n.Object("workload/held") != s.Object("workload/held") || s.ModuleEpoch() != 1 || len(s.principals) != ModuleActorLimit {
		t.Fatal("non-atomic window/budget/native mutation", result, err)
	}
	for _, oldActor := range []string{"user/0", "user/new-admin-session", "node/old-control"} {
		old := Command{Kind: Module, Actor: oldActor, RequestID: "late", Epoch: 1, Key: "control/access", Value: "signed-maintenance"}
		denied, r, err := ApplyAdmitted(n, 302, old, nil, reduce, admit)
		if err != nil || r.Code != Expired || len(denied.principals) != 1 || denied.ReceiptCount() != 1 {
			t.Fatal("old identity was re-admitted", oldActor, r, err)
		}
		old.Epoch = 2
		admitted, r, err := ApplyAdmitted(n, 302, old, nil, reduce, admit)
		rights, epoch, _, known := admitted.Principal(oldActor)
		if err != nil || r.Code != Applied || !known || rights != 0 || epoch != 2 {
			t.Fatal("new window was not reusable", oldActor, r, err)
		}
	}
	// The existing actor's full ledger can also request maintenance.
	c.Actor = "user/0"
	n, r, err := ApplyAdmitted(s, 301, c, nil, reduce, admit)
	if err != nil || r.Code != Applied || n.ModuleEpoch() != 2 {
		t.Fatal("full existing ledger cannot rotate", r, err)
	}
}

func TestModuleWindowRejectedCandidatesAllocateNothing(t *testing.T) {
	s, c, reduce, admit := windowFixture(t)
	for _, test := range []struct {
		name string
		edit func(*Command)
		a    ModuleAuthorizer
		r    Reducer
		v    Validator
	}{
		{name: "unproved", a: func(State, Command) bool { return false }},
		{name: "node", edit: func(c *Command) { c.Actor = "node/control" }},
		{name: "legacy", edit: func(c *Command) { c.Actor = "legacy-admin" }},
		{name: "CAS", edit: func(c *Command) { c.Expected = 123 }},
		{name: "root", edit: func(c *Command) { c.Key = "control/access" }},
		{name: "patch", r: func(State, Command) (map[string][]byte, Code) {
			return map[string][]byte{"control/storage": []byte("x"), "network/escape": []byte("x")}, Applied
		}},
		{name: "pending", r: func(State, Command) (map[string][]byte, Code) { return nil, ConditionFailed }},
		{name: "validator", v: func(State, State, Command) error { return errors.New("inconsistent typed root") }},
		{name: "future", edit: func(c *Command) { c.Epoch = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd, a, r := c, admit, reduce
			if test.edit != nil {
				test.edit(&cmd)
			}
			if test.a != nil {
				a = test.a
			}
			if test.r != nil {
				r = test.r
			}
			n, result, err := ApplyAdmitted(s, 301, cmd, test.v, r, a)
			want := clone(s)
			want.index = 301
			gotBytes, _ := Encode(n)
			wantBytes, _ := Encode(want)
			if err != nil || result.Code == Applied || !bytes.Equal(gotBytes, wantBytes) {
				t.Fatal("failed rotation changed authority/ledger/rows", result, err)
			}
		})
	}
}

func TestModuleWindowOriginalReceiptAndNextExplicitExpiry(t *testing.T) {
	s, c, reduce, admit := windowFixture(t)
	n, result, _ := ApplyAdmitted(s, 301, c, nil, reduce, admit)
	r, found := n.LookupResult(c)
	if !found || r != result {
		t.Fatal("lost maintenance receipt")
	}
	duplicate, r, err := ApplyAdmitted(n, 302, c, nil, nil, nil)
	if err != nil || r != result || duplicate.ModuleEpoch() != 2 || duplicate.Object(c.Key) != n.Object(c.Key) {
		t.Fatal("replayed maintenance", r, err)
	}
	changed := c
	changed.Value += "conflict"
	if _, ok := n.LookupResult(changed); ok {
		t.Fatal("digest collision")
	}
	_, r, _ = ApplyAdmitted(n, 302, changed, nil, reduce, admit)
	if r.Code != Expired {
		t.Fatal("changed old window executed", r)
	}
	second := c
	second.Epoch, second.Expected, second.RequestID = 2, 301, "rotate-next"
	next, r, err := ApplyAdmitted(n, 302, second, nil, reduce, admit)
	if err != nil || r.Code != Applied || next.ModuleEpoch() != 3 {
		t.Fatal(r, err)
	}
	if _, found := next.LookupResult(c); found || !next.ModuleExpired(c) {
		t.Fatal("expired old receipt retained as execution authority")
	}
	if _, found := next.LookupResult(second); !found {
		t.Fatal("new rotation receipt missing")
	}
}

func TestModuleWindowSnapshotCanonicalRestoreAndCodec(t *testing.T) {
	s, c, reduce, admit := windowFixture(t)
	oldBytes, _ := Encode(s)
	legacyBytes, _ := json.Marshal(rows(s))
	if !bytes.Equal(oldBytes, legacyBytes) || bytes.Contains(oldBytes, []byte(`"Window"`)) {
		t.Fatal("epoch1 snapshot changed")
	}
	n, result, _ := ApplyAdmitted(s, 301, c, nil, reduce, admit)
	raw, _ := Encode(n)
	restored, err := Decode(raw)
	r, found := restored.LookupResult(c)
	if err != nil || !found || r != result || restored.ModuleEpoch() != 2 {
		t.Fatal("window lost after restore", err)
	}
	reencoded, _ := Encode(restored)
	if !bytes.Equal(raw, reencoded) {
		t.Fatal("noncanonical window")
	}
	for _, edit := range []func(*moduleWindow){
		func(w *moduleWindow) { w.Epoch = 1 },
		func(w *moduleWindow) { w.ID = "" },
		func(w *moduleWindow) { w.Actor = "node/forged" },
		func(w *moduleWindow) { w.Result.Index = 999 },
		func(w *moduleWindow) { w.Result.Revision-- },
		func(w *moduleWindow) { w.Digest = [32]byte{} },
	} {
		bad := clone(n)
		edit(bad.window)
		b, _ := Encode(bad)
		if _, err := Decode(b); err == nil {
			t.Fatal("accepted malformed window")
		}
	}
	bad := clone(n)
	bad.principals["user/resurrected"] = principal{Epoch: 1}
	b, _ := Encode(bad)
	if _, err := Decode(b); err == nil {
		t.Fatal("accepted retired principal")
	}
	encoded, err := EncodeCommand(c)
	decoded, decodeErr := DecodeCommand(encoded)
	if err != nil || decodeErr != nil || decoded != c {
		t.Fatal("window command codec", err, decodeErr)
	}
	encoded[1] = byte(ModuleAppDown + 1)
	if _, err := DecodeCommand(encoded); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

func TestModuleWindowRetainsFailureUntilExplicitEpochChange(t *testing.T) {
	_, c, reduce, admit := windowFixture(t)
	s, _ := New("legacy-admin")
	denied := func(State, Command) (map[string][]byte, Code) { return nil, Forbidden }
	n, result, err := ApplyAdmitted(s, 1, c, nil, denied, admit)
	retained, found := n.LookupResult(c)
	if err != nil || result.Code != Forbidden || !found || retained != result || n.ModuleEpoch() != 1 {
		t.Fatal("failed request was not retained", result, err)
	}
	// Permission/preconditions may now allow the operation; the ORIGINAL failed
	// intent must still return its original outcome without running the reducer.
	replayed, r, err := ApplyAdmitted(n, 2, c, nil, reduce, admit)
	if err != nil || r != result || replayed.ModuleEpoch() != 1 || replayed.Object(c.Key).Present {
		t.Fatal("old denied intent became success", r, err)
	}
	conflict := c
	conflict.Value += "new-body"
	_, r, err = ApplyAdmitted(n, 2, conflict, nil, reduce, func(State, Command) bool { return true })
	if err != nil || r.Code != RequestConflict {
		t.Fatal("failed receipt lost digest conflict", r, err)
	}
	fresh := c
	fresh.RequestID = "explicit-new-window"
	next, r, err := ApplyAdmitted(n, 2, fresh, nil, reduce, admit)
	if err != nil || r.Code != Applied || next.ModuleEpoch() != 2 {
		t.Fatal("fresh approved intent failed", r, err)
	}
	if _, found := next.LookupResult(c); found || !next.ModuleExpired(c) {
		t.Fatal("failed old intent escaped epoch expiry")
	}
	full, old, _, auth := windowFixture(t)
	blocked, r, err := ApplyAdmitted(full, 301, old, nil, denied, auth)
	if err != nil || r.Code != LedgerFull || blocked.ModuleEpoch() != 1 {
		t.Fatal("unretained failure claimed a result", r, err)
	}
	if _, found := blocked.LookupResult(old); found {
		t.Fatal("capacity failure invented original receipt")
	}
}
