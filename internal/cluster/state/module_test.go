// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"slices"
	"strconv"
	"testing"
)

func TestRelatedControlPatchHasExplicitAuthorityAndOneAtomicReceipt(t *testing.T) {
	s, _ := New("admin")
	c := Command{Kind: Module, Actor: "admin", Epoch: 1, RequestID: "related", Key: "control/apps", Value: "typed"}
	patch := func(State, Command) (map[string][]byte, Code) {
		return map[string][]byte{"control/apps": []byte("app"), "control/vault": []byte("grants"), "control/volumes": []byte("consumers"), "control/vault/part/0": []byte("part")}, Applied
	}
	allow := func(_ State, input Command, keys []string) bool {
		return input == c && slices.Equal(keys, []string{"control/vault", "control/vault/part/0", "control/volumes"})
	}
	for _, admit := range []ModulePatchAuthorizer{nil, func(State, Command, []string) bool { return false }} {
		n, r, e := ApplyTransactional(s, 1, c, nil, patch, nil, nil, admit)
		if e != nil || r.Code != Invalid || n.Object(c.Key).Present || n.Object("control/vault").Present || n.Object("control/volumes").Present {
			t.Fatal("implicit related namespace", r, e)
		}
	}
	n, r, e := ApplyTransactional(s, 1, c, nil, patch, nil, nil, allow)
	if e != nil || r.Code != Applied {
		t.Fatal("explicit related patch", r, e)
	}
	for _, key := range []string{c.Key, "control/vault", "control/vault/part/0", "control/volumes"} {
		if n.Object(key).Revision != r.Index {
			t.Fatal("split ordinal", key)
		}
	}
	duplicate, original, e := ApplyTransactional(n, 2, c, nil, nil, nil, nil, nil)
	if e != nil || original != r || duplicate.Object("control/vault") != n.Object("control/vault") {
		t.Fatal("original related receipt", original, e)
	}
	for _, kind := range []string{"validator", "native"} {
		reduce := patch
		check := Validator(func(State, State, Command) error { return errors.New("related consumer mismatch") })
		if kind == "native" {
			check = nil
			reduce = func(State, Command) (map[string][]byte, Code) {
				return map[string][]byte{c.Key: []byte("app"), "network/escape": []byte("effect")}, Applied
			}
		}
		n, r, e := ApplyTransactional(s, 1, c, check, reduce, nil, nil, func(State, Command, []string) bool { return true })
		if e != nil || r.Code != Invalid || n.Object(c.Key).Present || n.Object("control/vault").Present || n.Object("network/escape").Present {
			t.Fatal("related patch escaped atomic rollback/isolation", kind, r, e)
		}
	}
	raw, e := Encode(n)
	restored, err := Decode(raw)
	if e != nil || err != nil || restored.Object("control/vault") != n.Object("control/vault") {
		t.Fatal("related snapshot", e, err)
	}
}

func TestModulePatchPreservesAtomicReceiptAndNamespace(t *testing.T) {
	s, _ := New("admin")
	c := Command{Kind: Module, Actor: "admin", Epoch: 1, RequestID: "module", Key: "control/access", Value: "{}"}
	patch := func(State, Command) (map[string][]byte, Code) {
		return map[string][]byte{c.Key: []byte("root"), c.Key + "/part/0": []byte("part")}, Applied
	}
	for i, test := range []struct {
		reduce Reducer
		check  Validator
	}{
		{},
		{reduce: func(State, Command) (map[string][]byte, Code) {
			return map[string][]byte{c.Key: []byte("root"), "network/escape": []byte("effect")}, Applied
		}},
		{reduce: patch, check: func(State, State, Command) error { return errors.New("policy rejection") }},
	} {
		n, result, err := ApplyReduced(s, 1, c, test.check, test.reduce)
		retained, found := n.LookupResult(c)
		if err != nil || result.Code != Invalid || !found || retained != result || n.Object(c.Key).Revision != 0 || n.Object(c.Key+"/part/0").Revision != 0 || n.Object("network/escape").Revision != 0 || s.Index() != 0 {
			t.Fatal("partial/rejected module state published", i, result, err)
		}
	}
	n, result, err := ApplyReduced(s, 1, c, nil, patch)
	if err != nil || result.Code != Applied || n.Object(c.Key).Revision != result.Revision || n.Object(c.Key+"/part/0").Revision != result.Revision {
		t.Fatal("module and receipt did not share ordinal", result, err)
	}
	duplicate, original, err := ApplyReduced(n, 2, c, nil, nil)
	if err != nil || original != result || duplicate.Object(c.Key).Revision != result.Revision {
		t.Fatal("duplicate requires reducer/re-executes", original, err)
	}
	forged := c
	forged.Kind, forged.RequestID = Mutate, "direct"
	_, denied, err := ApplyReduced(n, 2, forged, nil, patch)
	if err != nil || denied.Code != Invalid {
		t.Fatal("legacy admin bypassed control namespace", denied, err)
	}
	encoded, err := EncodeCommand(c)
	got, decodeErr := DecodeCommand(encoded)
	if err != nil || decodeErr != nil || got != c || Digest(got) != Digest(c) {
		t.Fatal("new schema1 kind changed original command", err, decodeErr)
	}
	raw, err := Encode(n)
	restored, decodeErr := Decode(raw)
	if err != nil || decodeErr != nil || restored.Object(c.Key+"/part/0") != n.Object(c.Key+"/part/0") {
		t.Fatal("existing snapshot rows lost module", err, decodeErr)
	}
}

func TestModuleActorAdmissionNeverGrantsLegacyRights(t *testing.T) {
	s, _ := New("admin")
	c := Command{Kind: Module, Actor: "user/proof-key", Epoch: 1, RequestID: "first", Key: "control/access", Value: "signed"}
	reduce := func(State, Command) (map[string][]byte, Code) {
		return map[string][]byte{c.Key: []byte("root")}, Applied
	}
	admit := func(_ State, input Command) bool { return input.Actor == c.Actor && input.Value == "signed" }
	for _, a := range []ModuleAuthorizer{nil, func(State, Command) bool { return false }} {
		n, result, err := ApplyAdmitted(s, 1, c, nil, reduce, a)
		_, _, _, exists := n.Principal(c.Actor)
		if err != nil || result.Code != Forbidden || exists || n.ReceiptCount() != 0 {
			t.Fatal("unauthenticated actor/receipt", result, err)
		}
	}
	n, result, err := ApplyAdmitted(s, 1, c, nil, reduce, admit)
	rights, epoch, _, known := n.Principal(c.Actor)
	if err != nil || result.Code != Applied || !known || rights != 0 || epoch != 1 {
		t.Fatal("module identity got legacy rights", result, err)
	}
	for _, kind := range []CommandKind{Mutate, SetRights, RotateLedger} {
		attempt := c
		attempt.Kind, attempt.RequestID = kind, "escape"
		attempt.Key, attempt.Value = "network/escape", "value"
		if kind != Mutate {
			attempt.Key, attempt.Value, attempt.Target, attempt.Rights = "", "", "admin", 0
		}
		next, denied, err := ApplyAdmitted(n, 2, attempt, nil, reduce, admit)
		if err != nil || denied.Code != Forbidden || next.Object("network/escape").Present {
			t.Fatal("module actor escaped", kind, denied, err)
		}
	}
	raw, err := Encode(n)
	restored, decodeErr := Decode(raw)
	if err != nil || decodeErr != nil {
		t.Fatal(err, decodeErr)
	}
	if got, found := restored.LookupResult(c); !found || got != result {
		t.Fatal("module receipt lost in snapshot", got, found)
	}
	next, got, err := ApplyAdmitted(restored, 2, c, nil, nil, nil)
	if err != nil || got != result || next.Object(c.Key).Revision != result.Revision {
		t.Fatal("duplicate re-executed", got, err)
	}
	conflict := c
	conflict.Value = "changed"
	_, got, err = ApplyAdmitted(n, 2, conflict, nil, reduce, admit)
	if err != nil || got.Code != RequestConflict {
		t.Fatal("conflicting original request", got, err)
	}
	full := clone(s)
	for i := 0; i < ModuleActorLimit-1; i++ {
		full.principals["user/occupied-"+strconv.Itoa(i)] = principal{Epoch: 1}
	}
	limited, denied, err := ApplyAdmitted(full, 1, c, nil, reduce, admit)
	_, _, _, created := limited.Principal(c.Actor)
	if err != nil || denied.Code != Forbidden || created || limited.ReceiptCount() != 0 {
		t.Fatal("module actor budget bypassed", denied, err)
	}
}
