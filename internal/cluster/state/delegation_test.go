// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"strings"
	"testing"
)

func TestExactDelegatedMutationKeepsRightsCASReceiptAndEpoch(t *testing.T) {
	for _, actor := range []string{"user/accepted", "node/accepted"} {
		t.Run(actor, func(t *testing.T) { exactDelegatedMutationKeepsRightsCASReceiptAndEpoch(t, actor) })
	}
}

func exactDelegatedMutationKeepsRightsCASReceiptAndEpoch(t *testing.T, actor string) {
	s, _ := New("admin")
	enrollment := Command{Kind: Module, Actor: actor, Epoch: 1, RequestID: "accepted", Key: "control/apps", Value: "accepted"}
	reduce := func(_ State, c Command) (map[string][]byte, Code) {
		return map[string][]byte{c.Key: []byte("checkpoint")}, Applied
	}
	admit := func(_ State, c Command) bool { return c.Kind == Module || c.Kind == ModuleWindow }
	var err error
	var result Result
	s, result, err = ApplyAdmitted(s, 1, enrollment, nil, reduce, admit)
	if err != nil || result.Code != Applied {
		t.Fatal(result, err)
	}
	command := Command{Actor: enrollment.Actor, Epoch: 1, RequestID: "rollout/step", Key: "network/bridge/tenant/app/net/node", Value: "frozen-goal"}
	delegate := func(_ State, c Command) bool { return c == command }
	// A broad module admission callback is not a mutation authorization callback.
	_, result, err = ApplyAdmitted(s, 2, command, nil, reduce, admit)
	if err != nil || result.Code != Forbidden {
		t.Fatal("module permission escaped", result, err)
	}
	for _, mutate := range []func(*Command){func(c *Command) { c.Actor = "user/unregistered" }, func(c *Command) { c.RequestID = "other" }, func(c *Command) { c.Key = "network/escape" }, func(c *Command) { c.Value = "modified" }, func(c *Command) { c.Expected = 1 }, func(c *Command) { c.Delete = true; c.Value = "" }, func(c *Command) { c.Kind = SetRights; c.Key = ""; c.Value = ""; c.Target = "admin"; c.Rights = Admin }} {
		c := command
		mutate(&c)
		_, r, e := ApplyDelegated(s, 2, c, nil, reduce, admit, delegate)
		if e != nil || r.Code != Forbidden {
			t.Fatal("non-exact delegation", c, r, e)
		}
	}
	// Exact authorization still cannot bypass validation or mutate input state.
	invalid, r, e := ApplyDelegated(s, 2, command, func(State, State, Command) error { return errors.New("typed policy") }, reduce, admit, delegate)
	if e != nil || r.Code != Invalid || invalid.Object(command.Key).Present || s.Index() != 1 {
		t.Fatal("validator bypass/partial write", r, e)
	}
	if got, ok := invalid.LookupResult(command); !ok || got != r {
		t.Fatal("rejection not retained")
	}
	n, original, e := ApplyDelegated(s, 2, command, nil, reduce, admit, delegate)
	rights, epoch, _, known := n.Principal(command.Actor)
	if e != nil || original.Code != Applied || !known || rights != 0 || epoch != 1 || !n.Object(command.Key).Present {
		t.Fatal("exact command", original, e)
	}
	duplicate, got, e := ApplyDelegated(n, 3, command, nil, nil, nil, nil)
	if e != nil || got != original || duplicate.Object(command.Key) != n.Object(command.Key) {
		t.Fatal("duplicate changed original result", got, e)
	}
	raw, e := Encode(n)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	if got, ok := restored.LookupResult(command); !ok || got != original {
		t.Fatal("snapshot lost original")
	}
	stale := command
	stale.RequestID = "stale"
	stale.Expected = 0
	_, got, e = ApplyDelegated(n, 3, stale, nil, reduce, admit, func(_ State, c Command) bool { return c == stale })
	if e != nil || got.Code != ConditionFailed {
		t.Fatal("delegation bypassed CAS", got, e)
	}
	window := Command{Kind: ModuleWindow, Actor: command.Actor, Epoch: 1, RequestID: "rotate", Key: "control/storage"}
	if strings.HasPrefix(actor, "node/") {
		_, denied, err := ApplyDelegated(n, n.Index()+1, window, nil, reduce, admit, delegate)
		if err != nil || denied.Code != Forbidden {
			t.Fatal("exact node removal granted module-window authority", denied, err)
		}
		enrollment.Actor, enrollment.RequestID = "user/rotation", "rotation-user"
		enrollment.Expected = n.Object(enrollment.Key).Revision
		n, r, e = ApplyAdmitted(n, n.Index()+1, enrollment, nil, reduce, admit)
		if e != nil || r.Code != Applied {
			t.Fatal("explicit window fixture user", r, e)
		}
		window.Actor = enrollment.Actor
	}
	rotated, r, e := ApplyDelegated(n, n.Index()+1, window, nil, reduce, admit, delegate)
	if e != nil || r.Code != Applied || rotated.ModuleEpoch() != 2 {
		t.Fatal("window", r, e)
	}
	_, expired, e := ApplyDelegated(rotated, rotated.Index()+1, command, nil, reduce, admit, delegate)
	if e != nil || expired.Code != Expired {
		t.Fatal("old delegated epoch resurrected", expired, e)
	}
}
