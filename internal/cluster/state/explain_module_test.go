// SPDX-License-Identifier: Apache-2.0

package state

import "testing"

func TestExplainModuleNamesTheRefusingStep(t *testing.T) {
	var s State
	c := Command{Kind: ModuleReport, Actor: "node/a", RequestID: "r", Epoch: 1, Key: "control/x", Value: "{}"}
	if got := ExplainModule(s, c, nil, nil, nil); got != "command" {
		t.Fatalf("no reducer: %q", got)
	}
	reduce := func(State, Command) (map[string][]byte, Code) {
		return map[string][]byte{"control/x": []byte("v")}, Applied
	}
	c.Expected = 7
	if got := ExplainModule(s, c, nil, reduce, nil); got != "cas" {
		t.Fatalf("stale expected: %q", got)
	}
	c.Expected = 0
	refuse := func(State, Command) (map[string][]byte, Code) { return nil, ConditionFailed }
	if got := ExplainModule(s, c, nil, refuse, nil); got != "reduce" {
		t.Fatalf("reducer refusal: %q", got)
	}
	related := func(State, Command) (map[string][]byte, Code) {
		return map[string][]byte{"control/x": []byte("v"), "control/y": []byte("w")}, Applied
	}
	if got := ExplainModule(s, c, nil, related, nil); got != "patch-admit" {
		t.Fatalf("unadmitted related key: %q", got)
	}
	if got := ExplainModule(s, c, nil, reduce, nil); got != "" {
		t.Fatalf("applies: %q", got)
	}
	if s.ReportLedgerFull("node/a", "control/x") {
		t.Fatal("an empty ledger is full")
	}
}
