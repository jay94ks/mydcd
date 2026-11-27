// SPDX-License-Identifier: Apache-2.0

package state

import "testing"

// A user's catalog change may carry a root read before someone else's
// unrelated catalog change; the reducer checks its record's own CAS. A root
// from the future and other books keep the exact root CAS.
func TestCatalogUserOperationRootCAS(t *testing.T) {
	user := Command{Kind: Module, Key: "control/access", Actor: "user/alice"}
	if !catalogUserOperation(user) {
		t.Fatal("user catalog change")
	}
	for _, c := range []Command{
		{Kind: Module, Key: "control/apps", Actor: "user/alice"},
		{Kind: Module, Key: "control/access", Actor: "node/abc"},
		{Kind: ModuleReport, Key: "control/access", Actor: "user/alice"},
	} {
		if catalogUserOperation(c) {
			t.Fatal("not a user catalog change", c)
		}
	}
	s, err := New("admin")
	if err != nil {
		t.Fatal(err)
	}
	reduce := func(State, Command) (map[string][]byte, Code) {
		return map[string][]byte{"control/access": []byte("next")}, Applied
	}
	s.putObject("control/access", Object{Revision: 5, Generation: 1, Value: "root", Present: true})
	for _, tc := range []struct {
		expected uint64
		want     Code
	}{{3, Applied}, {5, Applied}, {6, ConditionFailed}} {
		c := user
		c.Expected = tc.expected
		candidate := clone(s)
		candidate.index = s.index + 1
		if _, r := applyModule(s, candidate, candidate.index, c, nil, reduce, nil); r.Code != tc.want {
			t.Fatal(tc.expected, r.Code)
		}
	}
}
