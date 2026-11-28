// SPDX-License-Identifier: Apache-2.0

package state

import "testing"

// A user's certificate store change may carry a root read before another
// write to the store; the reducer checks its own record. A root from the
// future and node reports keep the exact root CAS.
func TestCertificateUserOperationRootCAS(t *testing.T) {
	user := Command{Kind: Module, Key: "control/certificates", Actor: "user/alice"}
	if !certificateUserOperation(user) {
		t.Fatal("user certificate change")
	}
	for _, c := range []Command{
		{Kind: Module, Key: "control/apps", Actor: "user/alice"},
		{Kind: Module, Key: "control/certificates", Actor: "node/abc"},
		{Kind: ModuleReport, Key: "control/certificates", Actor: "node/abc"},
	} {
		if certificateUserOperation(c) {
			t.Fatal("not a user certificate change", c)
		}
	}
	s, err := New("admin")
	if err != nil {
		t.Fatal(err)
	}
	reduce := func(State, Command) (map[string][]byte, Code) {
		return map[string][]byte{"control/certificates": []byte("next")}, Applied
	}
	s.putObject("control/certificates", Object{Revision: 5, Generation: 1, Value: "root", Present: true})
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
