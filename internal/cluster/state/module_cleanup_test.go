// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"slices"
	"testing"
)

// Native/source and positive closure are model inputs. This verifies only the
// actual atomic state/receipt boundary, not Docker or a lifecycle validator.
func TestTypedModuleCleanupRequiresExistingSourceAuthorityAndValidator(t *testing.T) {
	s, _ := New("admin")
	const source = "workload/task/original"
	s, initial, err := ApplyChecked(s, 1, Command{Actor: "admin", Epoch: 1, RequestID: "original", Key: source, Value: "original"}, nil)
	if err != nil || initial.Code != Applied {
		t.Fatal(initial, err)
	}
	original := s.Object(source)
	command := Command{Kind: Module, Actor: "admin", Epoch: 1, RequestID: "drain", Key: "control/resources", Value: "typed original source"}
	reduce := func(State, Command) (map[string][]byte, Code) {
		return map[string][]byte{command.Key: []byte("original mapping"), source: []byte("draining")}, Applied
	}
	allow := func(_ State, c Command, keys []string) bool {
		return c == command && slices.Equal(keys, []string{source})
	}
	validate := Validator(func(before, after State, c Command) error {
		if c != command || before.Object(source) != original || after.Object(source).Generation != original.Generation || after.Object(source).Value != "draining" {
			return errors.New("modeled exact source transition rejected")
		}
		return nil
	})
	for _, test := range []struct {
		name  string
		check Validator
		admit ModulePatchAuthorizer
	}{
		{"no-validator", nil, allow},
		{"no-authority", validate, nil},
		{"wrong-authority", validate, func(State, Command, []string) bool { return false }},
		{"rejected-source", func(State, State, Command) error { return errors.New("source mismatch") }, allow},
	} {
		t.Run(test.name, func(t *testing.T) {
			n, result, err := ApplyTransactional(s, 2, command, test.check, reduce, nil, nil, test.admit)
			if err != nil || result.Code != Invalid || n.Object(source) != original || n.Object(command.Key).Present {
				t.Fatal("invalid cleanup escaped atomic rejection", result, err)
			}
		})
	}
	n, result, err := ApplyTransactional(s, 2, command, validate, reduce, nil, nil, allow)
	if err != nil || result.Code != Applied || n.Object(source).Generation != original.Generation || n.Object(source).Revision != result.Index || n.Object(command.Key).Revision != result.Index {
		t.Fatal("typed original source/mapping did not commit atomically", result, err)
	}
	_, replayed, err := ApplyTransactional(n, 3, command, nil, nil, nil, nil, nil)
	if err != nil || replayed != result {
		t.Fatal("same cleanup required another native effect", replayed, err)
	}
	remove := command
	remove.RequestID, remove.Expected = "retire", n.Object(command.Key).Revision
	closed, removed, err := ApplyTransactional(n, 3, remove, func(State, State, Command) error { return nil }, func(State, Command) (map[string][]byte, Code) {
		return map[string][]byte{command.Key: []byte("closed original mapping"), source: nil}, Applied
	}, nil, nil, func(State, Command, []string) bool { return true })
	if err != nil || removed.Code != Applied || closed.Object(source).Present || closed.Object(source).Generation != original.Generation {
		t.Fatal("original source retirement floor", removed, err)
	}
	for _, key := range []string{source, "network/bridge/new-source"} {
		recreate := command
		recreate.RequestID, recreate.Expected = "new-"+key, closed.Object(command.Key).Revision
		bad, denied, err := ApplyTransactional(closed, 4, recreate, func(State, State, Command) error { return nil }, func(State, Command) (map[string][]byte, Code) {
			return map[string][]byte{command.Key: []byte("counterfeit"), key: []byte("new native")}, Applied
		}, nil, nil, func(State, Command, []string) bool { return true })
		if err != nil || denied.Code != Invalid || bad.Object(key) != closed.Object(key) || bad.Object(command.Key) != closed.Object(command.Key) {
			t.Fatal("module created/revived a native source", key, denied, err)
		}
	}
}
