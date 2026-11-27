// SPDX-License-Identifier: Apache-2.0

package control

import (
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// reducer is the shape of Book.Reduce.
type reducer = func(p Policy, s state.State, cmd state.Command) (map[string][]byte, state.Code)

// byKind is the Reduce of a book that accepts only some command kinds. Any
// other kind gets the verdict the single Reduce chain gave it before the
// books moved (R18 S2): a ModuleWindow is refused by reduceStorage (it
// accepts only the storage key), everything else is Invalid. Replay depends
// on these verdicts staying the same.
func byKind(m map[state.CommandKind]reducer) reducer {
	return func(p Policy, s state.State, cmd state.Command) (map[string][]byte, state.Code) {
		if r, ok := m[cmd.Kind]; ok {
			return r(p, s, cmd)
		}
		return refuseKind(p, s, cmd)
	}
}

func refuseKind(p Policy, s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind == state.ModuleWindow {
		return p.reduceStorage(s, cmd)
	}
	return nil, state.Invalid
}

// nodeActor reports whether cmd comes from a node key.
func nodeActor(cmd state.Command) bool { return strings.HasPrefix(cmd.Actor, "node/") }
