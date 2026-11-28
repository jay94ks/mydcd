// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/binary"
	"io"
)

// WriteReferences writes, in a fixed order, the value references of the
// object id: for a Secret its own, for a Group those of every Secret under
// it. It writes no value. Two writes are equal exactly when every Secret
// selected through id still points at the same value revision, so a planner
// can tell that an app bound earlier now selects newer values. A missing
// object writes only its id; the plan's own checks still refuse it later.
func (t Tree) WriteReferences(w io.Writer, id string) {
	t.writeReferences(w, id, 0, map[string]bool{})
}

func (t Tree) writeReferences(w io.Writer, id string, depth int, seen map[string]bool) {
	writeString(w, id)
	o, ok := t.objects[id]
	if !ok || seen[id] || depth > maxDepth {
		writeString(w, "")
		return
	}
	seen[id] = true
	writeString(w, string(o.Kind))
	switch o.Kind {
	case Secret:
		writeString(w, o.Reference.Profile)
		writeString(w, o.Reference.Object)
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], o.Reference.Revision)
		_, _ = w.Write(n[:])
		binary.BigEndian.PutUint64(n[:], uint64(len(o.Reference.Keys)))
		_, _ = w.Write(n[:])
		for _, k := range o.Reference.Keys {
			writeString(w, k)
		}
	case Group:
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(o.Entries)))
		_, _ = w.Write(n[:])
		for _, child := range o.Entries {
			t.writeReferences(w, child, depth+1, seen)
		}
	}
}

func writeString(w io.Writer, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	_, _ = w.Write(n[:])
	_, _ = io.WriteString(w, s)
}
