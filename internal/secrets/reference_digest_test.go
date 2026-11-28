// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func referenceDigest(t Tree, id string) [32]byte {
	h := sha256.New()
	t.WriteReferences(h, id)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func TestWriteReferencesFollowsValueRevisionsOnly(t *testing.T) {
	f := approved(t)
	o, _ := f.t.Object("runtime")
	group := o.Parent
	beforeSecret, beforeGroup := referenceDigest(f.t, "runtime"), referenceDigest(f.t, group)
	if beforeSecret != referenceDigest(f.t, "runtime") {
		t.Fatal("digest is not stable")
	}
	// A policy change (password change on the group) leaves the values.
	g, _ := f.t.Object(group)
	n, err := f.t.BeginPasswordChange(f.c, "alice", group, "change", g.Revision)
	policy := mustTree(t, n, err)
	if referenceDigest(policy, "runtime") != beforeSecret || referenceDigest(policy, group) != beforeGroup {
		t.Fatal("policy change moved the value digest")
	}
	ref := o.Reference
	ref.Revision++
	n, err = f.t.PublishReference(f.c, "alice", "runtime", o.Revision, ref)
	f.t = mustTree(t, n, err)
	if referenceDigest(f.t, "runtime") == beforeSecret || referenceDigest(f.t, group) == beforeGroup {
		t.Fatal("new value revision not seen through the secret and its group")
	}
	var missing bytes.Buffer
	f.t.WriteReferences(&missing, "no-such-object")
	if missing.Len() == 0 {
		t.Fatal("missing object wrote nothing")
	}
}
