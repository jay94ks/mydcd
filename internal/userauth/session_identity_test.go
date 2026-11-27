// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

func TestOriginalSessionIdentityIncludesIndependentUserApproval(t *testing.T) {
	_, _, session, issuer := journalFixture(t)
	approved, err := access.ApproveSession(session, issuer.Private)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSession(approved, approved) || sameSession(session, approved) {
		t.Fatal("original identity ignored the separately signed user delegation")
	}
	changed := approved
	approval := *approved.Approval
	approval.Signature = append([]byte(nil), approval.Signature...)
	approval.Signature[ed25519.SignatureSize-1] ^= 1
	changed.Approval = &approval
	if sameSession(approved, changed) {
		t.Fatal("changed user approval matched the original session")
	}
}
