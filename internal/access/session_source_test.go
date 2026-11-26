// SPDX-License-Identifier: Apache-2.0

package access

import (
	"crypto/ed25519"
	"testing"
)

func TestOriginalSessionEvidenceDoesNotBecomeCurrentAuthority(t *testing.T) {
	c := enrolled(t)
	s, issuer, _ := signedSession(c, "admin", "key", []Scope{{Tenant: "*", Actions: []Action{Read, Deploy}}})
	if VerifyOriginalSession(s, key(1), 150) != nil {
		t.Fatal("valid original signature/time")
	}
	issuer.Enabled = false
	if c.VerifySession(s, key(1), issuer, 201) == nil || VerifyOriginalSession(s, key(1), 150) != nil {
		t.Fatal("historical evidence and current authority conflated")
	}
	for _, at := range []int64{99, 200, 201} {
		if VerifyOriginalSession(s, key(1), at) == nil {
			t.Fatal("evidence accepted outside original lifetime", at)
		}
	}
	bad := s
	bad.User = "another-user"
	if VerifyOriginalSession(bad, key(1), 150) == nil || VerifyOriginalSession(s, key(2), 150) == nil {
		t.Fatal("historical source was rebound")
	}
	_, approvalKey := signingKey(7)
	approved, err := ApproveSession(s, approvalKey)
	if err != nil || VerifyOriginalSession(approved, key(1), 150) != nil {
		t.Fatal("valid original independent approval", err)
	}
	if ExactSessionDigest(approved) == ExactSessionDigest(s) || IssuedSessionDigest(approved) != IssuedSessionDigest(s) {
		t.Fatal("exact original digest discarded independent approval")
	}
	bad = approved
	a := *bad.Approval
	a.Session[0]++
	a.Signature = ed25519.Sign(approvalKey, SessionApprovalBytes(a))
	bad.Approval = &a
	if VerifyOriginalSession(bad, key(1), 150) == nil {
		t.Fatal("valid approval signature for another issued session accepted")
	}
}
