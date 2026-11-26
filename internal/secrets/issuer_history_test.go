// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestExplicitReplacementIssuerPreservesOriginalSignedApprovalAndLiveGrant(t *testing.T) {
	f := approved(t)
	f, grant := acquire(t, f, web(f), "original-task", 1)
	originalIssuer, _ := f.a.Issuer(public(f.issuer))
	originalRecords, _ := json.Marshal(f.a.records)
	nextKey := public(private(93))
	next, err := f.a.SetIssuer(f.c, "admin", f.a.Revision(), nextKey, originalIssuer.Enabled)
	if err != nil {
		t.Fatal(err)
	}
	retainedRecords, _ := json.Marshal(next.records)
	if retained, ok := next.Issuer(originalIssuer.Key); !ok || retained != originalIssuer || !bytes.Equal(originalRecords, retainedRecords) {
		t.Fatal("replacement rewrote original signature/policy/consumer leases")
	}
	if _, err := next.ReadSet(f.c, f.t, grant, 111); err != nil {
		t.Fatal("explicit replacement revoked original accepted grant", err)
	}
	raw, err := next.Encode()
	if err != nil {
		t.Fatal(err)
	}
	next, err = DecodeApprovals(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.ReadSet(f.c, f.t, grant, 111); err != nil {
		t.Fatal("snapshot lost historic grant", err)
	}
	// This metadata operation grants no node authentication. The control
	// approval permit and commit separately require the CURRENT member key;
	// retaining an old verifier row only keeps accepted original proofs valid.
}
