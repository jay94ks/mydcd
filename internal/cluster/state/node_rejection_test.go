// SPDX-License-Identifier: Apache-2.0

package state

import (
	"encoding/json"
	"testing"
)

func TestNodeRefusalReasonHasOneDeterministicCode(t *testing.T) {
	for code := NodeLastVoter; code <= NodeStillResponding; code++ {
		reason := RejectionReason(code)
		if reason == "" || !(Result{Code: code, Reason: reason}).ValidReason() {
			t.Fatal(code, reason)
		}
		if (Result{Code: code}).ValidReason() || (Result{Code: ConditionFailed, Reason: reason}).ValidReason() {
			t.Fatal("unbound reason", code)
		}
	}
	raw, err := json.Marshal(Result{Code: ConditionFailed})
	if err != nil || string(raw) != "{\"Code\":1,\"Index\":0,\"Revision\":0,\"Generation\":0}" {
		t.Fatal("old result shape changed", string(raw), err)
	}
}
