// SPDX-License-Identifier: Apache-2.0

package registryclient

import "testing"

func TestPublicPullOutcomeNeverCopiesArbitraryOwnError(t *testing.T) {
	if code := ResultCode(&Error{Code: "secret-body"}); code != "UNAVAILABLE" {
		t.Fatal("foreign code exposed", code)
	}
	for _, event := range []PullOutcome{{"load", "OK"}, {"resolve", "UNAUTHORIZED"}, {"load", "IMAGE_LOAD_FAILED"}} {
		if !event.Valid() {
			t.Fatal(event)
		}
	}
	for _, event := range []PullOutcome{{"resolve", "OK"}, {"login", "OK"}, {"load", "secret-body"}} {
		if event.Valid() {
			t.Fatal(event)
		}
	}
}
