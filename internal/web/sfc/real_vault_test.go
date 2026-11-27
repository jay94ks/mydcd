// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/userauth"
)

// Only the receiver's contract answers become reply codes; an expired
// session or a lost exchange stays an error.
func TestReplyCode(t *testing.T) {
	for _, code := range []string{"denied", "unknown"} {
		r, err := replyCode(userauth.Reply{}, &userauth.Error{Code: code})
		if err != nil || r.Code != code {
			t.Fatalf("%s: %+v %v", code, r, err)
		}
	}
	for _, code := range []string{"expired", "unavailable", "not-leader", "invalid", "transport", ""} {
		in := &userauth.Error{Code: code}
		if _, err := replyCode(userauth.Reply{}, in); !errors.Is(err, in) {
			t.Fatalf("%q became a reply: %v", code, err)
		}
	}
	if r, err := replyCode(userauth.Reply{Code: "ok"}, nil); err != nil || r.Code != "ok" {
		t.Fatalf("ok: %+v %v", r, err)
	}
}
