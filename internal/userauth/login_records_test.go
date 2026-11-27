// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/loginlog"
)

func TestLoginRecordFieldsOnlyWhereTheyBelong(t *testing.T) {
	hint := &loginlog.Client{Client: "Firefox", Address: "203.0.113.5"}
	q := &loginlog.Query{Limit: 10}
	for _, c := range []struct {
		r  Request
		ok bool
	}{
		{Request{Schema: 1, Method: "login-records", LoginQuery: q}, true},
		{Request{Schema: 1, Method: "login-records"}, false},
		{Request{Schema: 1, Method: "login-records", LoginQuery: &loginlog.Query{User: "bob", Limit: 10}}, false},
		{Request{Schema: 1, Method: "login-records", LoginQuery: &loginlog.Query{Limit: 0}}, false},
		{Request{Schema: 1, Method: "login-records", LoginQuery: q, Tenant: "shop"}, false},
		{Request{Schema: 1, Method: "whoami", LoginQuery: q}, false},
	} {
		if got := c.r.validLoginFields(); got != c.ok {
			t.Errorf("%s %+v: valid=%v", c.r.Method, c.r, got)
		}
	}
	// The login client hint now travels in the login methods' own params.
	if !(KeyLoginQuery{LoginClient: hint}).Valid() || !(KeyLoginQuery{}).Valid() || (KeyLoginQuery{LoginClient: &loginlog.Client{Client: "a\x00b"}}).Valid() {
		t.Error("key login client hint")
	}
	cl := CredentialLoginQuery{Ticket: Ticket{AuthMethod: access.Password}, Secret: []byte("pw"), LoginClient: hint}
	if !cl.Valid() {
		t.Error("credential login client hint")
	}
	cl.LoginClient = &loginlog.Client{Client: "a\x00b"}
	if cl.Valid() {
		t.Error("bad credential login client hint accepted")
	}
}
