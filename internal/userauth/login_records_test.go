// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/loginlog"
)

func TestLoginRecordFieldsOnlyWhereTheyBelong(t *testing.T) {
	hint := &loginlog.Client{Client: "Firefox", Address: "203.0.113.5"}
	for _, c := range []struct {
		params string
		ok     bool
	}{
		{`{"Limit":10}`, true},
		{`{}`, false},
		{`{"User":"bob","Limit":10}`, false},
		{`{"Limit":0}`, false},
		{`{"Limit":10,"After":"x"}`, false},
	} {
		r := Request{Schema: 1, Method: "login-records", Params: json.RawMessage(c.params)}
		if _, typed, got := r.typedMethod(); !typed || got != c.ok {
			t.Errorf("login-records %s: valid=%v", c.params, got)
		}
	}
	if _, typed, ok := (Request{Schema: 1, Method: "own-sessions", Params: json.RawMessage(`{}`)}).typedMethod(); !typed || !ok {
		t.Error("own-sessions refused")
	}
	if _, _, ok := (Request{Schema: 1, Method: "login-records", Tenant: "shop", Params: json.RawMessage(`{"Limit":10}`)}).typedMethod(); ok {
		t.Error("login-records with a tenant accepted")
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
