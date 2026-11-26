// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// Exercise the real request authorization adapter without claiming transport,
// source staging or actual execution. The actual MYDCP path is an L1 final test.
func TestCheckerLifecycleMetadataQueryRequiresExplicitTenantAndScope(t *testing.T) {
	_, client, session, issuer := journalFixture(t)
	catalog, err := access.New(client.Self.Public)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = catalog.Enroll(client.Self.Public, access.User{ID: session.User, Username: session.User, Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: client.Self.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = catalog.CreateTenant(session.User, "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.ManageServices}}}
	session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(session))
	svc := Service{Policy: control.Policy{Cluster: client.Cluster, Issuers: [][32]byte{issuer.Public}}}
	binding := userBinding{key: session.Key, challenge: [32]byte{1}}
	for _, test := range []struct {
		query Request
		want  string
	}{
		{Request{Method: "lifecycles", Tenant: "tenant"}, "ok"},
		{Request{Method: "lifecycles", Tenant: "tenant", After: "script/ready/00000000000000000001"}, "ok"},
		{Request{Method: "lifecycles"}, "denied"},
		{Request{Method: "lifecycles", Tenant: "other"}, "denied"},
		{Request{Method: "lifecycles", Tenant: "tenant", Node: "node-a"}, "denied"},
		{Request{Method: "lifecycles", Tenant: "tenant", After: strings.Repeat("a", 513)}, "denied"},
	} {
		raw, err := requestBody(test.query)
		if err != nil {
			t.Fatal(err)
		}
		e := Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, binding.challenge, raw))}
		if got := svc.execute(catalog, binding, test.query, e); got.Code != test.want {
			t.Fatal(test.query, got.Code, test.want)
		}
	}
	session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(session))
	q := Request{Method: "lifecycles", Tenant: "tenant"}
	raw, _ := requestBody(q)
	e := Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, binding.challenge, raw))}
	if svc.execute(catalog, binding, q, e).Code != "denied" {
		t.Fatal("limited system admin bypassed lifecycle metadata scope")
	}
}
