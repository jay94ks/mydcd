// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// Real request proof/session scope logic; not an actual transport/quorum or
// registry listener proof. E5's native fixture consumes the same service.
func TestRegistryMetadataReadRequiresExplicitTenantAndCurrentSessionRead(t *testing.T) {
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
	session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(session))
	svc := Service{Policy: control.Policy{Cluster: client.Cluster, Issuers: [][32]byte{issuer.Public}}}
	binding := userBinding{key: session.Key, challenge: [32]byte{1}}
	for _, test := range []struct {
		request Request
		want    string
	}{
		{Request{Method: "registries", Tenant: "tenant"}, "ok"},
		{Request{Method: "registries", Tenant: "tenant", After: "tenant/private"}, "ok"},
		{Request{Method: "registries"}, "denied"},
		{Request{Method: "registries", Tenant: "other"}, "denied"},
		{Request{Method: "registries", Tenant: "tenant", Node: "node-a"}, "denied"},
		{Request{Method: "registries", Tenant: "tenant", After: strings.Repeat("a", 513)}, "denied"},
		{Request{Method: "external-registries", Tenant: "tenant"}, "ok"},
		{Request{Method: "external-registry-pulls", Tenant: "tenant"}, "ok"},
		{Request{Method: "external-registry-pulls"}, "denied"},
		{Request{Method: "external-registry-pulls", Tenant: "other"}, "denied"},
		{Request{Method: "external-registry-pulls", Tenant: "tenant", Node: "node-a"}, "denied"},
		{Request{Method: "external-registry-pulls", Tenant: "tenant", ImageResolve: &control.ImageResolveQuery{Ref: "busybox"}}, "denied"},
		{Request{Method: "external-registry-pulls", Tenant: "tenant", After: strings.Repeat("a", 513)}, "denied"},
		{Request{Method: "external-registries", Tenant: "tenant", After: "tenant/private"}, "ok"},
		{Request{Method: "external-registries"}, "denied"},
		{Request{Method: "external-registries", Tenant: "other"}, "denied"},
		{Request{Method: "external-registries", Tenant: "tenant", Node: "node-a"}, "denied"},
		{Request{Method: "external-registries", Tenant: "tenant", After: strings.Repeat("a", 513)}, "denied"},
	} {
		raw, err := requestBody(test.request)
		if err != nil {
			t.Fatal(err)
		}
		envelope := Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, binding.challenge, raw))}
		if got := svc.execute(catalog, binding, test.request, envelope); got.Code != test.want {
			t.Fatal(test.request, got.Code, test.want)
		}
	}
	session.Scopes[0].Actions = []access.Action{access.ManageRegistry}
	session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(session))
	request := Request{Method: "registries", Tenant: "tenant"}
	raw, _ := requestBody(request)
	envelope := Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, binding.challenge, raw))}
	if svc.execute(catalog, binding, request, envelope).Code != "ok" {
		t.Fatal("registry manager could not read its public maintenance summary")
	}
	session.Scopes[0].Actions = []access.Action{access.ManageVolumes}
	session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(session))
	envelope = Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, binding.challenge, raw))}
	if svc.execute(catalog, binding, request, envelope).Code != "denied" {
		t.Fatal("system admin bypassed current session ceiling")
	}
}
