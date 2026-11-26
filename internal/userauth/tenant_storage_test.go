// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestTenantStorageStrictSelectorsAndSessionScope(t *testing.T) {
	valid := Request{Method: "tenant-storage", Tenant: "tenant", Node: "node-a", After: "cursor"}
	if !valid.validMethodFields() || !valid.validQuerySelectors() {
		t.Fatal("tenant root selector rejected")
	}
	for _, bad := range []Request{{Method: "tenant-storage"}, {Method: "tenant-storage", Tenant: "tenant", Node: "../node"}, {Method: "tenant-storage", Tenant: "tenant", After: strings.Repeat("a", 513)}, {Method: "tenant-storage", Tenant: "tenant", App: "foreign"}, {Method: "tenant-storage", Tenant: "tenant", NodeStorage: &control.NodeStorageSelection{Node: "node-a", ID: "hdd"}}, {Method: "tenant-storage", Tenant: "tenant", Secret: []byte("private")}} {
		if bad.validMethodFields() && bad.validQuerySelectors() {
			t.Fatal("mixed/invalid tenant root request accepted", bad.Method)
		}
	}
	_, client, session, issuer := journalFixture(t)
	users, err := access.New(client.Self.Public)
	if err != nil {
		t.Fatal(err)
	}
	users, err = users.Enroll(client.Self.Public, access.User{ID: session.User, Username: session.User, Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: client.Self.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	users, err = users.CreateTenant(session.User, "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	users, err = users.SetNodes(session.User, "tenant", tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	svc := Service{Policy: control.Policy{Cluster: client.Cluster, Issuers: [][32]byte{issuer.Public}}}
	binding := userBinding{key: session.Key, challenge: [32]byte{1}}
	for _, test := range []struct {
		action access.Action
		want   string
	}{{access.ManageVolumes, "ok"}, {access.ManageRegistry, "ok"}, {access.Read, "denied"}} {
		current := session
		current.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{test.action}}}
		current.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(current))
		request := Request{Method: "tenant-storage", Tenant: "tenant", Node: "node-a"}
		raw, err := requestBody(request)
		if err != nil {
			t.Fatal(err)
		}
		envelope := Envelope{Body: raw, Session: &current, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(current, binding.challenge, raw))}
		if got := svc.execute(users, binding, request, envelope); got.Code != test.want {
			t.Fatal(test.action, got.Code, test.want)
		}
	}
}
