// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestCredentialAndPolicyQueryPayloadsCannotSelectOtherScopes(t *testing.T) {
	good := Request{Method: "user-credentials", TargetUser: "alice"}
	if !good.validMethodFields() || !good.validQuerySelectors() {
		t.Fatal("explicit target credential query rejected")
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.TargetUser = "" },
		func(r *Request) { r.Method = "node-cli-policy" },
		func(r *Request) { r.Method = "whoami" },
		func(r *Request) { r.Tenant = "tenant" },
		func(r *Request) { r.Node = "node-a" },
		func(r *Request) { r.After = "cursor" },
	} {
		bad := good
		mutate(&bad)
		if bad.validMethodFields() {
			t.Fatal("credential selector crossed method/scope boundary")
		}
	}
	if !(Request{Method: "node-cli-policy"}).validMethodFields() || !(Request{Method: "node-cli-policy"}).validQuerySelectors() {
		t.Fatal("policy query rejected")
	}
}

func TestCredentialQueryNeedsSystemAdminAndKeepsActorSeparateFromTarget(t *testing.T) {
	_, client, session, issuer := journalFixture(t)
	c, err := access.New(client.Self.Public)
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Enroll(client.Self.Public, access.User{ID: session.User, Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: client.Self.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.PutUser(session.User, 0, access.User{ID: "target", Username: "target.login", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte{7}, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := c.User(session.User)
	session.AccountRevision = u.Revision
	session.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.ManageCluster}}}
	session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(session))
	service := Service{Policy: control.Policy{Cluster: client.Cluster, Issuers: [][32]byte{issuer.Public}}}
	binding := userBinding{key: session.Key, challenge: [32]byte{1}}
	query := func(request Request) Reply {
		t.Helper()
		raw, err := requestBody(request)
		if err != nil {
			t.Fatal(err)
		}
		return service.execute(c, binding, request, Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, binding.challenge, raw))})
	}
	reply := query(Request{Method: "user-credentials", TargetUser: "target.login"})
	if reply.Code != "ok" || reply.CredentialUser == nil || reply.CredentialUser.ID != "target" || reply.CredentialUser.ID == session.User {
		t.Fatal("credential query confused authenticated actor with target", reply.Code)
	}
	reply.CredentialUser.Credentials[0].Enabled = false
	live, _ := c.User("target")
	if !live.Credentials[0].Enabled {
		t.Fatal("public reply aliased the committed catalog")
	}
	if reply := query(Request{Method: "node-cli-policy"}); reply.Code != "ok" || reply.NodeCLI == nil || reply.NodeCLI.Revision != 0 {
		t.Fatal("default policy query", reply.Code)
	}
	session.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}
	session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(session))
	if query(Request{Method: "user-credentials", TargetUser: "target.login"}).Code != "denied" || query(Request{Method: "node-cli-policy"}).Code != "denied" {
		t.Fatal("system admin bypassed signed credential scope")
	}
}
