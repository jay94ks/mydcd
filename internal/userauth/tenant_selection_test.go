// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"testing"
)

func TestSelectTenantReturnsCurrentOwnedAllowedNodesAndTenantCAS(t *testing.T) {
	_, client, session, issuer := journalFixture(t)
	c, err := access.New(client.Self.Public)
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Enroll(client.Self.Public, access.User{ID: session.User, Username: session.User, Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: client.Self.Public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant(session.User, "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	c, err = c.SetNodes(session.User, "tenant", tenant.Revision, []string{"node-a", "node-b"})
	if err != nil {
		t.Fatal(err)
	}
	service := Service{Policy: control.Policy{Cluster: client.Cluster, Issuers: [][32]byte{issuer.Public}}}
	binding := userBinding{key: session.Key, challenge: [32]byte{3}}
	read := func(method string) Reply {
		request := Request{Method: method, Tenant: "tenant"}
		if method == "tenants" {
			request.Tenant = ""
		}
		raw, err := requestBody(request)
		if err != nil {
			t.Fatal(err)
		}
		envelope := Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(client.Self.Private, access.RequestBytes(session, binding.challenge, raw))}
		return service.execute(c, binding, request, envelope)
	}
	reply := read("select-tenant")
	tenant, _ = c.Tenant("tenant")
	if reply.Code != "ok" || reply.TenantRevision != tenant.Revision || len(reply.TenantAllowedNodes) != 2 {
		t.Fatal("missing current tenant fields", reply)
	}
	reply.TenantAllowedNodes[0] = "mutated"
	if again := read("select-tenant"); again.TenantAllowedNodes[0] != "node-a" {
		t.Fatal("returned nodes alias catalog")
	}
	c, err = c.SetNodes(session.User, "tenant", tenant.Revision, []string{"node-b"})
	if err != nil {
		t.Fatal(err)
	}
	reply = read("select-tenant")
	if reply.Code != "ok" || len(reply.TenantAllowedNodes) != 1 || reply.TenantAllowedNodes[0] != "node-b" {
		t.Fatal("stale node placement", reply)
	}
	listed := read("tenants")
	if len(listed.Tenants) != 1 || len(listed.Tenants[0].AllowedNodes) != 1 || listed.Tenants[0].AllowedNodes[0] != "node-b" {
		t.Fatal("list differs from select", listed)
	}
}
