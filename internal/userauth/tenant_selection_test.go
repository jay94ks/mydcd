// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
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
	user := UserView{ID: session.User, Username: session.User, SystemAdmin: true}
	read := func() SelectTenantReply {
		reply, code := service.selectTenantOf(c, user, session, time.Now().Unix(), "tenant")
		if code != "ok" {
			t.Fatal("select-tenant refused", code)
		}
		return reply
	}
	reply := read()
	tenant, _ = c.Tenant("tenant")
	if reply.Revision != tenant.Revision || len(reply.AllowedNodes) != 2 {
		t.Fatal("missing current tenant fields", reply)
	}
	reply.AllowedNodes[0] = "mutated"
	if again := read(); again.AllowedNodes[0] != "node-a" {
		t.Fatal("returned nodes alias catalog")
	}
	c, err = c.SetNodes(session.User, "tenant", tenant.Revision, []string{"node-b"})
	if err != nil {
		t.Fatal(err)
	}
	reply = read()
	if len(reply.AllowedNodes) != 1 || reply.AllowedNodes[0] != "node-b" {
		t.Fatal("stale node placement", reply)
	}
	listed := service.tenantsOf(c, user, session, time.Now().Unix())
	if len(listed.Tenants) != 1 || len(listed.Tenants[0].AllowedNodes) != 1 || listed.Tenants[0].AllowedNodes[0] != "node-b" {
		t.Fatal("list differs from select", listed)
	}
	if _, code := service.selectTenantOf(c, user, session, time.Now().Unix(), "missing"); code != "denied" {
		t.Fatal("unknown tenant selected", code)
	}
}
