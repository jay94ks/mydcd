// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNodeCLIPolicyCASAndSchemaOneRoundTrip(t *testing.T) {
	c := enrolled(t)
	before, _ := c.Encode()
	if bytes.Contains(before, []byte("NodeCLI")) || c.NodeCLI() != (NodeCLIPolicy{}) {
		t.Fatal("default policy changed legacy checkpoint bytes")
	}
	if _, err := c.SetNodeCLI("missing", 0, true); err != ErrDenied {
		t.Fatal("non-admin policy mutation", err)
	}
	n, err := c.SetNodeCLI("admin", 0, true)
	if err != nil || !n.NodeCLI().DisableNodeCLIOperation || n.NodeCLI().Revision != n.Revision() || c.NodeCLI() != (NodeCLIPolicy{}) {
		t.Fatal("policy transition mutated its original", err)
	}
	if _, err = n.SetNodeCLI("admin", 0, false); err != ErrConflict {
		t.Fatal("stale policy CAS accepted", err)
	}
	raw, err := n.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(raw)
	if err != nil || restored.NodeCLI() != n.NodeCLI() {
		t.Fatal("policy snapshot restore", err)
	}
	off, err := restored.SetNodeCLI("admin", restored.NodeCLI().Revision, false)
	if err != nil || off.NodeCLI().DisableNodeCLIOperation || off.NodeCLI().Revision <= n.NodeCLI().Revision {
		t.Fatal("policy disable lost transition ordinal", err)
	}
	var record catalogRecord
	_ = json.Unmarshal(raw, &record)
	record.NodeCLI.Revision = record.Revision + 1
	invalid, _ := json.Marshal(record)
	if _, err := Decode(invalid); err == nil {
		t.Fatal("future policy revision accepted")
	}
}

func TestNodeCLIRequiresIndependentUserApprovalOnlyAtNewRequestBoundary(t *testing.T) {
	c, grant, issuer, private := approvalFixture(t, Password)
	approved, err := ApproveSession(grant, private)
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.SetNodeCLI("admin", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.VerifySession(grant, grant.Cluster, issuer, 110) == nil ||
		c.VerifyAuthenticationSession(grant, grant.Cluster, issuer, 110) != nil ||
		c.VerifySession(approved, grant.Cluster, issuer, 110) != nil {
		t.Fatal("authentication and independently approved management were confused")
	}
	if c.AuthorizeAccepted(grant, grant.Cluster, 110, "tenant", Deploy, "") != nil ||
		c.AuthorizeAcceptedCleanup(grant, grant.Cluster, 110, "tenant", Deploy) != nil {
		t.Fatal("enabling policy invalidated a committed original grant")
	}
	// A node holding only its own key can issue a grant with any proof key,
	// but cannot sign a delegation with this account's registered user key.
	forged := grant
	forged.ID, forged.Key = "forged-admin", issuer.Key
	forged = resign(forged)
	if c.VerifySession(forged, grant.Cluster, issuer, 110) == nil {
		t.Fatal("node-issued session alone granted management permission")
	}
	bound := c.WithNodeKeys([][32]byte{approved.Approval.PublicKey})
	if bound.VerifySession(approved, grant.Cluster, issuer, 110) == nil || bound.VerifyManagementApproval(approved) == nil {
		t.Fatal("registered node key reused as independent user approval")
	}
	if bound.AuthorizeAccepted(approved, grant.Cluster, 110, "tenant", Deploy, "") != nil {
		t.Fatal("membership context rewrote already committed user approval")
	}
	if c.VerifySession(approved, grant.Cluster, issuer, 110) != nil {
		t.Fatal("membership context mutated another catalog view")
	}
	viewer := member(t, c, "tenant", "alice", Viewer, true)
	if viewer.VerifySession(approved, grant.Cluster, issuer, 110) == nil {
		t.Fatal("viewer acquired administrator management session")
	}
	other := tenant(t, c, "other")
	other = member(t, other, "other", "alice", Viewer, true)
	wide := approved
	wide.Scopes = []Scope{{Tenant: "*", Actions: []Action{Read, Deploy}}}
	wide = resign(wide)
	wide, err = ApproveSession(wide, private)
	if err != nil || other.AuthorizeSession(wide, grant.Cluster, issuer, 110, "other", Read, "") == nil || other.AuthorizeSession(wide, grant.Cluster, issuer, 110, "tenant", Deploy, "") != nil {
		t.Fatal("manager role leaked into a different tenant", err)
	}
}

func TestNodeCLIPreservesAnIndependentAdministratorKey(t *testing.T) {
	c := enrolled(t)
	c, err := c.SetNodeCLI("admin", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := c.User("admin")
	u.Credentials = []Credential{{ID: "password", Method: Password, VerifierRef: "backend", Enabled: true}}
	u.Revision = 0
	if _, err = c.PutUser("admin", c.users["admin"].Revision, u); err != ErrDenied {
		t.Fatal("last independent administrator key was removed", err)
	}
	if c.WithNodeKeys([][32]byte{c.users["admin"].Credentials[0].PublicKey}).ValidateNodeCLI() == nil {
		t.Fatal("installing last admin key as a node key locked policy management")
	}
	passwordOnly := enrolled(t)
	u, _ = passwordOnly.User("admin")
	u.Credentials = []Credential{{ID: "password", Method: Password, VerifierRef: "backend", Enabled: true}}
	passwordOnly = put(t, passwordOnly, "admin", u)
	if _, err := passwordOnly.SetNodeCLI("admin", 0, true); err != ErrDenied {
		t.Fatal("policy enabled without a usable registered administrator key", err)
	}
}
