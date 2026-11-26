// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNodeShellPolicyDefaultsBoundsAndOwnedNodeGrants(t *testing.T) {
	p := DefaultNodeShellPolicy()
	if !p.Valid() || p.Enabled || p.MaxSessions != 4 || p.IdleSeconds != 1800 {
		t.Fatal("unsafe default")
	}
	var err error
	p, err = p.SetNode(0, NodeShellNode{Node: "node-b", Shell: "on"})
	if err != nil {
		t.Fatal(err)
	}
	if _, enabled := p.Node("node-a"); enabled {
		t.Fatal("cluster off inherited as on")
	}
	if n, enabled := p.Node("node-b"); !enabled || n.Sudo {
		t.Fatal("explicit on/default sudo")
	}
	nodes := []string{"node-b"}
	p, err = p.SetGrant(p.Revision, NodeShellGrant{User: "alice", Nodes: nodes})
	if err != nil {
		t.Fatal(err)
	}
	nodes[0] = "node-c"
	if p.Grants[0].Nodes[0] != "node-b" {
		t.Fatal("grant aliases input")
	}
	copy := p.Clone()
	copy.Grants[0].Nodes[0] = "node-c"
	copy.Nodes[0].Sudo = true
	if p.Grants[0].Nodes[0] != "node-b" || p.Nodes[0].Sudo {
		t.Fatal("clone aliases policy")
	}
	for _, change := range []NodeShellPolicy{{Account: NodeShellAccount, MaxSessions: 0, IdleSeconds: 1800}, {Account: NodeShellAccount, MaxSessions: 17, IdleSeconds: 1800}, {Account: NodeShellAccount, MaxSessions: 4, IdleSeconds: 59}, {Account: NodeShellAccount, MaxSessions: 4, IdleSeconds: 86401}, {Account: "root", MaxSessions: 4, IdleSeconds: 1800}} {
		if change.Valid() {
			t.Fatal("invalid bound/account")
		}
	}
	if _, err = p.SetGlobal(0, true, 4, 1800); err != ErrConflict {
		t.Fatal("stale CAS", err)
	}
	if _, err = p.SetGrant(p.Revision, NodeShellGrant{User: "alice", Nodes: []string{"node-b", "node-b"}}); err == nil {
		t.Fatal("duplicate nodes")
	}
}
func TestNodeShellPermissionIsExplicitNodeScopedAndNeverTenantRole(t *testing.T) {
	c := tenant(t, enrolled(t), "tenant")
	c = put(t, c, "admin", user("alice", false))
	c = member(t, c, "tenant", "alice", Manager, true)
	session, issuer, _ := signedSession(c, "alice", "key", []Scope{{Tenant: "*", Actions: []Action{NodeShell}}})
	p := DefaultNodeShellPolicy()
	p, _ = p.SetGrant(0, NodeShellGrant{User: "alice", Nodes: []string{"node-b"}})
	if c.AuthorizeNodeShell(session, key(1), issuer, 100, "node-b", p) != nil {
		t.Fatal("explicit node denied")
	}
	if c.AuthorizeNodeShell(session, key(1), issuer, 100, "node-c", p) == nil {
		t.Fatal("manager inferred foreign shell grant")
	}
	read := session
	read.Scopes = []Scope{{Tenant: "tenant", Actions: []Action{Deploy, Read, ManageMembers}}}
	read = resign(read)
	if c.AuthorizeNodeShell(read, key(1), issuer, 100, "node-b", p) == nil {
		t.Fatal("tenant scope created host permission")
	}
	if ValidateScopes([]Scope{{Tenant: "tenant", Actions: []Action{NodeShell}}}) {
		t.Fatal("tenant NodeShell token accepted")
	}
	p, _ = p.SetGrant(p.Revision, NodeShellGrant{User: "alice"})
	if c.AuthorizeNodeShell(session, key(1), issuer, 100, "node-b", p) == nil {
		t.Fatal("grant revocation bypassed")
	}
	admin, issuer, _ := signedSession(c, "admin", "key", []Scope{{Tenant: "*", Actions: []Action{NodeShell}}})
	if c.AuthorizeNodeShell(admin, key(1), issuer, 100, "node-c", p) != nil {
		t.Fatal("current system administrator denied")
	}
}
func TestNodeShellAbsentPolicyDoesNotChangeLegacyCatalogOrSessionBytes(t *testing.T) {
	c := enrolled(t)
	before, _ := c.Encode()
	if DefaultNodeShellPolicy().Enabled {
		t.Fatal("default on")
	}
	after, _ := c.Encode()
	if !bytes.Equal(before, after) || bytes.Contains(after, []byte("NodeShell")) {
		t.Fatal("new policy rewrote legacy catalog")
	}
	original, _, _ := signedSession(c, "admin", "key", []Scope{{Tenant: "*", Actions: []Action{Read, ManageCluster}}})
	raw, _ := json.Marshal(original)
	var restored Session
	if json.Unmarshal(raw, &restored) != nil {
		t.Fatal("session decode")
	}
	round, _ := json.Marshal(restored)
	if !bytes.Equal(raw, round) {
		t.Fatal("legacy session bytes changed")
	}
}
