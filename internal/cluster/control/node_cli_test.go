// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

// Uses the product reducer/admission/snapshot; membership and time are modeled.
// It does not claim real quorum, transport or owner/native execution evidence.
func TestNodeCLICommittedPolicyRejectsIssuerForgeryAndKeepsOriginalGrant(t *testing.T) {
	f := newNodeStorageFixture(t)
	original := f.sessions["admin"]
	f.apply("admin", "set-node-cli-policy", 0, NodeCLIChange{true}, state.Forbidden)
	approved, err := access.ApproveSession(original, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	f.sessions["admin"] = approved
	f.apply("admin", "set-node-cli-policy", 0, NodeCLIChange{true}, state.Applied)
	c, err := f.p.Catalog(f.s)
	if err != nil || !c.NodeCLI().DisableNodeCLIOperation || f.p.NodeCLIAllowed(f.s) {
		t.Fatal("committed policy is not enforced", err)
	}
	if c.AuthorizeAccepted(original, f.p.Cluster, 2, "", access.ManageCluster, "") != nil {
		t.Fatal("policy activation invalidated an already accepted grant")
	}
	policyRevision := c.NodeCLI().Revision
	f.sessions["admin"] = original
	f.apply("admin", "create-tenant", 0, TenantID{"unapproved"}, state.Forbidden)
	f.apply("admin", "set-node-cli-policy", policyRevision, NodeCLIChange{false}, state.Forbidden)
	f.sessions["admin"] = approved
	f.apply("admin", "set-node-cli-policy", 0, NodeCLIChange{false}, state.ConditionFailed)
	f.apply("manager", "set-node-cli-policy", policyRevision, NodeCLIChange{false}, state.Forbidden)

	// The issuer knows its own key and a forged proof key, but no registered
	// user signing key. Changing issue time to the original grant is no escape.
	forged := original
	forged.ID, forged.Key = "forged-admin", [32]byte(f.node.Public().(ed25519.PublicKey))
	forged.Signature = ed25519.Sign(f.node, access.SessionBytes(forged))
	raw, _ := ChangeBytes("set-node-cli-policy", "admin", policyRevision, NodeCLIChange{false})
	var change Change
	_ = json.Unmarshal(raw, &change)
	op := UserOperation{Schema: 1, Session: forged, At: 2, Epoch: f.s.ModuleEpoch(), RequestID: "forged-policy-off", RootRevision: f.s.Object(CatalogKey).Revision, Change: change}
	op.Signature = ed25519.Sign(f.node, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	if f.p.AdmitModule(f.s, cmd) {
		t.Fatal("node-only forged administrator command admitted")
	}
	if _, code := f.p.Reduce(f.s, cmd); code != state.Forbidden {
		t.Fatal("replica reducer accepted a forged administrator", code)
	}
	// Also exercise the old raw Change entry, not just signed UserOperation.
	rawCommand := state.Command{Kind: state.Module, Actor: hex.EncodeToString(approved.Approval.PublicKey[:]), Epoch: 1, RequestID: "raw-bypass", Key: CatalogKey, Expected: f.s.Object(CatalogKey).Revision, Value: string(raw)}
	if _, code := f.p.Reduce(f.s, rawCommand); code != state.Forbidden {
		t.Fatal("raw credential-key command bypassed disabled node CLI", code)
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil || f.p.NodeCLIAllowed(f.s) {
		t.Fatal("restored FSM lost policy", err)
	}
	f.apply("admin", "set-node-cli-policy", policyRevision, NodeCLIChange{false}, state.Applied)
	f.sessions["admin"] = original
	c, _ = f.p.Catalog(f.s)
	f.apply("admin", "set-node-cli-policy", c.NodeCLI().Revision, NodeCLIChange{true}, state.Forbidden)
}

func TestNodeCLIRejectsRegisteredNodeKeyAsUserApproval(t *testing.T) {
	f := newNodeStorageFixture(t)
	u, _ := f.users.User("admin")
	nodeKey := [32]byte(f.node.Public().(ed25519.PublicKey))
	u.Credentials = append(u.Credentials, access.Credential{ID: "installed-node-key", Method: access.PrivateKey, PublicKey: nodeKey, Enabled: true})
	u.Revision = 0
	f.apply("admin", "put-user", f.sessions["admin"].AccountRevision, u, state.Applied)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = c.User("admin")
	session := f.sessions["admin"]
	session.AccountRevision = u.Revision
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	approved, err := access.ApproveSession(session, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	f.sessions["admin"] = approved
	f.apply("admin", "set-node-cli-policy", 0, NodeCLIChange{true}, state.Applied)
	forged := session
	forged.Credential, forged.Key = "installed-node-key", nodeKey
	forged.Signature = ed25519.Sign(f.node, access.SessionBytes(forged))
	forged, err = access.ApproveSession(forged, f.node)
	if err != nil {
		t.Fatal(err)
	}
	c, err = f.p.Catalog(f.s)
	current, currentErr := f.p.Current(f.s)
	if err != nil || currentErr != nil || c.VerifySession(forged, f.p.Cluster, current.Issuer(forged.Issuer), 2) == nil {
		t.Fatal("node key became independent administrator approval", err, currentErr)
	}
}
