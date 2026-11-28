// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
)

// The account methods over the fixture's real loopback SFCP and SDK Raft:
// each carries Params and returns Data, and the system-admin ones follow the
// session's signed scope rather than the account's role alone.
func TestAccountMethodsActualWire(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	f.session.Scopes = fullUserScopes()
	f.session.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(f.session))
	if err := f.service.Serve(); err != nil {
		t.Fatal(err)
	}
	for !f.engines[0].IsLeader() {
		_ = f.engines[1].TransferLeadership(f.ctx, f.peers[0].ID, f.peers[0].Endpoint)
		if f.ctx.Err() != nil {
			t.Fatal(f.ctx.Err())
		}
		time.Sleep(50 * time.Millisecond)
	}
	peer, session := f.peers[0], f.session
	users, err := f.client.Users(f.ctx, peer, session, "")
	if err != nil || len(users.Users) == 0 || users.Revision == 0 {
		t.Fatal("users", err)
	}
	if self, err := f.client.MyCredentials(f.ctx, peer, session); err != nil || self.ID != session.User {
		t.Fatal("my-credentials", err)
	}
	u, err := f.client.UserCredentials(f.ctx, peer, session, "admin")
	if err != nil || u.ID != "admin" || len(u.Credentials) == 0 {
		t.Fatal("user-credentials", err)
	}
	if _, err := f.client.UserCredentials(f.ctx, peer, session, "nobody"); err == nil {
		t.Fatal("unknown user")
	}
	if p, err := f.client.NodeCLIPolicy(f.ctx, peer, session); err != nil || p.DisableNodeCLIOperation {
		t.Fatal("node-cli-policy", err)
	}
	var refused *Error
	if _, err := f.client.TenantRetirement(f.ctx, peer, session, "missing", ""); !errors.As(err, &refused) {
		t.Fatal("retirement of a missing tenant", err)
	}
	if _, err := f.client.TenantMembers(f.ctx, peer, session, "missing", ""); err == nil {
		t.Fatal("members of a missing tenant")
	}
	if _, err := f.client.Users(f.ctx, peer, session, strings.Repeat("x", 513)); err == nil {
		t.Fatal("unbounded cursor sent")
	}
	// A signed read-only scope still bounds a system administrator.
	narrow := session
	narrow.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}
	narrow.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(narrow))
	if _, err := f.client.Users(f.ctx, peer, narrow, ""); err == nil {
		t.Fatal("users beyond scope")
	}
	if _, err := f.client.UserCredentials(f.ctx, peer, narrow, "admin"); err == nil {
		t.Fatal("user-credentials beyond scope")
	}
	if _, err := f.client.NodeCLIPolicy(f.ctx, peer, narrow); err == nil {
		t.Fatal("node-cli-policy beyond scope")
	}
	if self, err := f.client.MyCredentials(f.ctx, peer, narrow); err != nil || self.ID != session.User {
		t.Fatal("own credentials need no admin scope", err)
	}
}
