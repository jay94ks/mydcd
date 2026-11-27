// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
)

// The pre-session methods over the fixture's real loopback SFCP and SDK
// Raft: each carries its request in Params and its answer in Data, and none
// of them can be reached as a session's typed query.
func TestLoginMethodsActualWire(t *testing.T) {
	for _, name := range []string{"server-version", "challenge", "login", "credential-challenge", "credential-login"} {
		if rule, typed := methodRules[name]; !typed || !rule.sessionless {
			t.Fatal("not a sessionless typed method", name)
		}
	}
	f := newVolumeFileWireFixture(t)
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
	if v, err := f.client.ServerVersion(f.ctx, f.peers[0]); err != nil || v.Protocol != 1 {
		t.Fatal("server-version", v, err)
	}
	ticket, selected, err := f.client.KeyLoginChallenge(f.ctx, f.peers[0], "admin", f.user.Public)
	if err != nil || ticket.Username != "admin" {
		t.Fatal("challenge", err)
	}
	proof := f.client.KeyLoginProof(ticket)
	proof.Signature = ed25519.Sign(f.user.Private, access.KeyProofBytes(proof))
	session, err := f.client.KeyLogin(f.ctx, selected, ticket, proof)
	if err != nil || session.User != "admin" || session.Key != f.user.Public {
		t.Fatal("login", err)
	}
	if _, _, err := f.client.KeyLoginChallenge(f.ctx, f.peers[0], "nobody", f.user.Public); err == nil {
		t.Fatal("challenge for an unknown user")
	}
	if _, _, err := f.client.CredentialChallenge(f.ctx, f.peers[0], "admin", "private-key", ""); err == nil {
		t.Fatal("credential challenge for a non-credential method")
	}
}
