// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// KeyLogin refuses, before any exchange, a proof that is not exactly
// KeyLoginProof(ticket) signed by the ticket's user key.
func TestKeyLoginRefusesForeignProofBeforeSending(t *testing.T) {
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	issuer, user, other := mustKey(t), mustKey(t), mustKey(t)
	c := Client{Self: self, Cluster: [32]byte{7}}
	peer := sfcp.Peer{ID: "node", Policy: sfcp.Policy{Key: sfcp.Identity(issuer.Public().(ed25519.PublicKey))}}
	ticket := Ticket{Schema: 1, Cluster: c.Cluster, User: "u1", Username: "alice", Credential: "key", AccountRevision: 1, SessionKey: self.Public, UserKey: [32]byte(user.Public().(ed25519.PublicKey)), Challenge: [32]byte{9}, Issuer: [32]byte(peer.Key), Deadline: 300}
	sign := func(p access.KeyProof, k ed25519.PrivateKey) access.KeyProof {
		p.Signature = ed25519.Sign(k, access.KeyProofBytes(p))
		return p
	}
	changed := c.KeyLoginProof(ticket)
	changed.Deadline++
	for name, proof := range map[string]access.KeyProof{
		"other key":     sign(c.KeyLoginProof(ticket), other),
		"changed field": sign(changed, user),
		"unsigned":      c.KeyLoginProof(ticket),
	} {
		if _, err := c.KeyLogin(context.Background(), peer, ticket, proof); !errors.Is(err, sfcp.ErrAdmission) {
			t.Fatal(name, err)
		}
	}
	wrongPeer := peer
	wrongPeer.Key = sfcp.Identity(other.Public().(ed25519.PublicKey))
	if _, err := c.KeyLogin(context.Background(), wrongPeer, ticket, sign(c.KeyLoginProof(ticket), user)); !errors.Is(err, sfcp.ErrAdmission) {
		t.Fatal("ticket from another issuer", err)
	}
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAttachSessionApprovalMatchesApproveSession(t *testing.T) {
	issuer, user := mustKey(t), mustKey(t)
	s := access.Session{Schema: 1, ID: "s1", Cluster: [32]byte{1}, User: "u1", Credential: "key", AccountRevision: 1, Key: [32]byte{2}, Issuer: [32]byte(issuer.Public().(ed25519.PublicKey)), IssuerEpoch: 1, IssuedAt: 1, ExpiresAt: 100, Scopes: []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}}
	s.Signature = ed25519.Sign(issuer, access.SessionBytes(s))
	local, err := access.ApproveSession(s, user)
	if err != nil {
		t.Fatal(err)
	}
	a := access.SessionApproval{Schema: 1, PublicKey: [32]byte(user.Public().(ed25519.PublicKey)), Session: access.IssuedSessionDigest(s)}
	a.Signature = ed25519.Sign(user, access.SessionApprovalBytes(a))
	remote, err := access.AttachSessionApproval(s, a)
	if err != nil || string(access.SessionApprovalBytes(*remote.Approval)) != string(access.SessionApprovalBytes(*local.Approval)) || string(remote.Approval.Signature) != string(local.Approval.Signature) {
		t.Fatal("attached approval differs", err)
	}
	if _, err := access.AttachSessionApproval(local, a); err == nil {
		t.Fatal("second approval accepted")
	}
	a.Session[0] ^= 1
	if _, err := access.AttachSessionApproval(s, a); err == nil {
		t.Fatal("approval for another session accepted")
	}
}
