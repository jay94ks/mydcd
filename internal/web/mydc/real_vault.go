// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"errors"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Private Vault input (W1.2 step 2e). mydcd never relays SecretInput, so the
// input goes straight to the plan's receiver: over the socket when it is the
// pinned node, else to the receiver's own endpoint on a transport that trusts
// only that key (as `mydc vault write` does). Values and passwords are never
// stored or logged here; userauth wipes its encoded copy after sending.

func (c *realConn) WriteVault(ctx context.Context, tenant string, receiver config.Peer, q SecretWrite) (SecretWriteReply, error) {
	reply, err := c.secretInput(ctx, receiver, userauth.SecretRequest{Realm: q.Realm, ID: q.ID, Mode: q.Mode, Values: q.Values})
	if err != nil {
		return SecretWriteReply{}, err
	}
	return SecretWriteReply{Code: reply.Code, Observation: reply.VaultObservation}, nil
}

func (c *realConn) ApproveVault(ctx context.Context, tenant string, approver config.Peer, q VaultApprove) (string, error) {
	target := q.Target
	reply, err := c.secretInput(ctx, approver, userauth.SecretRequest{Realm: target.Realm, ID: target.ApprovalID, Mode: "approve", Target: &target,
		Password: q.Password, Origin: q.Origin, Selection: q.Selection})
	if err != nil {
		return "", err
	}
	return reply.Code, nil
}

func (c *realConn) secretInput(ctx context.Context, receiver config.Peer, q userauth.SecretRequest) (userauth.Reply, error) {
	const m = "secret-input"
	key, err := identity.ParseKey(receiver.Key)
	if err != nil || receiver.ID == "" {
		return userauth.Reply{}, fail(m, CodeInvalid, "receiver")
	}
	return realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		if mydcp.Identity(key) == c.peer.Key {
			return replyCode(u.WriteVault(ctx, c.peer, s, q))
		}
		if receiver.Endpoint == "" {
			return userauth.Reply{}, fail(m, CodeInvalid, "receiver has no endpoint")
		}
		peer := mydcp.Peer{ID: receiver.ID, Endpoint: receiver.Endpoint, Policy: mydcp.Policy{Key: mydcp.Identity(key), Respond: true}}
		mesh, err := mydcp.NewTransport(u.Self, u.Cluster, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
		if err != nil {
			return userauth.Reply{}, err
		}
		defer mesh.Close()
		u.Mesh, u.Peers = mesh, []mydcp.Peer{peer}
		return replyCode(u.WriteVault(ctx, peer, s, q))
	})
}

// replyCode keeps the receiver's contract answers (denied: the password was
// not accepted or the write was refused; unknown) as the reply's code, as
// the Conn contract has it. Anything else (a failed exchange, an expired
// session, not-leader, invalid) stays an error for realError.
func replyCode(reply userauth.Reply, err error) (userauth.Reply, error) {
	var e *userauth.Error
	if errors.As(err, &e) && (e.Code == "denied" || e.Code == "unknown") {
		reply.Code = e.Code
		return reply, nil
	}
	return reply, err
}
