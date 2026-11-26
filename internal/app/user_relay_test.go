// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func TestRealUserRelayHandoffAndCurrentUserReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	key := func(name string) *identity.Identity {
		t.Helper()
		id, err := identity.Create(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(id.Private) })
		return id
	}
	admin, alice, bob := key("admin"), key("alice"), key("bob")
	fixture := newManagedVoters(t, ctx, filepath.Join(root, "cluster"), admin, 3)
	clusterID, configs, peers := fixture.Cluster, fixture.Configs, fixture.Peers
	nodes := fixture.Nodes
	wait := func(check func() bool) {
		t.Helper()
		for !check() {
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	leader := -1
	findLeader := func() {
		t.Helper()
		wait(func() bool {
			for i, n := range nodes {
				if n != nil && n.Engine().IsLeader() {
					if _, err := n.Engine().Read(ctx, true); err == nil {
						leader = i
						return true
					}
				}
			}
			return false
		})
	}
	findLeader()
	policy := fixture.Policy
	catalog := func() access.Catalog {
		t.Helper()
		v, err := nodes[leader].Engine().Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		c, err := policy.Catalog(v.State)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	sequence := 0
	change := func(action, principal string, expected uint64, payload any) {
		t.Helper()
		sequence++
		fixture.Change(leader, fmt.Sprintf("setup-%d", sequence), action, expected, payload)
	}
	user := func(name string, id *identity.Identity, system bool) access.User {
		return access.User{ID: name, Username: name, Enabled: true, SystemAdmin: system, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: id.Public, Enabled: true}}}
	}
	change("put-user", "admin", 0, user("alice", alice, false))
	change("put-user", "admin", 0, user("bob", bob, true))
	change("create-tenant", "admin", 0, control.TenantID{ID: "one"})
	change("create-tenant", "admin", 0, control.TenantID{ID: "two"})
	change("set-membership", "admin", 0, access.Membership{Tenant: "one", User: "alice", Role: access.Manager, Enabled: true})
	change("set-membership", "admin", 0, access.Membership{Tenant: "two", User: "alice", Role: access.Viewer, Enabled: true})
	approved := map[mydcp.Identity]mydcp.Peer{}
	for _, p := range peers {
		k, _ := identity.ParseKey(p.Key)
		peer := mydcp.Peer{ID: p.ID, Endpoint: p.Endpoint, Policy: mydcp.Policy{Key: mydcp.Identity(k), Respond: true}}
		approved[peer.Key] = peer
	}
	peerAt := func(i int) mydcp.Peer { k, _ := identity.ParseKey(peers[i].Key); return approved[mydcp.Identity(k)] }
	client := func() userauth.Client {
		t.Helper()
		self, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := mydcp.NewTransport(self, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { p, ok := approved[k]; return p, ok })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = mesh.Close(); clear(self.Private) })
		c := userauth.Client{Self: self, Mesh: mesh, Cluster: clusterID}
		for _, p := range approved {
			c.Peers = append(c.Peers, p)
		}
		return c
	}
	c := client()
	session, err := c.Login(ctx, peerAt(leader), "alice", alice.Private)
	if err != nil {
		t.Fatal(err)
	}
	follower := (leader + 1) % 3
	wait(func() bool { p, ok := nodes[follower].Engine().LeaderPeer(); return ok && p.ID == peers[leader].ID })
	query, err := c.Query(ctx, peerAt(follower), session, "whoami", "")
	if err != nil || query.User == nil || query.User.ID != "alice" {
		t.Fatal("follower user relay", query.Code, err)
	}
	if query.RelayedBy != nodes[follower].Identity.Actor() || query.Node != nodes[leader].Identity.Actor() {
		t.Fatal("query bypassed server relay")
	}
	visible, err := c.Query(ctx, peerAt(follower), session, "tenants", "")
	if err != nil || len(visible.Tenants) != 2 || visible.Tenants[0].Role != access.Manager || visible.Tenants[1].Role != access.Viewer {
		t.Fatal("multiple current memberships", err)
	}
	selected, err := c.Query(ctx, peerAt(follower), session, "select-tenant", "two")
	if err != nil || selected.Tenant != "two" {
		t.Fatal("explicit second tenant selection", err)
	}
	tenant, _ := catalog().Tenant("one")
	raw, _ := control.ChangeBytes("set-trust", "alice", tenant.Revision, control.TrustAssignment{Tenant: "one", Rules: []access.TrustRule{{Registry: "docker.io", Repository: "library/php"}}})
	var mutation control.Change
	_ = json.Unmarshal(raw, &mutation)
	op, err := c.Prepare(ctx, peerAt(follower), session, "relayed-user-write", mutation)
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.Operation(ctx, peerAt(follower), op, false)
	if err != nil || first.Result == nil || first.Result.Code != state.Applied {
		t.Fatal("follower mutation relay", first.Code, first.Result, err)
	}
	if first.RelayedBy != nodes[follower].Identity.Actor() || first.Node != nodes[leader].Identity.Actor() {
		t.Fatal("mutation bypassed server relay")
	}
	if err = nodes[leader].Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	old := leader
	if err = nodes[old].Close(); err != nil {
		t.Fatal(err)
	}
	nodes[old] = nil
	findLeader()
	entry := -1
	for i, n := range nodes {
		if n != nil && i != leader {
			entry = i
		}
	}
	wait(func() bool { p, ok := nodes[entry].Engine().LeaderPeer(); return ok && p.ID == peers[leader].ID })
	result, err := c.Operation(ctx, peerAt(entry), op, true)
	if err != nil || result.Result == nil || *result.Result != *first.Result {
		t.Fatal("original receipt after leader handoff", result.Code, err)
	}
	if result.RelayedBy != nodes[entry].Identity.Actor() {
		t.Fatal("post-handoff query bypassed relay")
	}
	newClient := client()
	newSession, err := newClient.Login(ctx, peerAt(leader), "alice", alice.Private)
	if err != nil {
		t.Fatal(err)
	}
	result, err = newClient.Result(ctx, peerAt(entry), newSession, op)
	if err != nil || result.Result == nil || *result.Result != *first.Result {
		t.Fatal("same user new key cannot read own result", result.Code, err)
	}
	// Current SYSTEM ADMIN Bob cannot inherit Alice's immutable operation.
	other := client()
	otherSession, err := other.Login(ctx, peerAt(leader), "bob", bob.Private)
	if err != nil {
		t.Fatal(err)
	}
	adminTenants, err := other.Query(ctx, peerAt(entry), otherSession, "tenants", "")
	if err != nil || len(adminTenants.Tenants) != 2 {
		t.Fatal("implicit system admin tenant view", err)
	}
	for _, v := range adminTenants.Tenants {
		if v.Role != access.Manager {
			t.Fatal("implicit admin role missing", v.Role)
		}
	}
	body, _ := json.Marshal(userauth.Request{Schema: 1, Method: "result", Operation: &op, Nonce: [32]byte{7}})
	conn, err := other.Mesh.Dial(ctx, peerAt(leader))
	if err != nil {
		t.Fatal(err)
	}
	foreignEnvelope := userauth.Envelope{Body: body, Session: &otherSession, Signature: ed25519.Sign(other.Self.Private, access.RequestBytes(otherSession, conn.PeerChallenge(), body))}
	rawReply := func(conn *mydcp.Session, kind uint8, envelope userauth.Envelope) userauth.Reply {
		t.Helper()
		payload, _ := json.Marshal(envelope)
		digest := sha256.Sum256(payload)
		stream, err := conn.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.CancelRead(0)
		defer stream.Close()
		if err = mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.User, Kind: kind, Request: 71, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: payload}, {Tag: 2, Required: true, Value: digest[:]}}}); err != nil {
			t.Fatal(err)
		}
		// Finite user RPCs send their write EOF before reading the reply.
		if err = stream.Close(); err != nil {
			t.Fatal(err)
		}
		frame, err := mydcp.ReadFrame(stream, 128<<10)
		if err != nil {
			t.Fatal(err)
		}
		var r userauth.Reply
		if json.Unmarshal(frame.Fields[0].Value, &r) != nil {
			t.Fatal("invalid reply")
		}
		return r
	}
	if r := rawReply(conn, 1, foreignEnvelope); r.Code != "denied" {
		t.Fatal("foreign admin inherited original receipt", r.Code)
	}
	expired := otherSession
	now := time.Now().Unix()
	expired.IssuedAt, expired.ExpiresAt = now-600, now-1
	expired.Signature = ed25519.Sign(nodes[leader].Identity.Private, access.SessionBytes(expired))
	expiredBody, _ := json.Marshal(userauth.Request{Schema: 1, Method: "whoami", Nonce: [32]byte{10}})
	expiredEnvelope := userauth.Envelope{Body: expiredBody, Session: &expired, Signature: ed25519.Sign(other.Self.Private, access.RequestBytes(expired, conn.PeerChallenge(), expiredBody))}
	if r := rawReply(conn, 1, expiredEnvelope); r.Code != "denied" {
		t.Fatal("expired session accepted by server", r.Code)
	}
	member := nodes[entry]
	leaderPeer, _ := member.Engine().LeaderPeer()
	relayConn, err := member.Mesh.Dial(ctx, leaderPeer)
	if err != nil {
		t.Fatal(err)
	}
	userBody, _ := json.Marshal(userauth.Request{Schema: 1, Method: "whoami", Nonce: [32]byte{8}})
	challenge := [32]byte{9}
	relayed := userauth.Envelope{Body: userBody, Session: &newSession, Signature: ed25519.Sign(newClient.Self.Private, access.RequestBytes(newSession, challenge, userBody)), Relay: &userauth.Relay{Node: member.Identity.Public, Target: member.Identity.Public, Caller: newClient.Self.Public, Challenge: challenge, Connection: relayConn.PeerChallenge()}}
	relayed.Relay.Signature = ed25519.Sign(member.Identity.Private, userauth.RelayBytes(clusterID, relayed))
	if r := rawReply(relayConn, 3, relayed); r.Code != "denied" {
		t.Fatal("relay accepted wrong destination", r.Code)
	}
	relayed.Relay.Target = nodes[leader].Identity.Public
	relayed.Relay.Connection = [32]byte{22}
	relayed.Relay.Signature = ed25519.Sign(member.Identity.Private, userauth.RelayBytes(clusterID, relayed))
	if r := rawReply(relayConn, 3, relayed); r.Code != "denied" {
		t.Fatal("relay reused another connection proof", r.Code)
	}
	// Restore the former leader's original DB/key, then enter through it.
	nodes[old], err = Open(configs[old])
	if err != nil {
		t.Fatal(err)
	}
	wait(func() bool { p, ok := nodes[old].Engine().LeaderPeer(); return ok && p.ID == peers[leader].ID })
	result, err = newClient.Result(ctx, peerAt(old), newSession, op)
	if err != nil || result.Result == nil || *result.Result != *first.Result {
		t.Fatal("same DB restored member relay", result.Code, err)
	}
	// Lose quorum (N3/Q2) without reinitializing or shrinking membership.
	for i, n := range nodes {
		if i != leader && n != nil {
			if err = n.Close(); err != nil {
				t.Fatal(err)
			}
			nodes[i] = nil
		}
	}
	uncertain := op
	uncertain.RequestID = "no-majority"
	v, err := nodes[leader].Engine().Read(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	uncertain.RootRevision = v.State.Object(control.CatalogKey).Revision
	uncertain.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(uncertain))
	short, stop := context.WithTimeout(ctx, 2*time.Second)
	reply, callErr := c.Operation(short, peerAt(leader), uncertain, false)
	stop()
	if callErr == nil || reply.Result != nil && reply.Result.Code == state.Applied {
		t.Fatal("minority accepted user mutation")
	}
	isolated, err := nodes[leader].Engine().Read(ctx, false)
	if err != nil || isolated.State.Index() != v.State.Index() {
		t.Fatal("minority changed committed state", err)
	}
	// Same DB restoration recovers quorum and the OLD receipt, not a new ID.
	restore := (leader + 1) % 3
	nodes[restore], err = Open(configs[restore])
	if err != nil {
		t.Fatal(err)
	}
	findLeader()
	result, err = newClient.Result(ctx, peerAt(leader), newSession, op)
	if err != nil || result.Result == nil || *result.Result != *first.Result {
		t.Fatal("original result lost after quorum recovery", result.Code, err)
	}
	account, _ := catalog().User("alice")
	expectedAccount := account.Revision
	account.Revision, account.Enabled = 0, false
	change("put-user", "admin", expectedAccount, account)
	if _, err = newClient.Query(ctx, peerAt(leader), newSession, "whoami", ""); err == nil {
		t.Fatal("disabled account read accepted")
	}
	if _, err = newClient.Result(ctx, peerAt(leader), newSession, op); err == nil {
		t.Fatal("disabled account recovered original receipt")
	}
}
