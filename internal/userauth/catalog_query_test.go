// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"

	"github.com/hashicorp/raft"
)

func TestCatalogQuerySelectorsCannotCrossScopes(t *testing.T) {
	for _, r := range []Request{{Method: "users"}, {Method: "users", After: "opaque"}, {Method: "tenant-members", Tenant: "first"}} {
		if !r.validMethodFields() || !r.validQuerySelectors() {
			t.Fatal("valid selector", r.Method)
		}
	}
	for _, r := range []Request{{Method: "users", Tenant: "first"}, {Method: "users", Node: "node"}, {Method: "users", TargetUser: "alice"}, {Method: "tenant-members"}, {Method: "tenant-members", Tenant: "first", Node: "node"}, {Method: "users", After: strings.Repeat("x", 513)}} {
		if r.validMethodFields() && r.validQuerySelectors() {
			t.Fatal("foreign selector accepted", r.Method)
		}
	}
}

// This fixture uses a real local Raft voter, bbolt FSM, authenticated TLS,
// login challenge and both actual Unix and QUIC transports. Its installation
// policy is the pre-managed catalog contract, not a Docker/multi-node proof.
func TestCatalogQueriesActualRaftUnixAndQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	node, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(node.Private)
	keys := map[string]*identity.Identity{}
	for _, name := range []string{"admin", "manager", "viewer"} {
		key, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		keys[name] = key
		defer clear(key.Private)
	}
	clusterID := [32]byte{201}
	peer := mydcp.Peer{ID: "node", Policy: mydcp.Policy{Key: mydcp.Identity(node.Public), Member: true, Read: true, Respond: true}}
	lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
		for _, self := range keys {
			if key == mydcp.Identity(self.Public) {
				return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, true
			}
		}
		return peer, key == peer.Key
	}
	server, err := mydcp.NewTransport(node, clusterID, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peer.Endpoint = server.Addr().String()
	policy := control.Policy{Cluster: clusterID, BootstrapKey: keys["admin"].Public, Issuers: [][32]byte{node.Public}, TrustRoot: node.Public, Genesis: config.Peer{ID: "node", Key: node.Actor(), Endpoint: peer.Endpoint, Voter: true}}
	e, err := cluster.Open(cluster.Options{ID: "node", Root: filepath.Join(root, "db"), Admin: keys["admin"].Actor(), Cluster: clusterID, Mesh: server, Bootstrap: true,
		Servers: []raft.Server{{ID: "node", Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}}, Resolve: func(id raft.ServerID, _ raft.ServerAddress) (mydcp.Peer, bool) { return peer, id == "node" },
		ModuleID: policy.ID(), Validate: policy.Validate, Reduce: policy.Reduce, AdmitModule: policy.AdmitModule, TrackConfiguration: true})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for {
		if _, err := e.Read(ctx, true); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	sequence := 0
	install := func(action string, expected uint64, value any) {
		t.Helper()
		principal := "admin"
		if action == "enroll" {
			principal = ""
		}
		raw, err := control.ChangeBytes(action, principal, expected, value)
		if err != nil {
			t.Fatal(err)
		}
		view, err := e.Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		sequence++
		result, err := e.Submit(ctx, state.Command{Kind: state.Module, Actor: keys["admin"].Actor(), Epoch: 1, RequestID: fmt.Sprintf("catalog-install-%d", sequence), Key: control.CatalogKey, Expected: view.State.Object(control.CatalogKey).Revision, Value: string(raw)})
		if err != nil || result.Result.Code != state.Applied {
			t.Fatal("catalog installation", action, result.Result, err)
		}
	}
	for _, name := range []string{"admin", "manager", "viewer"} {
		u := access.User{ID: name, Username: name, Enabled: true, SystemAdmin: name == "admin", Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: keys[name].Public, Enabled: true}, {ID: "password", Method: access.Password, VerifierRef: "must-not-escape", Enabled: true}}}
		action := "put-user"
		if name == "admin" {
			action = "enroll"
		}
		install(action, 0, u)
	}
	for _, name := range []string{"first", "second"} {
		install("create-tenant", 0, control.TenantID{ID: name})
	}
	install("set-membership", 0, access.Membership{Tenant: "first", User: "manager", Role: access.Manager, Enabled: true})
	install("set-membership", 0, access.Membership{Tenant: "first", User: "viewer", Role: access.Viewer, Enabled: true})
	service := Service{Engine: e, Mesh: server, Self: node, Policy: policy}
	if err = service.Serve(); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "mydc.sock")
	if err = server.ListenUnix(socket); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"unix", "quic"} {
		t.Run(network, func(t *testing.T) {
			target := peer
			if network == "unix" {
				target.Endpoint = "unix://" + socket
			}
			clients := map[string]Client{}
			sessions := map[string]access.Session{}
			for _, name := range []string{"admin", "manager", "viewer"} {
				clientLookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
					if key == target.Key {
						return target, true
					}
					return lookup(key)
				}
				mesh, err := mydcp.NewTransport(keys[name], clusterID, clientLookup)
				if err != nil {
					t.Fatal(err)
				}
				defer mesh.Close()
				c := Client{Mesh: mesh, Self: keys[name], Cluster: clusterID, Peers: []mydcp.Peer{target}}
				s, err := c.Login(ctx, target, name, keys[name].Private)
				if err != nil {
					t.Fatal("actual login", name, err)
				}
				clients[name], sessions[name] = c, s
			}
			reply, err := clients["admin"].UsersPage(ctx, target, sessions["admin"], "")
			if err != nil || len(reply.Users) != 3 || reply.RootRevision == 0 || reply.UsersRevision == 0 {
				t.Fatal("actual users", reply.Code, err)
			}
			raw, _ := json.Marshal(reply)
			if strings.Contains(string(raw), "VerifierRef") || strings.Contains(string(raw), "must-not-escape") {
				t.Fatal("verifier escaped wire")
			}
			for _, name := range []string{"manager", "viewer"} {
				if _, err := clients[name].UsersPage(ctx, target, sessions[name], ""); err == nil {
					t.Fatal("non-admin users query", name)
				}
			}
			members, err := clients["manager"].TenantMembersPage(ctx, target, sessions["manager"], "first", "")
			if err != nil || len(members.TenantMembers) != 3 || members.TenantRevision == 0 || members.TenantMembersRevision != reply.UsersRevision {
				t.Fatal("actual membership", members.Code, err)
			}
			if _, err = clients["manager"].TenantMembersPage(ctx, target, sessions["manager"], "second", ""); err == nil {
				t.Fatal("cross-tenant membership leak")
			}
			if _, err = clients["viewer"].TenantMembersPage(ctx, target, sessions["viewer"], "first", ""); err == nil {
				t.Fatal("viewer membership leak")
			}
			// Prove that a signed scope ceiling still constrains a live admin.
			narrow := sessions["admin"]
			narrow.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}
			narrow.Signature = ed25519.Sign(node.Private, access.SessionBytes(narrow))
			if _, err = clients["admin"].UsersPage(ctx, target, narrow, ""); err == nil {
				t.Fatal("admin bypassed signed scope")
			}
			view, err := e.Read(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			catalog, err := policy.Catalog(view.State)
			if err != nil {
				t.Fatal(err)
			}
			m, _ := catalog.Membership("first", "viewer")
			payload, _ := json.Marshal(access.Membership{Tenant: "first", User: "viewer", Role: access.Manager, Enabled: true})
			op, err := clients["admin"].Prepare(ctx, target, sessions["admin"], "membership-"+network, control.Change{Schema: 1, Action: "set-membership", Principal: "admin", Expected: m.Revision, Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			changed, err := clients["admin"].Operation(ctx, target, op, false)
			if err != nil || changed.Result == nil || changed.Result.Code != state.Applied {
				t.Fatal("actual signed membership change", changed.Code, err)
			}
			updated, err := clients["manager"].TenantMembersPage(ctx, target, sessions["manager"], "first", "")
			if err != nil || updated.TenantMembersRevision <= members.TenantMembersRevision || updated.RootRevision <= members.RootRevision {
				t.Fatal("current revision not published", err)
			}
			// Restore with an ordinary signed user operation for the next transport.
			for _, row := range updated.TenantMembers {
				if row.User == "viewer" {
					m.Revision = row.Revision
				}
			}
			payload, _ = json.Marshal(access.Membership{Tenant: "first", User: "viewer", Role: access.Viewer, Enabled: true})
			op, err = clients["admin"].Prepare(ctx, target, sessions["admin"], "restore-"+network, control.Change{Schema: 1, Action: "set-membership", Principal: "admin", Expected: m.Revision, Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			changed, err = clients["admin"].Operation(ctx, target, op, false)
			if err != nil || changed.Result == nil || changed.Result.Code != state.Applied {
				t.Fatal("membership restore", changed.Code, err)
			}
		})
	}
}
