// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/eventlog"
)

func TestEventAccessUsesCurrentTenantPermissionAndTargetNotControlLocation(t *testing.T) {
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.apply("event-empty-tenant", "create-tenant", 0, struct{ ID string }{"other"}, state.Applied)
	f.apply("event-reader", "put-user", 0, access.User{ID: "reader", Username: "reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(f.admin.Public().(ed25519.PublicKey)), Enabled: true}}}, state.Applied)
	for _, tenant := range []string{"tenant", "other"} {
		f.apply("event-membership-"+tenant, "set-membership", 0, access.Membership{Tenant: tenant, User: "reader", Role: access.Manager, Enabled: true}, state.Applied)
	}
	catalog, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	user, _ := catalog.User("reader")
	reader := f.session
	reader.User, reader.AccountRevision = user.ID, user.Revision
	reader.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}, {Tenant: "other", Actions: []access.Action{access.Read}}}
	reader.Signature = ed25519.Sign(f.node, access.SessionBytes(reader))
	signed := func(e eventlog.Event) eventlog.Record {
		t.Helper()
		tag := sha256.Sum256([]byte("public-event-source"))
		r := eventlog.Record{Schema: 1, Cluster: f.p.Cluster, SourceKey: [32]byte(f.node.Public().(ed25519.PublicKey)), SourceNode: "node-a", Stream: [16]byte{1}, Sequence: 1, Tag: hex.EncodeToString(tag[:]), Event: e}
		r.Signature = ed25519.Sign(f.node, eventlog.SigningBytes(r))
		if !r.Valid() {
			t.Fatal("invalid event fixture")
		}
		return r
	}
	e := eventlog.Event{Kind: "task-exited", Scope: "app", At: 10000, Target: eventlog.Target{Tenant: "tenant", App: "shop", Node: "node-a"}}
	allowed, err := f.p.EventAccess(f.s, reader, 10, eventlog.Query{Tenant: "tenant"})
	if err != nil || !allowed(signed(e)) {
		t.Fatal("own tenant event denied", err)
	}
	e.Target.Tenant = "other"
	if allowed(signed(e)) {
		t.Fatal("different tenant event leaked")
	}
	e.Target.Tenant, e.Target.Node = "tenant", "hidden-node"
	if allowed(signed(e)) {
		t.Fatal("disallowed target node event leaked")
	}
	if _, err = f.p.EventAccess(f.s, reader, 10, eventlog.Query{}); !errors.Is(err, access.ErrDenied) {
		t.Fatal("tenant reader acquired cluster event scope", err)
	}
	if _, err = f.p.EventAccess(f.s, reader, 10, eventlog.Query{Tenant: "tenant", Node: "hidden-node"}); !errors.Is(err, access.ErrDenied) {
		t.Fatal("hidden node filter accepted", err)
	}
	// This tenant has no workload nodes. Its logical CD events are still
	// readable when a trusted control projects the committed transition.
	allowed, err = f.p.EventAccess(f.s, reader, 10, eventlog.Query{Tenant: "other"})
	digest := sha256.Sum256([]byte("public-committed-event"))
	e = eventlog.Event{Kind: "cd-candidate-created", Scope: "app", At: 10000, Authority: hex.EncodeToString(digest[:]), Target: eventlog.Target{Tenant: "other", App: "shop"}}
	if err != nil || !allowed(signed(e)) {
		t.Fatal("control journal location hid tenant CD fact", err)
	}
	user.Enabled = false
	revision := user.Revision
	user.Revision = 0
	f.apply("event-revoke-reader", "put-user", revision, accountFields(user), state.Applied)
	if _, err = f.p.EventAccess(f.s, reader, 10, eventlog.Query{Tenant: "other"}); !errors.Is(err, access.ErrDenied) {
		t.Fatal("cursor read bypassed account revocation", err)
	}
}
