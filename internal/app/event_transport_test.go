// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Real two-voter MYDCP/Raft/DB boundary with synthetic diagnostic source
// facts. This does not stand in for the separate actual Docker/OS sources.
func TestRQ4TwoNodeEventTransportCurrentPermissionAndGap(t *testing.T) {
	testRealManagedJoin(t, false, "events")
}

func verifyTwoNodeEventBoundary(t *testing.T, ctx context.Context, receiver, source *Runtime, client userauth.Client, admin access.Session, target mydcp.Peer, submit func(string, string, uint64, any), wait func(string, func() bool)) {
	t.Helper()
	for _, tenant := range []string{"first", "second"} {
		submit("event-create-"+tenant, "create-tenant", 0, control.TenantID{ID: tenant})
		view, err := receiver.Engine().Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := receiver.controlPolicy.Catalog(view.State)
		if err != nil {
			t.Fatal(err)
		}
		record, _ := catalog.Tenant(tenant)
		submit("event-nodes-"+tenant, "set-nodes", record.Revision, control.NodeAssignment{Tenant: tenant, Nodes: []string{"node-b"}})
	}
	submit("event-reader", "put-user", 0, access.User{ID: "event-reader", Username: "event-reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: client.Self.Public, Enabled: true}}})
	submit("event-reader-membership", "set-membership", 0, access.Membership{Tenant: "first", User: "event-reader", Role: access.Viewer, Enabled: true})
	reader, err := client.Login(ctx, target, "event-reader", client.Self.Private)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := receiver.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = source.Engine().ReadAtLeast(ctx, floor.State.Index()); err != nil {
		t.Fatal(err)
	}
	now := uint64(time.Now().UnixMilli())
	var expected []string
	for _, tenant := range []string{"first", "second"} {
		fact, err := source.events.Append("boundary-model/"+tenant, eventlog.Event{Kind: "task-exited", Scope: "app", At: now, Target: eventlog.Target{Tenant: tenant, App: "model", Node: "node-b", Task: "workload/task/" + tenant + "/model/web", Native: "synthetic-native", Generation: 1, Revision: 1}}, now)
		if err != nil {
			t.Fatal(err)
		}
		expected = append(expected, fact.PublicID())
	}
	last, err := source.replicateEventPeer(ctx, target)
	if err != nil || last != source.events.OwnLast() {
		t.Fatal("authenticated source batch/receipt", last, source.events.OwnLast(), err)
	}
	// A second pass finds the peer current and sends nothing new.
	if again, err := source.replicateEventPeer(ctx, target); err != nil || again != last {
		t.Fatal("repeat replication of an already current peer", again, last, err)
	}
	for i, tenant := range []string{"first", "second"} {
		page, err := client.EventsPage(ctx, target, admin, eventlog.Query{Tenant: tenant})
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != expected[i] {
			t.Fatal("real user/source identity", tenant, err)
		}
	}
	page, err := client.EventsPage(ctx, target, reader, eventlog.Query{Tenant: "first", Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != expected[0] {
		t.Fatal("tenant source event read", err)
	}
	if _, err = client.EventsPage(ctx, target, reader, eventlog.Query{Tenant: "second"}); err == nil {
		t.Fatal("other tenant event read accepted")
	}
	if _, err = client.EventsPage(ctx, target, reader, eventlog.Query{}); err == nil {
		t.Fatal("tenant reader acquired cluster scope")
	}
	// Even a valid installed source batch is not admitted under another key.
	batch, err := source.events.Export(0, uint64(time.Now().UnixMilli()))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(batch)
	if err = receiver.storeEventBatch(ctx, mydcp.Identity(receiver.Identity.Public), raw); err == nil {
		t.Fatal("valid batch borrowed another connection identity")
	}
	// An actual observer gap is delivered over the same member path and makes
	// the original reader cursor explicitly unusable, never an empty success.
	now = uint64(time.Now().UnixMilli())
	if _, err = source.events.Append("boundary-gap", eventlog.Event{Kind: "event-source-gap", Scope: "node", At: now, Target: eventlog.Target{Node: "node-b"}, Detail: eventlog.Detail{Code: "TEST_SOURCE_GAP"}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err = source.replicateEventPeer(ctx, target); err != nil {
		t.Fatal(err)
	}
	_, err = client.EventsPage(ctx, target, reader, eventlog.Query{Tenant: "first", After: page.Cursor})
	var code *userauth.Error
	if !errors.As(err, &code) || code.Code != "CURSOR_EXPIRED" {
		t.Fatal("remote source gap silently resumed", err)
	}
	page, err = client.EventsPage(ctx, target, reader, eventlog.Query{Tenant: "first"})
	if err != nil || !page.Incomplete {
		t.Fatal("explicit reset hid collection gap", err)
	}
	view, err := receiver.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := receiver.controlPolicy.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	account, _ := catalog.User("event-reader")
	account.Enabled = false
	revision := account.Revision
	account.Revision = 0
	submit("event-revoke-reader", "put-user", revision, account)
	wait("event reader revocation is effective on the actual API", func() bool {
		_, err := client.EventsPage(ctx, target, reader, eventlog.Query{Tenant: "first", After: page.Cursor})
		var code *userauth.Error
		return errors.As(err, &code) && code.Code == "denied"
	})
}
