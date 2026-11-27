// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"

	"github.com/hashicorp/raft"
)

func TestChangeFeedRingResyncsBelowFloor(t *testing.T) {
	f := &ChangeFeed{}
	if _, _, ok := f.since(5); ok {
		t.Fatal("unknown index accepted before the first view")
	}
	f.append(10, nil)
	ref := func(n string) control.WatchRef {
		return control.WatchRef{WatchKey: control.WatchKey{Kind: "app", Tenant: "t", Name: n}}
	}
	for i := uint64(11); i < 11+changeFeedBatches+5; i++ {
		f.append(i, []control.WatchRef{ref(fmt.Sprint(i))})
	}
	head := uint64(10 + changeFeedBatches + 5)
	if refs, index, ok := f.since(head - 2); !ok || index != head || len(refs) != 2 || refs[0].Name != fmt.Sprint(head-1) || refs[1].Name != fmt.Sprint(head) {
		t.Fatal("recent resume", refs, index, ok)
	}
	if _, index, ok := f.since(10); ok || index != head {
		t.Fatal("forgotten index resumed", index, ok)
	}
	if refs, index, ok := f.since(0); !ok || index != head || refs != nil {
		t.Fatal("from now", refs, index, ok)
	}
	if _, _, ok := f.since(head + 1); ok {
		t.Fatal("future index accepted")
	}
}

func TestWatchDiffNamesChangedAndDeletedRecords(t *testing.T) {
	a := control.WatchKey{Kind: "app", Tenant: "t", Name: "a"}
	b := control.WatchKey{Kind: "app", Tenant: "t", Name: "b"}
	c := control.WatchKey{Kind: "app", Tenant: "t", Name: "c"}
	older := control.WatchRecords{a: {1}, b: {2}}
	newer := control.WatchRecords{a: {1}, b: {3}, c: {4}}
	got := control.WatchDiff(older, newer)
	if len(got) != 2 || got[0].WatchKey != b || got[0].Deleted || got[1].WatchKey != c {
		t.Fatal(got)
	}
	got = control.WatchDiff(newer, control.WatchRecords{a: {1}})
	if len(got) != 2 || got[0].WatchKey != b || !got[0].Deleted || got[1].WatchKey != c || !got[1].Deleted {
		t.Fatal(got)
	}
}

// Real Raft, bbolt and the Unix management socket: a committed tenant
// change reaches a system administrator's watch as one reference, is
// withheld from a user of another tenant, and a resumed watch receives
// what happened after its last index.
func TestChangeWatchActualRaftUnix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := os.MkdirTemp("", "sfc-watch-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	newKey := func() *identity.Identity {
		key, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	node, admin, web, aliceKey := newKey(), newKey(), newKey(), newKey()
	clusterID := [32]byte{203}
	peer := sfcp.Peer{ID: "node", Policy: sfcp.Policy{Key: sfcp.Identity(node.Public), Member: true, Read: true, Respond: true}}
	lookup := func(k sfcp.Identity) (sfcp.Peer, bool) {
		if k == sfcp.Identity(web.Public) {
			return sfcp.Peer{ID: "web", Policy: sfcp.Policy{Key: k, UserAuth: true}}, true
		}
		return peer, k == peer.Key
	}
	server, err := sfcp.NewTransport(node, clusterID, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peer.Endpoint = server.Addr().String()
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, Issuers: [][32]byte{node.Public}, TrustRoot: node.Public, Genesis: config.Peer{ID: "node", Key: node.Actor(), Endpoint: peer.Endpoint, Voter: true}}
	e, err := cluster.Open(cluster.Options{ID: "node", Root: filepath.Join(root, "db"), Admin: admin.Actor(), Cluster: clusterID, Mesh: server, Bootstrap: true,
		Servers: []raft.Server{{ID: "node", Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}}, Resolve: func(id raft.ServerID, _ raft.ServerAddress) (sfcp.Peer, bool) { return peer, id == "node" }, ModuleID: policy.ID(), Validate: policy.Validate, Reduce: policy.Reduce, AdmitModule: policy.AdmitModule, TrackConfiguration: true})
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
	install := func(action string, payload any) {
		t.Helper()
		principal := "operator"
		if action == "enroll" {
			principal = ""
		}
		raw, err := control.ChangeBytes(action, principal, 0, payload)
		if err != nil {
			t.Fatal(err)
		}
		view, err := e.Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		sequence++
		result, err := e.Submit(ctx, state.Command{Kind: state.Module, Actor: admin.Actor(), Epoch: 1, RequestID: fmt.Sprintf("watch-install-%d", sequence), Key: control.CatalogKey, Expected: view.State.Object(control.CatalogKey).Revision, Value: string(raw)})
		if err != nil || result.Result.Code != state.Applied {
			t.Fatal("installation", action, result.Result, err)
		}
	}
	install("enroll", access.User{ID: "operator", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	install("put-user", access.User{ID: "alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: aliceKey.Public, Enabled: true}}})
	install("create-tenant", control.TenantID{ID: "a"})
	install("set-membership", access.Membership{Tenant: "a", User: "alice", Role: access.Manager, Enabled: true})

	feed := &ChangeFeed{Engine: e, Policy: policy}
	go feed.Run(ctx)
	bus := eventbus.New()
	svc := Service{Engine: e, Mesh: server, Self: node, Policy: policy, Changes: feed, Events: bus}
	if err = svc.Serve(); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "sfcdp.sock")
	if err = server.ListenUnix(socket); err != nil {
		t.Fatal(err)
	}
	target := peer
	target.Endpoint = "unix://" + socket
	mesh, err := sfcp.NewTransport(web, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return target, k == target.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	c := Client{Self: web, Cluster: clusterID, Peers: []sfcp.Peer{target}, Mesh: mesh}
	operator, err := c.Login(ctx, target, "operator", admin.Private)
	if err != nil {
		t.Fatal("operator login", err)
	}
	alice, err := c.Login(ctx, target, "alice", aliceKey.Private)
	if err != nil {
		t.Fatal("alice login", err)
	}

	type watch struct {
		frames chan ChangeWatchReply
		cancel context.CancelFunc
		done   chan error
	}
	start := func(s access.Session, from uint64, topics ...string) watch {
		wctx, wcancel := context.WithCancel(ctx)
		w := watch{frames: make(chan ChangeWatchReply, 64), cancel: wcancel, done: make(chan error, 1)}
		go func() {
			_, err := c.WatchChanges(wctx, target, s, from, topics, func(r ChangeWatchReply) error { w.frames <- r; return nil })
			w.done <- err
		}()
		return w
	}
	// first is the frame that says where the watch starts.
	first := func(w watch) uint64 {
		t.Helper()
		select {
		case r := <-w.frames:
			if r.Resync || len(r.Refs) != 0 || r.Index == 0 {
				t.Fatal("first frame", r)
			}
			return r.Index
		case err := <-w.done:
			t.Fatal("watch ended", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		return 0
	}
	// until reads frames up to index at, returning their refs.
	until := func(w watch, at uint64) []control.WatchRef {
		t.Helper()
		var refs []control.WatchRef
		for {
			select {
			case r := <-w.frames:
				if r.Resync {
					t.Fatal("unexpected resync", r)
				}
				refs = append(refs, r.Refs...)
				if r.Index >= at {
					return refs
				}
			case err := <-w.done:
				t.Fatal("watch ended", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	// A watch owns its local connection; start them one after another.
	ow := start(operator, 0)
	defer ow.cancel()
	first(ow)
	aw := start(alice, 0)
	defer aw.cancel()
	first(aw)

	install("create-tenant", control.TenantID{ID: "b"})
	view, err := e.Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	created := view.RaftIndex
	tenantB := control.WatchKey{Kind: "tenant", Tenant: "b", Name: "b"}
	if refs := until(ow, created); len(refs) != 1 || refs[0].WatchKey != tenantB || refs[0].Deleted {
		t.Fatal("operator refs", refs)
	}
	if refs := until(aw, created); len(refs) != 0 {
		t.Fatal("alice saw another tenant", refs)
	}

	// A resumed watch receives what was applied after its index.
	ow.cancel()
	install("create-tenant", control.TenantID{ID: "c"})
	resumed := start(operator, created)
	defer resumed.cancel()
	view, err = e.Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if refs := until(resumed, view.RaftIndex); len(refs) != 1 || refs[0].WatchKey != (control.WatchKey{Kind: "tenant", Tenant: "c", Name: "c"}) {
		t.Fatal("resumed refs", refs)
	}
	// An index this node no longer remembers is answered with a resync.
	stale := start(operator, 1)
	defer stale.cancel()
	select {
	case r := <-stale.frames:
		if !r.Resync || r.Index < view.RaftIndex || len(r.Refs) != 0 {
			t.Fatal("stale resume", r)
		}
	case err := <-stale.done:
		t.Fatal("watch ended", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	// Report events reach the watches that asked for them, by the read's
	// permission: a cluster item only the operator, a tenant item alice too.
	stale.cancel()
	resumed.cancel()
	aw.cancel()
	ew := start(operator, 0, eventbus.TopicReport)
	defer ew.cancel()
	first(ew)
	ea := start(alice, 0, eventbus.TopicReport)
	defer ea.cancel()
	first(ea)
	event := func(w watch) ChangeWatchReply {
		t.Helper()
		for {
			select {
			case r := <-w.frames:
				if len(r.Events) != 0 || r.EventsLost {
					return r
				}
			case err := <-w.done:
				t.Fatal("watch ended", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	bus.Publish(eventbus.Event{Topic: eventbus.TopicReport, Kind: eventbus.KindNodeReport, Node: "node", Changed: true})
	bus.Publish(eventbus.Event{Topic: eventbus.TopicReport, Kind: eventbus.KindNodeObservation, Node: "node", Source: "task/a/web", Tenant: "a", App: "web", Changed: true})
	got := map[string]bool{}
	for len(got) < 2 {
		for _, e := range event(ew).Events {
			got[e.Kind] = true
		}
	}
	r := event(ea)
	if len(r.Events) != 1 || r.Events[0] != (ChangeEvent{Topic: eventbus.TopicReport, Kind: eventbus.KindNodeObservation, Node: "node", Source: "task/a/web", Tenant: "a", App: "web"}) {
		t.Fatal("alice events", r)
	}
}

// An alarm reaches a watch only for the topics it asked for, and only when
// its sender chose watchers; one addressed to a user reaches only that user.
func TestChangeWatchAlarmTopicsAndScope(t *testing.T) {
	bus := eventbus.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	one := Service{Events: bus}.watchTopics(ctx, []string{"alarm/disk"})
	all := Service{Events: bus}.watchTopics(ctx, []string{eventbus.TopicAlarmPrefix})
	bus.Publish(eventbus.Event{Topic: "alarm/cpu", Node: "a", Note: "hot", Scope: eventbus.Scope{Web: true}})
	bus.Publish(eventbus.Event{Topic: "alarm/disk", Node: "a", Note: "full", Scope: eventbus.Scope{Web: true}})
	var got []ChangeEvent
	for len(got) < 2 {
		select {
		case b := <-all:
			got = append(got, b.events...)
		case <-ctx.Done():
			t.Fatal("all alarms", got)
		}
	}
	if got[0].Topic != "alarm/cpu" || got[0].Note != "hot" || got[1].Topic != "alarm/disk" {
		t.Fatal("all alarms", got)
	}
	select {
	case b := <-one:
		if len(b.events) != 1 || b.events[0].Topic != "alarm/disk" || !b.scopes[0].Web {
			t.Fatal("one alarm", b.events)
		}
	case <-ctx.Done():
		t.Fatal("one alarm")
	}
	e := ChangeEvent{Topic: "alarm/disk"}
	s := access.Session{User: "u"}
	if changeEventAllowed(access.Catalog{}, s, [32]byte{}, access.Issuer{}, 0, e, eventbus.Scope{AllNodes: true}) {
		t.Fatal("node-only alarm shown to a watcher")
	}
	if changeEventAllowed(access.Catalog{}, s, [32]byte{}, access.Issuer{}, 0, e, eventbus.Scope{Web: true, User: "v"}) {
		t.Fatal("another user's alarm shown")
	}
}
