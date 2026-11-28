// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

func liveTestSocket() *liveSocket {
	return &liveSocket{out: make(chan liveFrame, liveQueue), stop: make(chan struct{})}
}

func nextFrame(t *testing.T, c *liveSocket) liveFrame {
	t.Helper()
	select {
	case f := <-c.out:
		return f
	default:
		t.Fatal("no frame")
	}
	return liveFrame{}
}

func appRef(name string) control.WatchRef {
	return control.WatchRef{WatchKey: control.WatchKey{Kind: "app", Tenant: "shop", Name: name}}
}

func TestLiveWatchFansOutResumesAndResyncs(t *testing.T) {
	w := &liveWatch{sockets: map[*liveSocket]struct{}{}, seq: 1000}
	a := liveTestSocket()
	w.join(a, 0)
	if f := nextFrame(t, a); f.Type != "state" || f.State != "reconnecting" {
		t.Fatal(f)
	}
	w.receive(sfc.ChangeBatch{Index: 10})
	if f := nextFrame(t, a); f.Type != "state" || f.State != "live" {
		t.Fatal(f)
	}
	start := nextFrame(t, a)
	if start.Type != "changes" || start.Index <= 1000 || start.Resync || len(start.Refs) != 0 {
		t.Fatal("start", start)
	}
	w.receive(sfc.ChangeBatch{Index: 12, Refs: []control.WatchRef{appRef("web")}})
	first := nextFrame(t, a)
	if first.Index != start.Index+1 || len(first.Refs) != 1 || first.Refs[0] != (liveRef{Kind: "app", Tenant: "shop", Name: "web"}) {
		t.Fatal("change", first)
	}
	// An index frame without refs moves nothing the tabs see.
	w.receive(sfc.ChangeBatch{Index: 13})
	// The web daemon's own data goes into the same numbering.
	w.local([]liveRef{{Kind: "notification", Name: "n1"}})
	if f := nextFrame(t, a); f.Index != first.Index+1 || f.Refs[0].Kind != "notification" {
		t.Fatal("local", f)
	}
	w.receive(sfc.ChangeBatch{Index: 15, Refs: []control.WatchRef{appRef("db")}})
	last := nextFrame(t, a)

	// A tab that saw the first change gets only what came after it.
	b := liveTestSocket()
	w.join(b, first.Index)
	nextFrame(t, b) // state
	if f := nextFrame(t, b); f.Index != last.Index || f.Resync || len(f.Refs) != 2 || f.Refs[0].Name != "n1" || f.Refs[1].Name != "db" {
		t.Fatal("resume", f)
	}
	// A tab from before this watch, or from another daemon run, reads again.
	for _, from := range []uint64{3, last.Index + 50} {
		c := liveTestSocket()
		w.join(c, from)
		nextFrame(t, c)
		if f := nextFrame(t, c); f.Index != last.Index || !f.Resync {
			t.Fatal("old tab", from, f)
		}
	}
	// sfcd lost the history: every tab reads again.
	w.lost()
	if f := nextFrame(t, a); f.State != "reconnecting" {
		t.Fatal(f)
	}
	w.receive(sfc.ChangeBatch{Index: 9000, Resync: true})
	nextFrame(t, a) // live
	resync := nextFrame(t, a)
	if resync.Index != last.Index+1 || !resync.Resync {
		t.Fatal("resync", resync)
	}
	d := liveTestSocket()
	w.join(d, last.Index)
	nextFrame(t, d)
	if f := nextFrame(t, d); !f.Resync {
		t.Fatal("resume across a resync", f)
	}
}

// A socket that falls behind keeps its place: the frames it cannot take
// merge into one that names each record once, then into a resync.
func TestLiveWatchMergesSlowSocket(t *testing.T) {
	w := &liveWatch{sockets: map[*liveSocket]struct{}{}, seq: 10}
	a := liveTestSocket()
	w.join(a, 0)
	w.receive(sfc.ChangeBatch{Index: 1})
	for i := uint64(2); i < 2+liveQueue*3; i++ {
		w.receive(sfc.ChangeBatch{Index: i, Refs: []control.WatchRef{appRef(fmt.Sprint("web", i%5))}})
	}
	if _, ok := w.sockets[a]; !ok || len(a.out) != liveQueue {
		t.Fatal("slow socket dropped", len(a.out))
	}
	if over := w.takeOver(a); over != nil {
		t.Fatal("merged frame before the queue drained", over)
	}
	for len(a.out) > 0 {
		<-a.out
	}
	over := w.takeOver(a)
	if len(over) != 1 || over[0].Resync || over[0].Index != w.seq || len(over[0].Refs) != 5 {
		t.Fatal("merged", over)
	}
	// Too many records to name become a resync.
	for i := 0; i < liveQueue+liveMerged+2; i++ {
		w.local([]liveRef{{Kind: "op", Name: fmt.Sprint("op", i)}})
	}
	for len(a.out) > 0 {
		<-a.out
	}
	if over := w.takeOver(a); len(over) != 1 || !over[0].Resync || len(over[0].Refs) != 0 {
		t.Fatal("overflow", over)
	}
}

func TestLiveSocketFake(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	dial := func(origin string) (*websocket.Conn, error) {
		cfg, _ := websocket.NewConfig(strings.Replace(f.http.URL, "http", "ws", 1)+"/api/v1/live", origin)
		cfg.Header = http.Header{}
		for _, c := range f.hc.Jar.Cookies(mustURL(f.http.URL)) {
			cfg.Header.Add("Cookie", c.Name+"="+c.Value)
		}
		return websocket.DialConfig(cfg)
	}
	if _, err := dial("http://evil.example"); err == nil {
		t.Fatal("cross-origin socket accepted")
	}
	conn, err := dial(f.http.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var types []string
	for len(types) < 3 {
		var m liveFrame
		if err := websocket.JSON.Receive(conn, &m); err != nil {
			t.Fatal(types, err)
		}
		types = append(types, m.Type+":"+m.State)
		if m.Type == "changes" {
			if m.Index == 0 || m.Resync {
				t.Fatal(m)
			}
			break
		}
	}
	if strings.Join(types, ",") != "state:reconnecting,state:live,changes:" {
		t.Fatal(types)
	}
}

// Web-own records go only to the logins that may see them.
func TestLiveStoreChangeReachesItsUser(t *testing.T) {
	s := &Server{}
	started := func(u sessionUser) (*webSession, *liveSocket) {
		ws := &webSession{user: u}
		w := &liveWatch{ws: ws, sockets: map[*liveSocket]struct{}{}, seq: 100, watched: 1}
		c := liveTestSocket()
		w.sockets[c] = struct{}{}
		if s.live.watches == nil {
			s.live.watches = map[*webSession]*liveWatch{}
		}
		s.live.watches[ws] = w
		return ws, c
	}
	_, alice := started(sessionUser{ID: "alice"})
	_, admin := started(sessionUser{ID: "root", SystemAdmin: true})
	empty := func(c *liveSocket) {
		t.Helper()
		select {
		case f := <-c.out:
			t.Fatal("unexpected frame", f)
		default:
		}
	}
	s.storeChanged(store.Change{Kind: "op", User: "alice", ID: "op1"})
	if f := nextFrame(t, alice); len(f.Refs) != 1 || f.Refs[0] != (liveRef{Kind: "op", Name: "op1"}) {
		t.Fatal("alice op", f)
	}
	empty(admin)
	s.storeChanged(store.Change{Kind: "notification", User: "root"})
	if f := nextFrame(t, admin); f.Refs[0].Kind != "notification" || f.Refs[0].Name != "" {
		t.Fatal("admin notification", f)
	}
	empty(alice)
	// A cluster incident is for system administrators only.
	s.storeChanged(store.Change{Kind: "incident", ID: "i1", Deleted: true})
	if f := nextFrame(t, admin); f.Refs[0] != (liveRef{Kind: "incident", Name: "i1", Deleted: true}) {
		t.Fatal("admin incident", f)
	}
	empty(alice)
	// A DNS domain reaches the members of any workspace it names.
	for ws, w := range s.live.watches {
		if ws.user.ID == "alice" {
			w.roles, w.rolesAt = map[string]sfc.Role{"b": sfc.RoleManager}, time.Now()
		}
	}
	s.storeChanged(store.Change{Kind: "dns-domain", ID: "shop.example", Tenants: []string{"a", "b"}})
	var f liveFrame
	select {
	case f = <-alice.out: // the role check runs apart from the writer
	case <-time.After(5 * time.Second):
		t.Fatal("alice heard nothing")
	}
	if f.Refs[0] != (liveRef{Kind: "dns-domain", Name: "shop.example"}) {
		t.Fatal("alice domain", f)
	}
	nextFrame(t, admin)
	s.storeChanged(store.Change{Kind: "dns-domain", ID: "other.example", Tenants: []string{"a"}})
	nextFrame(t, admin)
	time.Sleep(50 * time.Millisecond)
	empty(alice)
}

// Report notices go out as refs of the same numbering; a loss, or a break
// of the sfcd watch, makes the tabs read again.
func TestLiveWatchReportEvents(t *testing.T) {
	w := &liveWatch{sockets: map[*liveSocket]struct{}{}, seq: 50}
	a := liveTestSocket()
	w.join(a, 0)
	nextFrame(t, a) // reconnecting
	w.receive(sfc.ChangeBatch{Index: 10})
	nextFrame(t, a) // live
	start := nextFrame(t, a)
	w.receive(sfc.ChangeBatch{Index: 10, Events: []userauth.ChangeEvent{{Topic: "report", Kind: "node-observation", Node: "n1", Source: "task/shop/web", Tenant: "shop", App: "web"}}})
	f := nextFrame(t, a)
	if f.Index != start.Index+1 || f.Resync || len(f.Refs) != 1 || f.Refs[0] != (liveRef{Kind: "node-observation", Tenant: "shop", Name: "n1", Source: "task/shop/web", App: "web"}) {
		t.Fatal("event", f)
	}
	w.receive(sfc.ChangeBatch{Index: 10, EventsLost: true})
	if f := nextFrame(t, a); !f.Resync || f.Index != start.Index+2 {
		t.Fatal("lost", f)
	}
	w.lost()
	nextFrame(t, a) // reconnecting
	w.receive(sfc.ChangeBatch{Index: 10})
	nextFrame(t, a) // live
	if f := nextFrame(t, a); !f.Resync {
		t.Fatal("gap", f)
	}
	// A tab from before the gap reads again.
	b := liveTestSocket()
	w.join(b, f.Index-1)
	nextFrame(t, b)
	if f := nextFrame(t, b); !f.Resync {
		t.Fatal("old tab after gap", f)
	}
}

// Concurrent incident checks of one login read its roles once, and a
// tenant change forgets them.
func TestLiveWatchRolesShared(t *testing.T) {
	w := &liveWatch{sockets: map[*liveSocket]struct{}{}, seq: 1, watched: 1}
	var reads atomic.Int32
	release := make(chan struct{})
	read := func(context.Context) (map[string]sfc.Role, error) {
		reads.Add(1)
		<-release
		return map[string]sfc.Role{"shop": sfc.RoleManager}, nil
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := w.tenantRoles(context.Background(), read); err != nil || r["shop"] == "" {
				t.Error(r, err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if reads.Load() != 1 {
		t.Fatal("reads", reads.Load())
	}
	w.receive(sfc.ChangeBatch{Index: 2, Refs: []control.WatchRef{{WatchKey: control.WatchKey{Kind: "tenant", Tenant: "shop", Name: "shop"}}}})
	if _, err := w.tenantRoles(context.Background(), read); err != nil || reads.Load() != 2 {
		t.Fatal("not forgotten", reads.Load(), err)
	}
}

// A tenant change during a roles read keeps that read's result from being
// kept: the next check reads again.
func TestLiveWatchRolesForgetDuringRead(t *testing.T) {
	w := &liveWatch{sockets: map[*liveSocket]struct{}{}, seq: 1, watched: 1}
	reads := 0
	read := func(context.Context) (map[string]sfc.Role, error) {
		reads++
		if reads == 1 {
			w.forgetRoles()
		}
		return map[string]sfc.Role{"shop": sfc.RoleManager}, nil
	}
	if _, err := w.tenantRoles(context.Background(), read); err != nil {
		t.Fatal(err)
	}
	if _, err := w.tenantRoles(context.Background(), read); err != nil || reads != 2 {
		t.Fatal("stale roles kept", reads, err)
	}
}

// An engine notice keeps its container and reasons for the screens.
func TestLiveRefsEngineNotice(t *testing.T) {
	refs := liveRefs(sfc.ChangeBatch{Events: []userauth.ChangeEvent{{Topic: "engine", Kind: "engine.container", Node: "n1", Tenant: "shop", App: "web", Container: "c1", Reasons: []string{"die", "start"}}}})
	if len(refs) != 1 || refs[0] != (liveRef{Kind: "engine.container", Tenant: "shop", Name: "n1", App: "web", Container: "c1", Reasons: "die,start"}) {
		t.Fatal(refs)
	}
}
