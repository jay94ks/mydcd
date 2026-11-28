// SPDX-License-Identifier: Apache-2.0

package topiclast

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

type wire struct {
	pub     *sfcp.Topics
	sub     *sfcp.Topics
	session *sfcp.Session
	dials   atomic.Int32
	down    atomic.Bool
}

// newWire: real QUIC between "consumer" (subscriber) and "provider"
// (publisher), both members, with the obs family on both sides.
func newWire(t *testing.T) *wire {
	t.Helper()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peers := map[sfcp.Identity]sfcp.Peer{
		sfcp.Identity(a.Public): {ID: "consumer", Policy: sfcp.Policy{Key: sfcp.Identity(a.Public), Member: true, Respond: true}},
		sfcp.Identity(b.Public): {ID: "provider", Policy: sfcp.Policy{Key: sfcp.Identity(b.Public), Member: true, Respond: true}},
	}
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) { p, ok := peers[key]; return p, ok }
	server, err := sfcp.NewTransport(b, [32]byte{7}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	pub, err := sfcp.NewTopics(server)
	if err != nil {
		t.Fatal(err)
	}
	if err = pub.ReserveTopic(sfcp.TopicFamilyObservation, sfcp.TopicACL{TTL: 150 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	client, err := sfcp.NewTransport(a, [32]byte{7}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	sub, err := sfcp.NewTopics(client)
	if err != nil {
		t.Fatal(err)
	}
	if err = sub.ReserveTopic(sfcp.TopicFamilyObservation, sfcp.TopicACL{TTL: 150 * time.Second}); err != nil {
		t.Fatal(err)
	}
	peer := peers[sfcp.Identity(b.Public)]
	peer.Endpoint = server.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	return &wire{pub: pub, sub: sub, session: session}
}

func (w *wire) dial(ctx context.Context, peer string, o sfcp.SubscribeOptions) (Sub, []uint8, error) {
	w.dials.Add(1)
	if w.down.Load() || peer != "provider" {
		return nil, nil, errors.New("no session")
	}
	s, r, err := w.sub.Subscribe(ctx, w.session, o)
	if err != nil {
		return nil, nil, err
	}
	return s, r, nil
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func valueOf(c *Cache, topic string) string {
	for _, v := range c.Values(topic) {
		return string(v.Data)
	}
	return ""
}

func TestMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, topic string
		want           bool
	}{
		{"obs/#", "obs/a/host", true},
		{"obs/+/host", "obs/a/host", true},
		{"obs/+/host", "obs/a/dsk/sys", false},
		{"obs/a/#", "obs/a", true},
		{"obs/+/tsk/#", "obs/a/tsk/k1", true},
		{"obs/a/host", "obs/a/host/x", false},
	} {
		if got := Match(tc.pattern, tc.topic); got != tc.want {
			t.Errorf("Match(%q, %q) = %v", tc.pattern, tc.topic, got)
		}
	}
}

// A new subscription gets the fresh remembered values before its answer,
// so one Wait is a snapshot; a value older than MaxAge is not sent and the
// family is asked to measure again.
func TestSnapshotOnSubscribeAndStale(t *testing.T) {
	w := newWire(t)
	now := time.Now()
	var stale []string
	var staleMu sync.Mutex
	store := NewStore(w.pub, StoreOptions{
		Family: sfcp.TopicFamilyObservation, MaxAge: 120 * time.Second,
		Publish: sfcp.PublishOptions{Replace: true},
		Stale: func(p string) {
			staleMu.Lock()
			stale = append(stale, p)
			staleMu.Unlock()
		},
	})
	if sent, err := store.Set("obs/provider/host", []byte("h1"), now); err != nil || sent {
		t.Fatalf("Set without a subscriber: sent=%v err=%v", sent, err)
	}
	if _, err := store.Set("obs/provider/cns", []byte("old"), now.Add(-200*time.Second)); err != nil {
		t.Fatal(err)
	}

	var changed atomic.Int32
	c := NewCache(w.dial, CacheOptions{Linger: 50 * time.Millisecond, Changed: func(Value) { changed.Add(1) }})
	t.Cleanup(c.Close)
	c.SetPeers([]string{"provider"})
	release := c.Want("obs/+/host", false)
	if got := c.Wait(testCtx(t), "obs/+/host"); !got["provider"] {
		t.Fatalf("Wait = %v", got)
	}
	if v := valueOf(c, "obs/provider/host"); v != "h1" {
		t.Fatalf("snapshot value = %q", v)
	}

	releaseCns := c.Want("obs/+/cns", false)
	if got := c.Wait(testCtx(t), "obs/+/cns"); !got["provider"] {
		t.Fatalf("Wait cns = %v", got)
	}
	if v := valueOf(c, "obs/provider/cns"); v != "" {
		t.Fatalf("stale value was republished: %q", v)
	}
	staleMu.Lock()
	if len(stale) != 1 || stale[0] != "obs/+/cns" {
		t.Fatalf("Stale calls = %v", stale)
	}
	staleMu.Unlock()

	// A later value travels as pull: Available, then BulkGet.
	if sent, err := store.Set("obs/provider/host", []byte("h2"), time.Now()); err != nil || !sent {
		t.Fatalf("Set with a subscriber: sent=%v err=%v", sent, err)
	}
	eventually(t, "h2 not received", func() bool { return valueOf(c, "obs/provider/host") == "h2" })
	if changed.Load() < 2 {
		t.Fatalf("Changed calls = %d", changed.Load())
	}

	// After release and Linger the subscription goes away.
	release()
	releaseCns()
	eventually(t, "subscription kept after linger", func() bool {
		return !store.HasInterest("obs/provider/host") && !store.HasInterest("obs/provider/cns")
	})
}

func TestPushWantAndAccept(t *testing.T) {
	w := newWire(t)
	store := NewStore(w.pub, StoreOptions{Family: sfcp.TopicFamilyObservation, Publish: sfcp.PublishOptions{Replace: true}})
	c := NewCache(w.dial, CacheOptions{Linger: time.Minute, Accept: func(m sfcp.Message, prev []byte, had bool) bool {
		return string(m.Data) != "reject"
	}})
	t.Cleanup(c.Close)
	c.SetPeers([]string{"provider"})
	defer c.Want("obs/#", true)()
	if got := c.Wait(testCtx(t), "obs/#"); !got["provider"] {
		t.Fatalf("Wait = %v", got)
	}
	eventually(t, "no interest at the publisher", func() bool { return store.HasInterest("obs/provider/host") })
	if _, err := store.Set("obs/provider/host", []byte("p1"), time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "p1 not pushed", func() bool { return valueOf(c, "obs/provider/host") == "p1" })
	if _, err := store.Set("obs/provider/host", []byte("reject"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Set("obs/provider/dev", []byte("d1"), time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "d1 not pushed", func() bool { return valueOf(c, "obs/provider/dev") == "d1" })
	if v := valueOf(c, "obs/provider/host"); v != "p1" {
		t.Fatalf("Accept was not applied: %q", v)
	}
}

// A publisher without a session stays waiting ("대기 중"): Wait returns at
// its deadline with false, and PeerUp dials again at once.
func TestUnreachablePublisherIsWaiting(t *testing.T) {
	w := newWire(t)
	NewStore(w.pub, StoreOptions{Family: sfcp.TopicFamilyObservation})
	w.down.Store(true)
	c := NewCache(w.dial, CacheOptions{Linger: time.Minute, RetryMin: time.Hour, RetryMax: time.Hour})
	t.Cleanup(c.Close)
	c.SetPeers([]string{"provider", "absent"})
	defer c.Want("obs/+/host", false)()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	got := c.Wait(ctx, "obs/+/host")
	if got["provider"] || got["absent"] || len(got) != 2 {
		t.Fatalf("Wait = %v", got)
	}
	w.down.Store(false)
	c.PeerUp("provider")
	eventually(t, "PeerUp did not dial again", func() bool { return c.Synced("obs/+/host")["provider"] })
	c.SetPeers([]string{"provider"})
	if got := c.Wait(testCtx(t), "obs/+/host"); len(got) != 1 || !got["provider"] {
		t.Fatalf("after SetPeers: %v", got)
	}
}

// Values a released pattern brought in are forgotten after Linger.
func TestReleasedPatternDropsItsValues(t *testing.T) {
	w := newWire(t)
	store := NewStore(w.pub, StoreOptions{Family: sfcp.TopicFamilyObservation})
	if _, err := store.Set("obs/provider/host", []byte("h"), time.Now()); err != nil {
		t.Fatal(err)
	}
	c := NewCache(w.dial, CacheOptions{Linger: 20 * time.Millisecond})
	t.Cleanup(c.Close)
	c.SetPeers([]string{"provider"})
	release := c.Want("obs/+/host", false)
	c.Wait(testCtx(t), "obs/+/host")
	if valueOf(c, "obs/provider/host") != "h" {
		t.Fatal("no value")
	}
	release()
	eventually(t, "value kept after the pattern went away", func() bool { return len(c.Values("obs/#")) == 0 })
}
