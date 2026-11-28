// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/topiclast"
)

func TestNodeAlarmReach(t *testing.T) {
	ok := eventbus.Event{Topic: "alarm/disk", Scope: eventbus.Scope{Nodes: []string{"b"}}}
	if !validNodeAlarm(ok) || !alarmReaches(ok.Scope, "b") || alarmReaches(ok.Scope, "c") {
		t.Fatal("named node reach")
	}
	for name, e := range map[string]eventbus.Event{
		"no reach":   {Topic: "alarm/disk"},
		"user":       {Topic: "alarm/disk", Scope: eventbus.Scope{Web: true, User: "u"}},
		"topic":      {Topic: eventbus.TopicReport, Scope: eventbus.Scope{AllNodes: true}},
		"long note":  {Topic: "alarm/disk", Scope: eventbus.Scope{AllNodes: true}, Note: strings.Repeat("x", eventbus.MaxAlarmNote+1)},
		"many nodes": {Topic: "alarm/disk", Scope: eventbus.Scope{Nodes: make([]string, 65)}},
	} {
		if validNodeAlarm(e) {
			t.Fatal("accepted", name)
		}
	}
	web := eventbus.Scope{Web: true}
	if !alarmReaches(web, "any") || !alarmReaches(eventbus.Scope{AllNodes: true}, "any") {
		t.Fatal("broad reach")
	}
}

// alarmNet is real QUIC from "b" and "c" to publisher "a", each with its
// own alm side and bus.
type alarmNet struct {
	sides map[string]*alarmTopics
	buses map[string]*eventbus.Sub
}

func newAlarmNet(t *testing.T) *alarmNet {
	t.Helper()
	ids := map[string]*identity.Identity{}
	peers := map[sfcp.Identity]sfcp.Peer{}
	for _, n := range []string{"a", "b", "c"} {
		id, err := identity.Create(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		ids[n] = id
		peers[sfcp.Identity(id.Public)] = sfcp.Peer{ID: n, Policy: sfcp.Policy{Key: sfcp.Identity(id.Public), Member: true, Respond: true}}
	}
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) { p, ok := peers[key]; return p, ok }
	net := &alarmNet{sides: map[string]*alarmTopics{}, buses: map[string]*eventbus.Sub{}}
	var server *sfcp.Transport
	for _, n := range []string{"a", "b", "c"} {
		tr, err := sfcp.NewTransport(ids[n], [32]byte{7}, lookup)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tr.Close() })
		topics, err := sfcp.NewTopics(tr)
		if err != nil {
			t.Fatal(err)
		}
		if err = topics.ReserveTopic(sfcp.TopicFamilyAlarm, sfcp.TopicACL{TTL: alarmTopicTTL}); err != nil {
			t.Fatal(err)
		}
		var dial topiclast.Dialer
		if n == "a" {
			server = tr
			if err = tr.Listen("127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			dial = func(context.Context, string, sfcp.SubscribeOptions) (topiclast.Sub, []uint8, error) {
				return nil, nil, errObservationPeerDown
			}
		} else {
			peer := peers[sfcp.Identity(ids["a"].Public)]
			peer.Endpoint = server.Addr().String()
			dial = func(ctx context.Context, to string, o sfcp.SubscribeOptions) (topiclast.Sub, []uint8, error) {
				if to != "a" {
					return nil, nil, errObservationPeerDown
				}
				s, err := tr.Dial(ctx, peer)
				if err != nil {
					return nil, nil, err
				}
				sub, res, err := topics.Subscribe(ctx, s, o)
				if err != nil {
					return nil, nil, err
				}
				return sub, res, nil
			}
		}
		bus := eventbus.New()
		net.buses[n] = bus.Subscribe(0, nil)
		side := newAlarmTopics(n, topics, bus, dial)
		t.Cleanup(side.cache.Close)
		net.sides[n] = side
	}
	for _, n := range []string{"b", "c"} {
		net.sides[n].cache.SetPeers([]string{"a"})
	}
	return net
}

func (n *alarmNet) next(t *testing.T, node string, wait time.Duration) (eventbus.Event, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	batch, _, err := n.buses[node].Next(ctx)
	if err != nil || len(batch) == 0 {
		return eventbus.Event{}, false
	}
	return batch[0], true
}

// Alarms go over the alm family only to the servers in reach, under the
// sender's name (P4: alm replaces Observation kind 20).
func TestNodeAlarmOverTopics(t *testing.T) {
	n := newAlarmNet(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		n.sides["a"].mu.Lock()
		subscribed := len(n.sides["a"].subs) == 2
		n.sides["a"].mu.Unlock()
		if subscribed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("b and c did not subscribe to alm/# on a")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if alarmTopicName("a", "alarm/disk.full") != "alm/a/disk.full" {
		t.Fatal("alarm topic name")
	}
	if err := n.sides["a"].send(eventbus.Event{Topic: "alarm/disk.full", Node: "forged", Note: "70%", Scope: eventbus.Scope{Nodes: []string{"b"}}}); err != nil {
		t.Fatal(err)
	}
	e, ok := n.next(t, "b", 5*time.Second)
	if !ok || e.Topic != "alarm/disk.full" || e.Node != "a" || e.Note != "70%" {
		t.Fatalf("b got %+v, %v", e, ok)
	}
	if e, ok := n.next(t, "c", 300*time.Millisecond); ok {
		t.Fatalf("c is out of reach but got %+v", e)
	}
	if e, ok := n.next(t, "a", 100*time.Millisecond); ok {
		t.Fatalf("a is out of reach but published %+v", e)
	}
	if err := n.sides["a"].send(eventbus.Event{Topic: "alarm/up", Scope: eventbus.Scope{AllNodes: true}}); err != nil {
		t.Fatal(err)
	}
	for _, node := range []string{"a", "b", "c"} {
		if e, ok := n.next(t, node, 5*time.Second); !ok || e.Topic != "alarm/up" || e.Node != "a" {
			t.Fatalf("%s got %+v, %v", node, e, ok)
		}
	}
	if err := n.sides["a"].send(eventbus.Event{Topic: "alarm/up"}); !errors.Is(err, errAlarm) {
		t.Fatal("alarm without reach accepted", err)
	}
}

// A message whose topic does not name its publisher, or whose body names
// another alarm, is dropped.
func TestNodeAlarmAcceptChecksTopic(t *testing.T) {
	bus := eventbus.New()
	sub := bus.Subscribe(0, nil)
	a := &alarmTopics{self: "b", bus: bus}
	raw := []byte(`{"Topic":"alarm/disk","Scope":{"AllNodes":true}}`)
	for _, m := range []sfcp.Message{
		{Topic: "alm/x/disk", PublisherID: "a", Data: raw},
		{Topic: "alm/a/other", PublisherID: "a", Data: raw},
		{Topic: "alm/a/disk", PublisherID: "a", Data: raw, Binary: true},
	} {
		a.accept(m, nil, false)
	}
	a.accept(sfcp.Message{Topic: "alm/a/disk", PublisherID: "a", Data: raw}, nil, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	batch, _, err := sub.Next(ctx)
	if err != nil || len(batch) != 1 || batch[0].Node != "a" || batch[0].Topic != "alarm/disk" {
		t.Fatalf("accepted %+v, %v", batch, err)
	}
}
