// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
)

// Test-only family (topic-space 5-4).
const topicTestFamily = "tq"

func init() { topicSlots[topicTestFamily] = topicSlot{"tests", "topics_test.go"} }

// fakeTimers records timers instead of running them, so tests fire
// redelivery and expiry by hand and can see that nothing ticks while idle.
type fakeTimers struct {
	mu  sync.Mutex
	all []*fakeTimer
}

type fakeTimer struct {
	d       time.Duration
	f       func()
	stopped bool
}

func (t *fakeTimer) Stop() bool { t.stopped = true; return true }

func (ft *fakeTimers) after(d time.Duration, f func()) topicTimer {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	t := &fakeTimer{d: d, f: f}
	ft.all = append(ft.all, t)
	return t
}

// fire runs every live timer of duration d and reports how many ran.
func (ft *fakeTimers) fire(d time.Duration) int {
	ft.mu.Lock()
	var run []*fakeTimer
	for _, t := range ft.all {
		if t.d == d && !t.stopped {
			t.stopped = true
			run = append(run, t)
		}
	}
	ft.mu.Unlock()
	for _, t := range run {
		t.f()
	}
	return len(run)
}

type topicPair struct {
	pub, sub *Topics
	session  *Session
	timers   *fakeTimers
}

// topicWirePair: real QUIC between "consumer" (subscriber) and "provider"
// (publisher), both members, both with acl for the test family.
func topicWirePair(t *testing.T, acl TopicACL) topicPair {
	t.Helper()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(a.Private); clear(b.Private) })
	peers := map[Identity]Peer{
		Identity(a.Public): {ID: "consumer", Policy: Policy{Key: Identity(a.Public), Member: true, Respond: true}},
		Identity(b.Public): {ID: "provider", Policy: Policy{Key: Identity(b.Public), Member: true, Respond: true}},
	}
	lookup := func(key Identity) (Peer, bool) { p, ok := peers[key]; return p, ok }
	server, err := NewTransport(b, [32]byte{94}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	pub, err := NewTopics(server)
	if err != nil {
		t.Fatal(err)
	}
	timers := &fakeTimers{}
	pub.after = timers.after
	if err = pub.ReserveTopic(topicTestFamily, acl); err != nil {
		t.Fatal(err)
	}
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	client, err := NewTransport(a, [32]byte{94}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	sub, err := NewTopics(client)
	if err != nil {
		t.Fatal(err)
	}
	if err = sub.ReserveTopic(topicTestFamily, acl); err != nil {
		t.Fatal(err)
	}
	peer := peers[Identity(b.Public)]
	peer.Endpoint = server.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	return topicPair{pub: pub, sub: sub, session: session, timers: timers}
}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func waitAvailable(t *testing.T, sub *Subscription) {
	t.Helper()
	select {
	case <-sub.Available():
	case <-time.After(5 * time.Second):
		t.Fatal("no Available notice")
	}
}

// eventually polls a condition the other side changes; tests only.
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

func TestTopicNamesAndPatterns(t *testing.T) {
	for _, c := range []struct {
		s       string
		pattern bool
		ok      bool
	}{
		{"obs/jay2/host", false, true},
		{"obs/jay2/#", true, true},
		{"obs/+/cns", true, true},
		{"obs/jay2/#", false, false},
		{"#", true, false},
		{"+/jay2", true, false},
		{"obs/#/x", true, false},
		{"obs//x", false, false},
		{"obs/Jay2", false, false},
		{"obs/" + strings.Repeat("a", TopicMaxBytes-4), false, true},
		{"obs/" + strings.Repeat("a", TopicMaxBytes-3), false, false},
		{"obs/" + strings.Repeat("a/", 300) + "a", false, true}, // no segment count limit
	} {
		if _, ok := splitTopic(c.s, c.pattern); ok != c.ok {
			t.Errorf("splitTopic(%.40q, %v) = %v", c.s, c.pattern, ok)
		}
	}
	match := func(p, s string) bool {
		ps, _ := splitTopic(p, true)
		ss, _ := splitTopic(s, false)
		return matchTopic(ps, ss)
	}
	if !match("obs/jay2/#", "obs/jay2/dsk/sys") || !match("obs/+/cns", "obs/jay3/cns") || match("obs/+/cns", "obs/jay3/cns/x") || match("obs/jay2/host", "obs/jay2") {
		t.Fatal("pattern matching")
	}
	// XXH32 reference values.
	if xxhash32(nil) != 0x02cc5d05 || xxhash32([]byte("abc")) != 0x32d153ff ||
		xxhash32([]byte("Nobody inspects the spammish repetition")) != 0xe2293b2f {
		t.Fatalf("xxhash32 = %08x %08x", xxhash32(nil), xxhash32([]byte("abc")))
	}
	sha := strings.Repeat("ab12", 16)
	if TopicSegment("Jay2") != "jay2" || TopicSegment(sha) != sha {
		t.Fatal("a value that fits must stay as it is")
	}
	for _, v := range []string{"개발팀", "my team", "a/b", "+", "#", ""} {
		s := TopicSegment(v)
		if len(s) != 9 || s[0] != 'x' || !validSegment(s) {
			t.Fatalf("TopicSegment(%q) = %q", v, s)
		}
	}
	if TopicName("obs", "Jay2", "use", "개발팀") != "obs/jay2/use/"+TopicSegment("개발팀") {
		t.Fatal("TopicName")
	}
}

func TestTopicWireCodecs(t *testing.T) {
	now := time.Now()
	long := "tq/provider/" + strings.Repeat("z", 1000)
	m := &outMsg{topic: long, flags: topicBinary | topicReplace, seq: 7, expires: now.Add(time.Minute), data: []byte{1, 2, 3}}
	b := appendMessage(appendMessage(nil, m, now), m, now)
	ins, ok := decodeMessages(b)
	if !ok || len(ins) != 2 || ins[0].topic != long || ins[1].seq != 7 || !bytes.Equal(ins[1].data, []byte{1, 2, 3}) {
		t.Fatal("messages round trip")
	}
	if _, ok := decodeMessages(b[:len(b)-1]); ok {
		t.Fatal("cut message accepted")
	}
	keys := []topicAckKey{{topic: long, seq: 1}, {topic: "tq/a", seq: 2}}
	got, ok := decodeAcks(encodeAcks(keys))
	if !ok || len(got) != 2 || got[0].topic != long || got[1].seq != 2 {
		t.Fatal("acks round trip")
	}
	c, ok := decodeChange(encodeChange(topicChange{flags: topicPush, add: []string{long}, remove: []string{"tq/x"}}))
	if !ok || c.flags != topicPush || c.add[0] != long || c.remove[0] != "tq/x" {
		t.Fatal("change round trip")
	}
}

func TestTopicReservationTable(t *testing.T) {
	h := &Topics{acls: map[string]*TopicACL{}}
	if err := h.ReserveTopic("zz", TopicACL{}); !errors.Is(err, ErrTopicSlot) {
		t.Fatal("family without a slot accepted")
	}
	if err := h.ReserveTopic(TopicFamilyObservation, TopicACL{}); err != nil {
		t.Fatal(err)
	}
	if err := h.ReserveTopic(TopicFamilyObservation, TopicACL{}); !errors.Is(err, ErrTopicSlot) {
		t.Fatal("second ACL for one slot accepted")
	}
	for _, f := range []string{TopicFamilyAlarm, TopicFamilyTransit, TopicFamilyEngine, TopicFamilyWorkload} {
		if _, ok := topicSlots[f]; !ok {
			t.Fatalf("family %s not reserved", f)
		}
	}
	if err := h.Publish("alm/provider/x", nil, PublishOptions{}); !errors.Is(err, ErrTopic) {
		t.Fatal("publish in a family without ACL accepted")
	}
}

// Pull is the default: Available once, BulkGet takes the queue. Interest
// callbacks run before the subscribe reply, and replace keeps one value.
func TestTopicPullAvailableBulkGetReplace(t *testing.T) {
	p := topicWirePair(t, TopicACL{})
	p.pub.OnInterest(func(i Interest) {
		if i.Added && i.PeerID == "consumer" {
			if err := p.pub.Publish("tq/provider/now", []byte("current"), PublishOptions{Replace: true}); err != nil {
				t.Error(err)
			}
		}
	})
	ctx := testCtx(t)
	sub, results, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/provider/#", "zz/provider/#"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if len(results) != 2 || results[0] != TopicAccepted || results[1] != TopicDenied {
		t.Fatalf("results = %v", results)
	}
	if !p.pub.HasInterest("tq/provider/now") || p.pub.HasInterest("tq/other/now") {
		t.Fatal("HasInterest")
	}
	waitAvailable(t, sub)
	msgs, more, lost, err := sub.BulkGet(ctx, BulkGetOptions{})
	if err != nil || more || lost || len(msgs) != 1 || string(msgs[0].Data) != "current" || msgs[0].PublisherID != "provider" {
		t.Fatalf("first BulkGet = %v %v %v %v", msgs, more, lost, err)
	}
	for i := range 5 {
		if err := p.pub.Publish("tq/provider/rxtx", []byte{byte(i)}, PublishOptions{Binary: true, Replace: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.pub.Publish("tq/provider/other", []byte("x"), PublishOptions{}); err != nil {
		t.Fatal(err)
	}
	waitAvailable(t, sub)
	msgs, _, _, err = sub.BulkGet(ctx, BulkGetOptions{})
	if err != nil || len(msgs) != 2 {
		t.Fatalf("second BulkGet = %d, %v", len(msgs), err)
	}
	for _, m := range msgs {
		if m.Topic == "tq/provider/rxtx" && (!m.Binary || !bytes.Equal(m.Data, []byte{4})) {
			t.Fatal("replace did not keep only the newest value")
		}
	}
	// Idle: no timers are armed for best-effort traffic.
	p.timers.mu.Lock()
	n := len(p.timers.all)
	p.timers.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d timers armed without must-deliver", n)
	}
}

func TestTopicPushAndOverflowLost(t *testing.T) {
	p := topicWirePair(t, TopicACL{})
	ctx := testCtx(t)
	sub, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/+/a"}, Push: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if err := p.pub.Publish("tq/provider/a", []byte("hi"), PublishOptions{}); err != nil {
		t.Fatal(err)
	}
	msgs, lost, err := sub.Next(ctx, 0)
	if err != nil || lost || len(msgs) != 1 || string(msgs[0].Data) != "hi" {
		t.Fatalf("Next = %v %v %v", msgs, lost, err)
	}
	// Switch to pull and overflow the best-effort queue.
	if _, err := sub.Change(ctx, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte{1}, TopicMaxData)
	for range 6 {
		if err := p.pub.Publish("tq/provider/a", big, PublishOptions{Binary: true}); err != nil {
			t.Fatal(err)
		}
	}
	waitAvailable(t, sub)
	msgs, _, lost, err = sub.BulkGet(ctx, BulkGetOptions{})
	if err != nil || !lost || len(msgs) == 0 || len(msgs) >= 6 {
		t.Fatalf("overflow BulkGet = %d lost %v %v", len(msgs), lost, err)
	}
	for _, m := range msgs {
		if len(m.Data) != TopicMaxData {
			t.Fatal("a message was split or merged")
		}
	}
	// A message from a publisher not allowed by the ACL is dropped alone.
	if err := p.pub.Publish("tq/someone/a", []byte("forged"), PublishOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := p.pub.Publish("tq/provider/a", []byte("real"), PublishOptions{}); err != nil {
		t.Fatal(err)
	}
	waitAvailable(t, sub)
	msgs, _, _, err = sub.BulkGet(ctx, BulkGetOptions{})
	if err != nil || len(msgs) != 1 || string(msgs[0].Data) != "real" {
		t.Fatalf("ACL check = %v %v", msgs, err)
	}
}

func TestTopicMustDeliverAckRequeueExpiry(t *testing.T) {
	var undelivered []string
	var umu sync.Mutex
	p := topicWirePair(t, TopicACL{MustDeliver: true, TTL: time.Minute, Undelivered: func(_ Identity, topic string, _ uint64) {
		umu.Lock()
		undelivered = append(undelivered, topic)
		umu.Unlock()
	}})
	ctx := testCtx(t)
	if err := p.pub.Publish("tq/provider/m", []byte("x"), PublishOptions{MustDeliver: true}); err != nil {
		t.Fatal(err)
	}
	sub, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/provider/#"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	if err := p.pub.Publish("tq/provider/m", []byte("must"), PublishOptions{MustDeliver: true}); err != nil {
		t.Fatal(err)
	}
	waitAvailable(t, sub)
	msgs, _, _, err := sub.BulkGet(ctx, BulkGetOptions{})
	if err != nil || len(msgs) != 1 || !msgs[0].MustDeliver {
		t.Fatalf("BulkGet = %v %v", msgs, err)
	}
	// Not acknowledged: after the pull requeue time it comes again.
	if p.timers.fire(topicPullRequeue) != 1 {
		t.Fatal("no requeue timer")
	}
	waitAvailable(t, sub)
	again, _, _, err := sub.BulkGet(ctx, BulkGetOptions{})
	if err != nil || len(again) != 1 || again[0].Seq != msgs[0].Seq {
		t.Fatalf("redelivery = %v %v", again, err)
	}
	if err := sub.BulkAck(ctx, again...); err != nil {
		t.Fatal(err)
	}
	eventually(t, "ack did not clear the held message", func() bool {
		p.pub.mu.Lock()
		defer p.pub.mu.Unlock()
		return len(p.pub.held) == 0
	})
	// The receiver re-acks a duplicate instead of handing it out again.
	if !p.sub.wasAcked(topicAckKey{again[0].Publisher, again[0].Topic, again[0].Seq}, time.Now()) {
		t.Fatal("receiver forgot the acknowledged key")
	}
	// TTL end without ack tells Undelivered.
	if err := p.pub.Publish("tq/provider/late", []byte("late"), PublishOptions{MustDeliver: true}); err != nil {
		t.Fatal(err)
	}
	if p.timers.fire(time.Minute) == 0 {
		p.timers.mu.Lock()
		var ds []time.Duration
		for _, x := range p.timers.all {
			if !x.stopped {
				ds = append(ds, x.d)
			}
		}
		p.timers.mu.Unlock()
		// Expiry is armed with the remaining TTL, a little under a minute.
		for _, d := range ds {
			if d > 50*time.Second && d <= time.Minute {
				p.timers.fire(d)
			}
		}
	}
	umu.Lock()
	defer umu.Unlock()
	if len(undelivered) != 1 || undelivered[0] != "tq/provider/late" {
		t.Fatalf("undelivered = %v", undelivered)
	}
}

func TestTopicBackpressure(t *testing.T) {
	p := topicWirePair(t, TopicACL{MustDeliver: true})
	ctx := testCtx(t)
	sub, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/provider/#"}})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	for i := range topicHeldPerPeer {
		if err := p.pub.Publish("tq/provider/m", []byte{byte(i)}, PublishOptions{Binary: true, MustDeliver: true}); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if err := p.pub.Publish("tq/provider/m", nil, PublishOptions{Binary: true, MustDeliver: true}); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("over the limit: %v", err)
	}
}

func TestTopicSubscriberGone(t *testing.T) {
	for _, keep := range []bool{true, false} {
		var gone []Gone
		var gmu sync.Mutex
		p := topicWirePair(t, TopicACL{MustDeliver: true, SubscriberGone: func(g Gone) GoneAction {
			gmu.Lock()
			gone = append(gone, g)
			gmu.Unlock()
			if keep {
				return Keep
			}
			return Drop
		}})
		var removed []string
		var imu sync.Mutex
		p.pub.OnInterest(func(i Interest) {
			if !i.Added {
				imu.Lock()
				removed = append(removed, i.Pattern)
				imu.Unlock()
			}
		})
		ctx := testCtx(t)
		sub, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/provider/#"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.pub.Publish("tq/provider/m", []byte("must"), PublishOptions{MustDeliver: true}); err != nil {
			t.Fatal(err)
		}
		sub.Close()
		eventually(t, "SubscriberGone not called", func() bool {
			gmu.Lock()
			defer gmu.Unlock()
			return len(gone) == 1
		})
		gmu.Lock()
		g := gone[0]
		gmu.Unlock()
		if g.PeerID != "consumer" || g.Reason != GoneUnsubscribed || len(g.Patterns) != 1 || g.Patterns[0] != "tq/provider/#" {
			t.Fatalf("gone = %+v", g)
		}
		p.pub.mu.Lock()
		held := len(p.pub.held)
		p.pub.mu.Unlock()
		if keep != (held == 1) {
			t.Fatalf("keep %v: held %d", keep, held)
		}
		imu.Lock()
		if len(removed) != 1 {
			t.Fatalf("interest removals = %v", removed)
		}
		imu.Unlock()
		if p.pub.HasInterest("tq/provider/m") {
			t.Fatal("interest stayed after close")
		}
	}
}

// A push subscriber that never calls Next keeps a bounded inbox and sees
// lost; the receiver's acknowledged-key memory stays bounded.
func TestTopicReceiverBounds(t *testing.T) {
	p := topicWirePair(t, TopicACL{})
	ctx := testCtx(t)
	sub, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/provider/#"}, Push: true})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	big := bytes.Repeat([]byte{1}, TopicMaxData)
	for range 8 {
		if err := p.pub.Publish("tq/provider/a", big, PublishOptions{Binary: true}); err != nil {
			t.Fatal(err)
		}
		// Let the writer hand each one over so the publisher queue never
		// overflows; the inbox is what must stay bounded.
		eventually(t, "message not handed", func() bool {
			p.pub.mu.Lock()
			defer p.pub.mu.Unlock()
			for st := range p.pub.streams {
				if len(st.queue) != 0 {
					return false
				}
			}
			return true
		})
	}
	eventually(t, "inbox not filled", func() bool {
		sub.mu.Lock()
		defer sub.mu.Unlock()
		return sub.lost
	})
	sub.mu.Lock()
	size, n := sub.inboxSize, len(sub.inbox)
	sub.mu.Unlock()
	if size > topicQueueBytes || n == 0 || n >= 8 {
		t.Fatalf("inbox %d bytes, %d messages", size, n)
	}
	msgs, lost, err := sub.Next(ctx, 0)
	if err != nil || !lost || len(msgs) != n {
		t.Fatalf("Next = %d %v %v", len(msgs), lost, err)
	}
	sub.mu.Lock()
	size = sub.inboxSize
	sub.mu.Unlock()
	if size != 0 {
		t.Fatalf("inbox size after Next = %d", size)
	}

	h := &Topics{acked: map[topicAckKey]time.Time{}, now: time.Now}
	keys := make([]topicAckKey, 1000)
	for round := range 80 {
		for i := range keys {
			keys[i] = topicAckKey{topic: "tq/x", seq: uint64(round*len(keys) + i)}
		}
		h.rememberAcked(keys)
	}
	if len(h.acked) > topicAckedMax {
		t.Fatalf("acked keys = %d", len(h.acked))
	}
}

// No stream limit; under load the subscription that went longest without
// taking anything is closed (GoneShed) and the others keep working.
func TestTopicShedUnderLoad(t *testing.T) {
	old := topicLoadBytes
	topicLoadBytes = 100 << 10
	t.Cleanup(func() { topicLoadBytes = old })
	p := topicWirePair(t, TopicACL{})
	ctx := testCtx(t)
	var subs []*Subscription
	for i := range 10 { // more than the old per-session limit of 4
		s, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{fmt.Sprintf("tq/provider/a%d", i)}})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		subs = append(subs, s)
	}
	idle, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/provider/#"}})
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	big := bytes.Repeat([]byte{1}, TopicMaxData)
	for range 2 {
		if err := p.pub.Publish("tq/provider/b", big, PublishOptions{Binary: true}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-idle.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("idle subscription not shed")
	}
	eventually(t, "shed stream not forgotten", func() bool {
		p.pub.mu.Lock()
		defer p.pub.mu.Unlock()
		return len(p.pub.streams) == 10 && p.pub.queueBytes == 0
	})
	if err := p.pub.Publish("tq/provider/a0", []byte("still"), PublishOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-subs[0].Done():
		t.Fatalf("other subscription ended: %v", subs[0].Err())
	default:
	}
	waitAvailable(t, subs[0])
	msgs, _, _, err := subs[0].BulkGet(ctx, BulkGetOptions{})
	if err != nil || len(msgs) != 1 {
		t.Fatalf("other subscription = %v %v", msgs, err)
	}
}

// PublishTo from an added interest reaches only the new subscription,
// before its subscribe reply; the subscription that already has the value
// does not get it again (R18 #827 follow-up).
func TestTopicPublishToNewSubscriber(t *testing.T) {
	p := topicWirePair(t, TopicACL{})
	var last Interest
	p.pub.OnInterest(func(i Interest) {
		if !i.Added {
			return
		}
		last = i
		if err := p.pub.PublishTo(i, "tq/provider/now", []byte("current"), PublishOptions{Replace: true}); err != nil {
			t.Error(err)
		}
	})
	ctx := testCtx(t)
	first, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/provider/#"}})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	waitAvailable(t, first)
	if msgs, _, _, err := first.BulkGet(ctx, BulkGetOptions{}); err != nil || len(msgs) != 1 {
		t.Fatalf("first BulkGet = %d, %v", len(msgs), err)
	}
	second, _, err := p.sub.Subscribe(ctx, p.session, SubscribeOptions{Patterns: []string{"tq/provider/now"}})
	if err != nil {
		t.Fatal(err)
	}
	// The value was queued before the reply, so it is there already.
	msgs, _, _, err := second.BulkGet(ctx, BulkGetOptions{})
	if err != nil || len(msgs) != 1 || string(msgs[0].Data) != "current" {
		t.Fatalf("second BulkGet = %v, %v", msgs, err)
	}
	if msgs, _, _, err := first.BulkGet(ctx, BulkGetOptions{}); err != nil || len(msgs) != 0 {
		t.Fatalf("first subscription got the value again: %d, %v", len(msgs), err)
	}
	if err := p.pub.PublishTo(last, "tq/provider/other", nil, PublishOptions{}); !errors.Is(err, ErrTopicGone) {
		t.Fatalf("PublishTo a topic the subscription does not match = %v", err)
	}
	second.Close()
	eventually(t, "second subscription gone", func() bool {
		return errors.Is(p.pub.PublishTo(last, "tq/provider/now", nil, PublishOptions{}), ErrTopicGone)
	})
	if err := p.pub.PublishTo(Interest{}, "tq/provider/now", nil, PublishOptions{}); !errors.Is(err, ErrTopicGone) {
		t.Fatalf("PublishTo a zero Interest = %v", err)
	}
}
