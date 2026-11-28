// SPDX-License-Identifier: Apache-2.0

// Package topiclast keeps last values on top of the SFCP Topic channel
// (purpose 26). The channel itself remembers nothing (sfcp-topics.md 3-3);
// Jay 2026-11-28 10:12 KST asked for "마지막 값 보관" as a separate module
// that families use (devel/design/node-observation-topics.md 2-1a).
//
// Store is the publishing side: it remembers each topic's last message and,
// when a subscription appears, publishes again the ones that are still fresh.
// Cache is the subscribing side: it keeps subscriptions open to a set of
// publishers while someone wants a pattern, holds the last value of each
// topic, and knows per publisher whether a pattern is synced.
package topiclast

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
)

// Match reports whether a topic pattern ("+" one segment, final "#" the
// rest) matches topic. It follows sfcp's matching (sfcp-topics.md 2-1).
func Match(pattern, topic string) bool {
	p, t := strings.Split(pattern, "/"), strings.Split(topic, "/")
	for i, seg := range p {
		if seg == "#" && i == len(p)-1 {
			return true
		}
		if i >= len(t) || seg != "+" && seg != t[i] {
			return false
		}
	}
	return len(p) == len(t)
}

// ---- publishing side ----

// Publisher is the part of *sfcp.Topics a Store uses.
type Publisher interface {
	Publish(topic string, data []byte, o sfcp.PublishOptions) error
	PublishTo(in sfcp.Interest, topic string, data []byte, o sfcp.PublishOptions) error
	HasInterest(topic string) bool
	OnInterest(func(sfcp.Interest))
}

// StoreOptions configure a Store.
type StoreOptions struct {
	// Family is the topic family (first segment); interests in other
	// families are ignored.
	Family string
	// MaxAge bounds how old a remembered value may be and still be
	// published again to a new subscriber. Zero means no bound.
	MaxAge time.Duration
	// Publish are the options for every publication.
	Publish sfcp.PublishOptions
	// Stale is called, after the fresh values were published, when a new
	// subscription matched a remembered value older than MaxAge. The
	// family measures again and calls Set; until then the subscriber has
	// no value for that topic.
	Stale func(pattern string)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

type stored struct {
	data []byte
	at   time.Time
}

// Store remembers the last message of each topic this node publishes.
type Store struct {
	pub  Publisher
	opts StoreOptions

	mu   sync.Mutex
	last map[string]stored
}

// NewStore attaches a Store to pub's interest callbacks.
func NewStore(pub Publisher, o StoreOptions) *Store {
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &Store{pub: pub, opts: o, last: map[string]stored{}}
	pub.OnInterest(s.interest)
	return s
}

// Set remembers data as topic's value taken at at, and publishes it when
// some subscription matches. published says whether it was sent.
func (s *Store) Set(topic string, data []byte, at time.Time) (published bool, err error) {
	s.mu.Lock()
	s.last[topic] = stored{data: append([]byte(nil), data...), at: at}
	s.mu.Unlock()
	if !s.pub.HasInterest(topic) {
		return false, nil
	}
	if err := s.pub.Publish(topic, data, s.opts.Publish); err != nil {
		return false, err
	}
	return true, nil
}

// Keep remembers data as topic's value without publishing it: an unchanged
// value the family does not send again yet, which a new subscriber still
// gets.
func (s *Store) Keep(topic string, data []byte, at time.Time) {
	s.mu.Lock()
	s.last[topic] = stored{data: append([]byte(nil), data...), at: at}
	s.mu.Unlock()
}

// Get returns topic's remembered value.
func (s *Store) Get(topic string) (data []byte, at time.Time, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.last[topic]
	return v.data, v.at, ok
}

// Delete forgets topic (its source went away).
func (s *Store) Delete(topic string) {
	s.mu.Lock()
	delete(s.last, topic)
	s.mu.Unlock()
}

// HasInterest reports whether some subscription matches topic.
func (s *Store) HasInterest(topic string) bool { return s.pub.HasInterest(topic) }

// interest runs synchronously before the subscription's answer, so what it
// publishes reaches the new subscriber ahead of the answer (#816).
func (s *Store) interest(i sfcp.Interest) {
	if !i.Added || strings.SplitN(i.Pattern, "/", 2)[0] != s.opts.Family {
		return
	}
	now := s.opts.Now()
	type out struct {
		topic string
		data  []byte
	}
	var fresh []out
	stale := false
	s.mu.Lock()
	for topic, v := range s.last {
		if !Match(i.Pattern, topic) {
			continue
		}
		if s.opts.MaxAge > 0 && now.Sub(v.at) > s.opts.MaxAge {
			stale = true
			continue
		}
		fresh = append(fresh, out{topic, v.data})
	}
	s.mu.Unlock()
	// Only the new subscription gets them; the others already have them.
	for _, m := range fresh {
		_ = s.pub.PublishTo(i, m.topic, m.data, s.opts.Publish)
	}
	if stale && s.opts.Stale != nil {
		s.opts.Stale(i.Pattern)
	}
}

// ---- subscribing side ----

// Sub is the part of *sfcp.Subscription a Cache uses.
type Sub interface {
	Change(ctx context.Context, add, remove []string, push bool) ([]uint8, error)
	BulkGet(ctx context.Context, o sfcp.BulkGetOptions) (msgs []sfcp.Message, more, lost bool, err error)
	Next(ctx context.Context, max int) (msgs []sfcp.Message, lost bool, err error)
	Available() <-chan struct{}
	Done() <-chan struct{}
	Close()
}

// Dialer opens a subscription to one publisher. It fails when there is no
// session to that peer; the Cache tries again when told the peer is up.
type Dialer func(ctx context.Context, peer string, o sfcp.SubscribeOptions) (Sub, []uint8, error)

// Value is one topic's last received message.
type Value struct {
	Publisher string
	Topic     string
	Data      []byte
	Received  time.Time
}

// CacheOptions configure a Cache.
type CacheOptions struct {
	// Linger is how long a pattern stays subscribed after its last want
	// is released (design 6-2: 150s).
	Linger time.Duration
	// Accept decides whether m replaces prev (had says whether there was
	// one). Nil accepts every message. The family checks signatures and
	// drops older values here: the channel does not keep order.
	Accept func(m sfcp.Message, prev []byte, had bool) bool
	// Changed is told about every accepted value.
	Changed func(v Value)
	// Retry bounds the wait before dialing a peer again after a failure.
	RetryMin, RetryMax time.Duration
	Now                func() time.Time
}

type want struct {
	count int
	push  int
	timer *time.Timer
}

// Cache holds subscriptions and last values for the patterns someone wants.
type Cache struct {
	dial Dialer
	opts CacheOptions
	ctx  context.Context
	stop context.CancelFunc

	mu      sync.Mutex
	wants   map[string]*want
	peers   map[string]*peerSub
	values  map[string]map[string]Value // publisher -> topic -> value
	changed chan struct{}               // closed and replaced on every sync change
}

// NewCache starts a Cache; Close stops it.
func NewCache(dial Dialer, o CacheOptions) *Cache {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RetryMin <= 0 {
		o.RetryMin = time.Second
	}
	if o.RetryMax < o.RetryMin {
		o.RetryMax = 10 * time.Second
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Cache{dial: dial, opts: o, ctx: ctx, stop: stop,
		wants: map[string]*want{}, peers: map[string]*peerSub{},
		values: map[string]map[string]Value{}, changed: make(chan struct{})}
}

// Close ends every subscription.
func (c *Cache) Close() {
	c.stop()
	c.mu.Lock()
	for _, p := range c.peers {
		p.kick()
	}
	c.mu.Unlock()
}

// SetPeers names the publishers to subscribe to. Removed peers lose their
// subscription and values.
func (c *Cache) SetPeers(peers []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := map[string]bool{}
	for _, id := range peers {
		keep[id] = true
		if c.peers[id] == nil {
			p := &peerSub{c: c, id: id, wake: make(chan struct{}, 1), synced: map[string]bool{}}
			c.peers[id] = p
			go p.run()
			p.kick()
		}
	}
	for id, p := range c.peers {
		if !keep[id] {
			delete(c.peers, id)
			delete(c.values, id)
			p.gone = true
			p.kick()
		}
	}
	c.notifyLocked()
}

// PeerUp says a session to peer (re)appeared; a failed or ended
// subscription to it is opened again at once.
func (c *Cache) PeerUp(peer string) {
	c.mu.Lock()
	p := c.peers[peer]
	if p != nil {
		p.up = true
	}
	c.mu.Unlock()
	if p != nil {
		p.kick()
	}
}

// Want keeps pattern subscribed until release is called and Linger passes.
// push asks publishers to send at once instead of waiting for BulkGet.
func (c *Cache) Want(pattern string, push bool) (release func()) {
	c.mu.Lock()
	w := c.wants[pattern]
	isNew := w == nil
	if isNew {
		w = &want{}
		c.wants[pattern] = w
	}
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	w.count++
	pushChanged := false
	if push {
		w.push++
		pushChanged = w.push == 1
	}
	c.mu.Unlock()
	if isNew {
		// Every peer gets a fresh try for the new pattern: Wait waits for
		// it unless the dial fails again.
		c.mu.Lock()
		for _, p := range c.peers {
			p.failed = false
			p.up = true
		}
		c.mu.Unlock()
	}
	if isNew || pushChanged {
		c.kickAll()
	}
	var once sync.Once
	return func() { once.Do(func() { c.release(pattern, push) }) }
}

func (c *Cache) release(pattern string, push bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.wants[pattern]
	if w == nil {
		return
	}
	w.count--
	if push {
		w.push--
	}
	if w.count > 0 {
		return
	}
	w.timer = time.AfterFunc(c.opts.Linger, func() {
		c.mu.Lock()
		if c.wants[pattern] == w && w.count == 0 {
			delete(c.wants, pattern)
			c.dropUnwantedLocked()
		}
		c.mu.Unlock()
		c.kickAll()
	})
}

// dropUnwantedLocked forgets values no wanted pattern matches any more.
func (c *Cache) dropUnwantedLocked() {
	for peer, topics := range c.values {
		for topic := range topics {
			kept := false
			for pattern := range c.wants {
				if Match(pattern, topic) {
					kept = true
					break
				}
			}
			if !kept {
				delete(topics, topic)
			}
		}
		if len(topics) == 0 {
			delete(c.values, peer)
		}
	}
}

func (c *Cache) kickAll() {
	c.mu.Lock()
	for _, p := range c.peers {
		p.kick()
	}
	c.mu.Unlock()
}

// Synced reports, per current publisher, whether pattern is synced.
func (c *Cache) Synced(pattern string) map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]bool, len(c.peers))
	for id, p := range c.peers {
		out[id] = p.synced[pattern]
	}
	return out
}

// Wait waits until every current publisher has pattern synced or could not
// be dialed, or ctx ends, and returns the per-publisher state at that
// moment. A publisher that is not synced is shown as waiting ("대기 중",
// design 6-1).
func (c *Cache) Wait(ctx context.Context, pattern string) map[string]bool {
	for {
		c.mu.Lock()
		ch := c.changed
		all := true
		out := make(map[string]bool, len(c.peers))
		for id, p := range c.peers {
			out[id] = p.synced[pattern]
			all = all && (out[id] || p.failed)
		}
		c.mu.Unlock()
		if all {
			return out
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return out
		}
	}
}

// Values returns the last value of every topic that matches pattern.
func (c *Cache) Values(pattern string) []Value {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Value
	for _, topics := range c.values {
		for topic, v := range topics {
			if Match(pattern, topic) {
				out = append(out, v)
			}
		}
	}
	return out
}

func (c *Cache) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

// desiredLocked is the pattern set and push mode every peer should have.
func (c *Cache) desiredLocked() (map[string]bool, bool) {
	out := map[string]bool{}
	push := false
	for p, w := range c.wants {
		out[p] = true
		push = push || w.push > 0
	}
	return out, push
}

func (c *Cache) receive(peer string, msgs []sfcp.Message) {
	now := c.opts.Now()
	for _, m := range msgs {
		if m.PublisherID != peer {
			continue
		}
		c.mu.Lock()
		if c.peers[peer] == nil {
			c.mu.Unlock()
			return
		}
		prev, had := c.values[peer][m.Topic]
		c.mu.Unlock()
		// Accept may write to disk; it runs without the cache lock. A
		// peer's messages arrive from one reader at a time.
		if c.opts.Accept != nil && !c.opts.Accept(m, prev.Data, had) {
			continue
		}
		v := Value{Publisher: peer, Topic: m.Topic, Data: m.Data, Received: now}
		c.mu.Lock()
		if c.peers[peer] == nil {
			c.mu.Unlock()
			return
		}
		topics := c.values[peer]
		if topics == nil {
			topics = map[string]Value{}
			c.values[peer] = topics
		}
		topics[m.Topic] = v
		c.mu.Unlock()
		if c.opts.Changed != nil {
			c.opts.Changed(v)
		}
	}
}

// peerSub owns the one subscription stream to one publisher.
type peerSub struct {
	c    *Cache
	id   string
	wake chan struct{}

	// guarded by c.mu
	gone   bool
	up     bool
	failed bool // the last dial failed; Wait does not wait for this peer
	synced map[string]bool
}

func (p *peerSub) kick() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *peerSub) setFailed(v bool) {
	p.c.mu.Lock()
	if p.failed != v {
		p.failed = v
		p.c.notifyLocked()
	}
	p.c.mu.Unlock()
}

func (p *peerSub) setSynced(patterns map[string]bool, v bool) {
	p.c.mu.Lock()
	for pat := range patterns {
		if v {
			p.synced[pat] = true
		} else {
			delete(p.synced, pat)
		}
	}
	p.c.notifyLocked()
	p.c.mu.Unlock()
}

func (p *peerSub) run() {
	c := p.c
	var sub Sub
	applied := map[string]bool{}
	appliedPush := false
	retry := c.opts.RetryMin
	var retryTimer <-chan time.Time
	var lost chan struct{}
	closeSub := func() {
		if sub != nil {
			sub.Close()
			sub = nil
		}
		p.setSynced(applied, false)
		applied = map[string]bool{}
		lost = nil
		p.setFailed(true)
	}
	defer closeSub()

	// drain pulls every queued message; lostSeen asks for a resync.
	drain := func() (lostSeen bool, err error) {
		for {
			msgs, more, l, err := sub.BulkGet(c.ctx, sfcp.BulkGetOptions{})
			if err != nil {
				return false, err
			}
			c.receive(p.id, msgs)
			lostSeen = lostSeen || l
			if !more {
				return lostSeen, nil
			}
		}
	}
	startRead := func() {
		if appliedPush && lost == nil {
			lost = make(chan struct{}, 1)
			go p.read(sub, lost)
		}
	}
	// settle finishes a change: pull takes what the publisher queued,
	// including what its interest callback published before answering.
	settle := func(added map[string]bool) (bool, error) {
		resync := false
		if !appliedPush {
			var err error
			if resync, err = drain(); err != nil {
				return false, err
			}
		}
		p.setSynced(added, true)
		return resync, nil
	}
	// resubscribe removes and adds every pattern again, so publishers
	// publish current values again after a lost mark.
	resubscribe := func() error {
		p.setSynced(applied, false)
		list := keys(applied)
		if _, err := sub.Change(c.ctx, nil, list, appliedPush); err != nil {
			return err
		}
		if _, err := sub.Change(c.ctx, list, nil, appliedPush); err != nil {
			return err
		}
		_, err := settle(applied)
		return err
	}

	for {
		c.mu.Lock()
		gone := p.gone || c.ctx.Err() != nil
		want, push := c.desiredLocked()
		up := p.up
		p.up = false
		c.mu.Unlock()
		if gone {
			return
		}
		if up {
			retryTimer = nil
		}

		var err error
		resync := false
		switch {
		case len(want) == 0:
			if sub != nil {
				closeSub()
			}
		case sub == nil:
			if retryTimer != nil {
				break
			}
			var s Sub
			if s, _, err = c.dial(c.ctx, p.id, sfcp.SubscribeOptions{Patterns: keys(want), Push: push}); err == nil {
				sub, applied, appliedPush = s, want, push
				startRead()
				resync, err = settle(applied)
			}
		default:
			var add, remove []string
			for pat := range want {
				if !applied[pat] {
					add = append(add, pat)
				}
			}
			for pat := range applied {
				if !want[pat] {
					remove = append(remove, pat)
				}
			}
			if len(add) == 0 && len(remove) == 0 && push == appliedPush {
				break
			}
			if _, err = sub.Change(c.ctx, add, remove, push); err == nil {
				p.setSynced(sliceSet(remove), false)
				applied, appliedPush = want, push
				startRead()
				resync, err = settle(sliceSet(add))
			}
		}
		if err == nil && resync {
			err = resubscribe()
		}
		if err != nil {
			closeSub()
			if c.ctx.Err() != nil {
				return
			}
			retryTimer = time.After(retry)
			retry = min(retry*2, c.opts.RetryMax)
			p.setFailed(true)
		} else if sub != nil {
			retry = c.opts.RetryMin
			p.setFailed(false)
		}

		var available, done <-chan struct{}
		if sub != nil {
			done = sub.Done()
			if !appliedPush {
				available = sub.Available()
			}
		}
		select {
		case <-p.wake:
		case <-retryTimer:
			retryTimer = nil
		case <-done:
			// The stream ended (session gone); dial again after a pause.
			closeSub()
			retryTimer = time.After(retry)
		case <-lost:
			if err := resubscribe(); err != nil {
				closeSub()
				retryTimer = time.After(retry)
			}
		case <-available:
			l, err := drain()
			if err == nil && l {
				err = resubscribe()
			}
			if err != nil {
				closeSub()
				retryTimer = time.After(retry)
			}
		case <-c.ctx.Done():
			return
		}
	}
}

// read moves pushed messages into the cache and reports lost marks.
func (p *peerSub) read(sub Sub, lost chan<- struct{}) {
	for {
		msgs, l, err := sub.Next(p.c.ctx, 0)
		if err != nil {
			return
		}
		p.c.receive(p.id, msgs)
		if l {
			select {
			case lost <- struct{}{}:
			default:
			}
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sliceSet(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, s := range list {
		out[s] = true
	}
	return out
}
