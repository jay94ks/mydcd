// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/quic-go/quic-go"
)

// Topic is the subscribe/publish channel between members
// (devel/design/sfcp-topics.md, topic names devel/design/sfcp-topic-space.md).
//
// A subscriber opens one long-lived stream to a publisher; the stream is the
// subscription. By default the publisher keeps the subscriber's messages in a
// queue, says once that some are Available, and the subscriber takes them
// with BulkGet; a push subscription is sent each message at once. Messages are
// never merged or split, their order is not kept, every one has a TTL of at
// most five minutes, and only must-deliver messages are held until the
// subscriber's BulkAck. Nothing here polls: work happens when a message is
// published, a frame arrives or a deadline timer fires.
const Topic Purpose = 26

// Topic kinds beyond the common ones (KindRequest: subscription change,
// KindResponse: its results, KindStored: BulkAck).
const (
	KindTopicMessages  uint8 = KindOwn     // a batch of messages
	KindTopicLost      uint8 = KindOwn + 1 // best-effort messages were dropped (push)
	KindTopicBulkGet   uint8 = KindOwn + 2 // take queued messages
	KindTopicBulkEnd   uint8 = KindOwn + 3 // end of one BulkGet reply
	KindTopicAvailable uint8 = KindOwn + 4 // the queue went from empty to non-empty (pull)
)

// topicLoadBytes is the publisher memory (queued plus held messages) past
// which idle subscriptions are shed; there is no stream limit. A variable
// only so tests can lower it.
var topicLoadBytes = 64 << 20

// Limits (design 3-7).
const (
	TopicMaxTTL         = 5 * time.Minute
	TopicMaxData        = 60 << 10
	topicFrameBudget    = 64 << 10
	topicQueueBytes     = 256 << 10
	topicMaxPatterns    = 256
	topicHeldPerPeer    = 256
	topicHeldBytes      = 1 << 20
	topicBulkMax        = 4096
	topicBulkBytes      = 4 << 20
	topicPullRequeue    = 30 * time.Second
	topicPushRetryFirst = time.Second
	topicPushRetryLast  = 30 * time.Second
	// TopicMaxBytes bounds a topic or pattern. Shorter is better (Jay
	// 10:03 KST): 4K is a ceiling, not a target.
	TopicMaxBytes = 4096
	// topicAckedMax bounds the receiver's memory of acknowledged keys.
	topicAckedMax = 65536
)

// Message flags on the wire.
const (
	topicBinary      = 1 << 0
	topicMustDeliver = 1 << 1
	topicReplace     = 1 << 2
)

// Subscription change flags.
const topicPush = 1 << 0

// Per-pattern subscription results.
const (
	TopicAccepted uint8 = iota
	TopicDenied
	TopicOverLimit
	TopicInvalid
)

var (
	// ErrTopicSlot: the family has no slot in the reservation table, or its
	// slot already has an ACL.
	ErrTopicSlot = errors.New("SFCP topic family has no free reservation slot")
	// ErrTopic: an invalid topic, pattern or publish option.
	ErrTopic = errors.New("invalid SFCP topic")
	// ErrBackpressure: a subscriber already holds too many must-deliver
	// messages; the message was not queued for it.
	ErrBackpressure = errors.New("SFCP topic subscriber is over its must-deliver limit")
	// ErrTopicGone: PublishTo's subscription has ended or no longer
	// matches the topic.
	ErrTopicGone = errors.New("SFCP topic subscription is gone")
)

// topicSlot is one row of the reservation table. A family must have a slot
// before any code may attach an ACL to it (design 4).
type topicSlot struct {
	owner, doc string
}

// topicSlots is the reservation table (devel/design/sfcp-topic-space.md 2).
// Tests add "t…" families from _test.go only.
var topicSlots = map[string]topicSlot{
	TopicFamilyObservation: {"node observation (R18)", "devel/design/sfcp-topic-space.md"},
	TopicFamilyAlarm:       {"node alarms (SFCP)", "devel/design/sfcp-topic-space.md"},
	TopicFamilyTransit:     {"transit load, 0.1.1 (SFCP)", "devel/design/sfcp-transit.md"},
	TopicFamilyEngine:      {"engine events, reserved; use decided by implementation (R18)", "devel/design/sfcp-topic-space.md"},
	TopicFamilyWorkload:    {"workload reports, reserved; use decided by implementation (R18)", "devel/design/sfcp-topic-space.md"},
}

// Per-part abbreviation tables (devel/design/sfcp-topic-space.md 3). Code
// takes abbreviations from these and never spells them itself.
const (
	TopicFamilyObservation = "obs"
	TopicFamilyAlarm       = "alm"
	TopicFamilyTransit     = "tr"
	TopicFamilyEngine      = "eng"
	TopicFamilyWorkload    = "wl"
)

// TopicObservationSource maps an observability report source kind to its
// T-obs-src abbreviation.
var TopicObservationSource = map[string]string{
	"host":          "host",
	"devices":       "dev",
	"disk":          "dsk",
	"usage":         "use",
	"link":          "lnk",
	"consensus":     "cns",
	"volume":        "vol",
	"task":          "tsk",
	"registry-pull": "rpl",
	"rxtx":          "rxtx",
}

// TopicObservationDisk is T-obs-dsk.
var TopicObservationDisk = map[string]string{
	"system":            "sys",
	"container-runtime": "crt",
	"root":              "rt",
}

// TopicTransitKind is T-tr-kind; TopicEngineObject is T-eng-obj.
var (
	TopicTransitKind  = map[string]string{"load": "ld"}
	TopicEngineObject = map[string]string{"container": "ct", "node": "nd"}
)

// GoneReason says why a subscriber went away.
type GoneReason uint8

const (
	GoneUnsubscribed GoneReason = iota + 1 // patterns removed or the stream closed cleanly
	GoneRemoved                            // no longer a cluster member
	GoneLost                               // the session broke; it may come back
	GoneShed                               // this publisher closed it under load
)

func (r GoneReason) String() string {
	switch r {
	case GoneUnsubscribed:
		return "unsubscribed"
	case GoneRemoved:
		return "removed"
	case GoneLost:
		return "lost"
	case GoneShed:
		return "shed"
	}
	return "unknown"
}

// Gone is what a publisher learns when a subscriber goes away: who, why and
// which patterns that connection had. No message list (Jay 09:56 KST).
type Gone struct {
	Peer     Identity
	PeerID   string
	Reason   GoneReason
	Patterns []string
}

// GoneAction is the publisher's choice for the subscriber's must-deliver
// messages.
type GoneAction uint8

const (
	// Keep holds them until their TTL; a returning subscriber gets them.
	Keep GoneAction = iota + 1
	// Drop forgets them now without Undelivered.
	Drop
)

// TopicACL is a family's rules, hard-coded by the feature that reserved its
// slot (design 4).
type TopicACL struct {
	// Publish reports whether peer may publish topic; the receiver checks
	// every message. Nil admits only topics whose second segment is the
	// sending peer's ID.
	Publish func(peer Peer, topic string) bool
	// Subscribe reports whether peer may subscribe pattern. Nil admits
	// cluster members.
	Subscribe func(peer Peer, pattern string) bool
	// TTL is the default message TTL; zero means TopicMaxTTL.
	TTL time.Duration
	// MustDeliver allows the must-deliver flag in this family.
	MustDeliver bool
	// Undelivered is told about a must-deliver message whose TTL ended
	// before the subscriber acknowledged it.
	Undelivered func(peer Identity, topic string, seq uint64)
	// SubscriberGone chooses Keep or Drop for a vanished subscriber's
	// must-deliver messages. Nil means Drop, except Keep for GoneLost
	// (GoneShed drops too, which frees the load that caused it).
	SubscriberGone func(Gone) GoneAction
}

// Message is one received message.
type Message struct {
	Publisher   Identity
	PublisherID string
	Topic       string
	Binary      bool
	MustDeliver bool
	Replace     bool
	Seq         uint64
	Expires     time.Time
	Data        []byte
}

// PublishOptions are a message's flags. TTL zero is the family default.
type PublishOptions struct {
	Binary, MustDeliver, Replace bool
	TTL                          time.Duration
}

// Interest is a subscription appearing or going away on this publisher.
type Interest struct {
	Peer    Identity
	PeerID  string
	Pattern string
	Added   bool

	st *topicStream // the subscription stream, for PublishTo
}

// Topics is one node's side of the channel: the families this build serves,
// the subscribers of this node's messages, and the messages it holds for
// them.
type Topics struct {
	t *Transport

	mu       sync.Mutex
	acls     map[string]*TopicACL
	streams  map[*topicStream]struct{}
	seq      map[string]uint64
	held     map[Identity]*heldPeer
	interest []func(Interest)
	acked    map[topicAckKey]time.Time // receiver side: must-deliver already acknowledged
	// queueBytes and heldBytes are this node's publisher memory, the load
	// that sheds idle subscriptions (design 3-7).
	queueBytes, heldBytes int
	now                   func() time.Time
	after                 func(time.Duration, func()) topicTimer
}

type topicTimer interface{ Stop() bool }

// NewTopics attaches the channel to t. Call it once per transport, before
// Listen.
func NewTopics(t *Transport) (*Topics, error) {
	h := &Topics{
		t:       t,
		acls:    map[string]*TopicACL{},
		streams: map[*topicStream]struct{}{},
		seq:     map[string]uint64{},
		held:    map[Identity]*heldPeer{},
		acked:   map[topicAckKey]time.Time{},
		now:     time.Now,
		after:   func(d time.Duration, f func()) topicTimer { return time.AfterFunc(d, f) },
	}
	if err := t.On(Topic, h.serve); err != nil {
		return nil, err
	}
	return h, nil
}

// ReserveTopic attaches the ACL of a family that has a slot in the
// reservation table. A family without a slot, or a second ACL for one slot,
// is refused; sfcd stops on that error.
func (h *Topics) ReserveTopic(family string, acl TopicACL) error {
	if _, ok := topicSlots[family]; !ok {
		return ErrTopicSlot
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.acls[family] != nil {
		return ErrTopicSlot
	}
	if acl.TTL <= 0 || acl.TTL > TopicMaxTTL {
		acl.TTL = TopicMaxTTL
	}
	h.acls[family] = &acl
	return nil
}

// OnInterest adds a callback for subscriptions appearing and going away.
// Features publish current values when an interest is added (no retained
// values, design 3-3).
func (h *Topics) OnInterest(f func(Interest)) {
	h.mu.Lock()
	h.interest = append(h.interest, f)
	h.mu.Unlock()
}

// HasInterest reports whether some subscription matches topic.
func (h *Topics) HasInterest(topic string) bool {
	segs, ok := splitTopic(topic, false)
	if !ok {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for st := range h.streams {
		if st.matches(segs) {
			return true
		}
	}
	return false
}

// TopicName joins segments into a topic with TopicSegment (topic-space 1).
func TopicName(segments ...string) string {
	out := make([]string, len(segments))
	for i, s := range segments {
		out[i] = TopicSegment(s)
	}
	return strings.Join(out, "/")
}

// TopicSegment turns a human-given value into a segment: upper case becomes
// lower case, and a value that still cannot be a segment (other characters,
// or longer than 64 bytes) becomes x + 8 hex digits of its xxHash32 (seed 0).
// A key that is already a hash, such as 64 hex digits of a SHA-256, goes in
// as it is. Two values may share a segment; receivers trust the message
// body, not the topic.
func TopicSegment(v string) string {
	l := strings.ToLower(v)
	if validSegment(l) {
		return l
	}
	return fmt.Sprintf("x%08x", xxhash32([]byte(v)))
}

// xxhash32 is XXH32 with seed 0.
func xxhash32(b []byte) uint32 {
	const (
		p1 uint32 = 2654435761
		p2 uint32 = 2246822519
		p3 uint32 = 3266489917
		p4 uint32 = 668265263
		p5 uint32 = 374761393
	)
	rotl := func(x uint32, r uint) uint32 { return x<<r | x>>(32-r) }
	le := func(b []byte) uint32 { return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24 }
	n := len(b)
	var h uint32
	if n >= 16 {
		v1, v2, v3, v4 := uint32(p1), uint32(p2), uint32(0), uint32(0)
		v1 += p2
		v4 -= p1
		round := func(v, in uint32) uint32 { return rotl(v+in*p2, 13) * p1 }
		for len(b) >= 16 {
			v1 = round(v1, le(b[0:]))
			v2 = round(v2, le(b[4:]))
			v3 = round(v3, le(b[8:]))
			v4 = round(v4, le(b[12:]))
			b = b[16:]
		}
		h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)
	} else {
		h = p5
	}
	h += uint32(n)
	for len(b) >= 4 {
		h = rotl(h+le(b)*p3, 17) * p4
		b = b[4:]
	}
	for _, c := range b {
		h = rotl(h+uint32(c)*p5, 11) * p1
	}
	h ^= h >> 15
	h *= p2
	h ^= h >> 13
	h *= p3
	h ^= h >> 16
	return h
}

// ---- names ----

func validSegment(s string) bool {
	if s == "" || len(s) > TopicMaxBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// splitTopic checks a topic (pattern false) or a pattern (pattern true).
func splitTopic(s string, pattern bool) ([]string, bool) {
	if s == "" || len(s) > TopicMaxBytes {
		return nil, false
	}
	segs := strings.Split(s, "/")
	for i, seg := range segs {
		switch {
		case pattern && i > 0 && seg == "+":
		case pattern && i > 0 && i == len(segs)-1 && seg == "#":
		case validSegment(seg):
		default:
			return nil, false
		}
	}
	return segs, true
}

func matchTopic(pattern, topic []string) bool {
	for i, p := range pattern {
		if p == "#" {
			return true
		}
		if i >= len(topic) || p != "+" && p != topic[i] {
			return false
		}
	}
	return len(pattern) == len(topic)
}

// ---- wire ----

// patternsFit reports whether a pattern list fits one frame with room for
// the fixed header of its kind.
func patternsFit(list []string) bool {
	size := 16
	for _, p := range list {
		size += 2 + len(p)
	}
	return size <= topicFrameBudget
}

func appendStrings(b []byte, list []string) []byte {
	b = binary.LittleEndian.AppendUint16(b, uint16(len(list)))
	for _, s := range list {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(s)))
		b = append(b, s...)
	}
	return b
}

func readStrings(b []byte) ([]string, []byte, bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(binary.LittleEndian.Uint16(b))
	b = b[2:]
	out := make([]string, 0, n)
	for range n {
		if len(b) < 2 {
			return nil, nil, false
		}
		l := int(binary.LittleEndian.Uint16(b))
		if l > len(b)-2 {
			return nil, nil, false
		}
		out, b = append(out, string(b[2:2+l])), b[2+l:]
	}
	return out, b, true
}

type topicChange struct {
	flags       uint8
	add, remove []string
}

func encodeChange(c topicChange) []byte {
	b := []byte{c.flags}
	b = appendStrings(b, c.add)
	return appendStrings(b, c.remove)
}

func decodeChange(b []byte) (topicChange, bool) {
	if len(b) < 1 {
		return topicChange{}, false
	}
	c := topicChange{flags: b[0]}
	var ok bool
	if c.add, b, ok = readStrings(b[1:]); !ok {
		return c, false
	}
	if c.remove, b, ok = readStrings(b); !ok || len(b) != 0 || len(c.add)+len(c.remove) > topicMaxPatterns {
		return c, false
	}
	return c, true
}

// outMsg is one published message as the publisher keeps it.
type outMsg struct {
	topic   string
	family  string
	flags   uint8
	seq     uint64
	expires time.Time
	data    []byte
}

func (m *outMsg) size() int { return 19 + len(m.topic) + len(m.data) }

func appendMessage(b []byte, m *outMsg, now time.Time) []byte {
	ttl := m.expires.Sub(now).Milliseconds()
	if ttl < 1 {
		ttl = 1
	}
	b = binary.LittleEndian.AppendUint32(b, uint32(m.size()-4))
	b = append(b, m.flags)
	b = binary.LittleEndian.AppendUint64(b, m.seq)
	b = binary.LittleEndian.AppendUint32(b, uint32(ttl))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(m.topic)))
	b = append(b, m.topic...)
	return append(b, m.data...)
}

type inMsg struct {
	flags uint8
	seq   uint64
	ttl   time.Duration
	topic string
	data  []byte
}

func decodeMessages(b []byte) ([]inMsg, bool) {
	var out []inMsg
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, false
		}
		n := int(binary.LittleEndian.Uint32(b))
		if n < 15 || n > len(b)-4 {
			return nil, false
		}
		m, rest := b[4:4+n], b[4+n:]
		tl := int(binary.LittleEndian.Uint16(m[13:15]))
		if 15+tl > len(m) {
			return nil, false
		}
		ttl := binary.LittleEndian.Uint32(m[9:13])
		out = append(out, inMsg{
			flags: m[0],
			seq:   binary.LittleEndian.Uint64(m[1:9]),
			ttl:   time.Duration(ttl) * time.Millisecond,
			topic: string(m[15 : 15+tl]),
			data:  append([]byte(nil), m[15+tl:]...),
		})
		b = rest
	}
	return out, len(out) > 0
}

type topicAckKey struct {
	pub   Identity
	topic string
	seq   uint64
}

func encodeAcks(keys []topicAckKey) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(keys)))
	for _, k := range keys {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(k.topic)))
		b = append(b, k.topic...)
		b = binary.LittleEndian.AppendUint64(b, k.seq)
	}
	return b
}

func decodeAcks(b []byte) ([]topicAckKey, bool) {
	if len(b) < 2 {
		return nil, false
	}
	n := int(binary.LittleEndian.Uint16(b))
	b = b[2:]
	out := make([]topicAckKey, 0, n)
	for range n {
		if len(b) < 2 {
			return nil, false
		}
		l := int(binary.LittleEndian.Uint16(b))
		if l+8 > len(b)-2 {
			return nil, false
		}
		out = append(out, topicAckKey{topic: string(b[2 : 2+l]), seq: binary.LittleEndian.Uint64(b[2+l : 10+l])})
		b = b[10+l:]
	}
	return out, len(b) == 0
}

func topicFrame(kind uint8, request uint64, body []byte) Frame {
	return Frame{Purpose: Topic, Kind: kind, Request: request, Fields: []Field{{Tag: 1, Required: true, Value: body}}}
}

func topicBody(f Frame) []byte {
	if len(f.Fields) == 0 {
		return nil
	}
	return f.Fields[0].Value
}

// ---- publisher ----

// heldPeer is the must-deliver messages held for one subscriber key.
type heldPeer struct {
	msgs  map[topicAckKey]*heldMsg
	bytes int
}

type heldMsg struct {
	m       *outMsg
	queued  *topicStream // the stream whose queue has it, or nil
	handed  bool         // given to the subscriber, waiting for BulkAck
	retry   topicTimer
	backoff time.Duration
	expiry  topicTimer
}

// Publish sends a message to every subscription that matches topic. With
// MustDeliver it is held per subscriber until BulkAck or its TTL; a
// subscriber over its limit does not get it and Publish returns
// ErrBackpressure (the others still do).
func (h *Topics) Publish(topic string, data []byte, o PublishOptions) error {
	return h.publish(nil, topic, data, o)
}

// PublishTo sends a message only to the subscription of in, typically from
// an OnInterest callback handing a new subscriber the current value so the
// subscribers that already have it do not get it again. Called from the
// callback of an added interest, the message is queued before the kind 2
// reply, like Publish. It returns ErrTopicGone when that subscription has
// ended or none of its patterns match topic.
func (h *Topics) PublishTo(in Interest, topic string, data []byte, o PublishOptions) error {
	if in.st == nil {
		return ErrTopicGone
	}
	return h.publish(in.st, topic, data, o)
}

// publish builds one message and delivers it to only (nil: every matching
// subscription, once per subscriber key).
func (h *Topics) publish(only *topicStream, topic string, data []byte, o PublishOptions) error {
	segs, ok := splitTopic(topic, false)
	if !ok || len(data) > TopicMaxData {
		return ErrTopic
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	acl := h.acls[segs[0]]
	if acl == nil || o.MustDeliver && !acl.MustDeliver || o.TTL < 0 || o.TTL > TopicMaxTTL {
		return ErrTopic
	}
	if !o.Binary && !utf8.Valid(data) {
		return ErrTopic
	}
	if only != nil {
		if _, live := h.streams[only]; !live || only.closed || only.shed || !only.matches(segs) {
			return ErrTopicGone
		}
	}
	ttl := o.TTL
	if ttl == 0 {
		ttl = acl.TTL
	}
	now := h.now()
	seq := h.seq[topic]
	if seq == 0 {
		// Start from the clock so a restarted publisher never reuses a
		// sequence a receiver still remembers.
		seq = uint64(now.UnixNano())
	}
	seq++
	h.seq[topic] = seq
	m := &outMsg{topic: topic, family: segs[0], seq: seq, expires: now.Add(ttl), data: append([]byte(nil), data...)}
	if o.Binary {
		m.flags |= topicBinary
	}
	if o.MustDeliver {
		m.flags |= topicMustDeliver
	}
	if o.Replace {
		m.flags |= topicReplace
	}
	var err error
	deliver := func(st *topicStream) {
		if o.MustDeliver {
			if !h.holdLocked(st, m) {
				err = ErrBackpressure
			}
			return
		}
		st.enqueueLocked(m, nil)
	}
	if only != nil {
		deliver(only)
	} else {
		seen := map[Identity]bool{}
		for st := range h.streams {
			if seen[st.peer.Key] || !st.matches(segs) {
				continue
			}
			seen[st.peer.Key] = true
			deliver(st)
		}
	}
	h.shedLocked()
	return err
}

// holdLocked starts holding a must-deliver message for st's peer and queues it.
func (h *Topics) holdLocked(st *topicStream, m *outMsg) bool {
	hp := h.held[st.peer.Key]
	if hp == nil {
		hp = &heldPeer{msgs: map[topicAckKey]*heldMsg{}}
		h.held[st.peer.Key] = hp
	}
	if m.flags&topicReplace != 0 {
		for k, old := range hp.msgs {
			if k.topic == m.topic && !old.handed {
				h.forgetLocked(st.peer.Key, k, old)
			}
		}
	}
	if len(hp.msgs) >= topicHeldPerPeer || hp.bytes+m.size() > topicHeldBytes {
		return false
	}
	key := topicAckKey{st.peer.Key, m.topic, m.seq}
	hm := &heldMsg{m: m, backoff: topicPushRetryFirst}
	hp.msgs[key] = hm
	hp.bytes += m.size()
	h.heldBytes += m.size()
	peer := st.peer.Key
	hm.expiry = h.after(m.expires.Sub(h.now()), func() { h.expire(peer, key) })
	st.enqueueLocked(m, hm)
	return true
}

func (h *Topics) forgetLocked(peer Identity, key topicAckKey, hm *heldMsg) {
	hp := h.held[peer]
	if hp == nil || hp.msgs[key] != hm {
		return
	}
	delete(hp.msgs, key)
	hp.bytes -= hm.m.size()
	h.heldBytes -= hm.m.size()
	if hm.retry != nil {
		hm.retry.Stop()
	}
	if hm.expiry != nil {
		hm.expiry.Stop()
	}
	if hm.queued != nil {
		hm.queued.unqueueLocked(hm)
	}
	if len(hp.msgs) == 0 {
		delete(h.held, peer)
	}
}

func (h *Topics) expire(peer Identity, key topicAckKey) {
	h.mu.Lock()
	hp := h.held[peer]
	var hm *heldMsg
	if hp != nil {
		hm = hp.msgs[key]
	}
	var undelivered func(Identity, string, uint64)
	if hm != nil {
		h.forgetLocked(peer, key, hm)
		if acl := h.acls[hm.m.family]; acl != nil {
			undelivered = acl.Undelivered
		}
	}
	h.mu.Unlock()
	if undelivered != nil {
		undelivered(peer, key.topic, key.seq)
	}
}

// requeue puts a handed but unacknowledged message back for its subscriber.
func (h *Topics) requeue(peer Identity, key topicAckKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hp := h.held[peer]
	if hp == nil {
		return
	}
	hm := hp.msgs[key]
	if hm == nil || !hm.handed {
		return
	}
	hm.handed = false
	h.placeLocked(peer, key, hm)
}

// placeLocked queues an idle held message on a matching stream of its peer.
func (h *Topics) placeLocked(peer Identity, key topicAckKey, hm *heldMsg) {
	segs, _ := splitTopic(key.topic, false)
	for st := range h.streams {
		if st.peer.Key == peer && st.matches(segs) {
			st.enqueueLocked(hm.m, hm)
			return
		}
	}
}

func (h *Topics) ack(peer Identity, keys []topicAckKey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	hp := h.held[peer]
	if hp == nil {
		return
	}
	for _, k := range keys {
		k.pub = peer
		if hm := hp.msgs[k]; hm != nil {
			h.forgetLocked(peer, k, hm)
		}
		if hp = h.held[peer]; hp == nil {
			return
		}
	}
}

// topicStream is one subscription stream served by this node.
type topicStream struct {
	h       *Topics
	sess    *Session
	peer    Peer
	stream  *quic.Stream
	request uint64

	// guarded by h.mu
	push      bool
	patterns  [][]string
	raw       []string
	queue     []*queued
	bytes     int
	lost      bool
	available bool
	ctrl      []Frame
	closed    bool
	shed      bool      // closed by load shedding
	active    time.Time // last time the subscriber changed or took messages

	wake chan struct{}
}

type queued struct {
	m  *outMsg
	hm *heldMsg // nil for best-effort
}

func (st *topicStream) matches(topic []string) bool {
	for _, p := range st.patterns {
		if matchTopic(p, topic) {
			return true
		}
	}
	return false
}

func (st *topicStream) grow(d int) {
	st.bytes += d
	st.h.queueBytes += d
}

// shedLocked runs when the publisher's memory passes topicLoadBytes: it
// closes the subscriptions that went longest without taking anything,
// among those holding memory, until the load is back under three quarters
// (Jay 10:27 KST: no stream limit, clean up under load). There is no
// timer; only the publish that crossed the line pays for it.
func (h *Topics) shedLocked() {
	load := h.queueBytes + h.heldBytes
	if load <= topicLoadBytes {
		return
	}
	var victims []*topicStream
	for st := range h.streams {
		if !st.shed && (st.bytes > 0 || h.held[st.peer.Key] != nil) {
			victims = append(victims, st)
		}
	}
	sort.Slice(victims, func(i, j int) bool { return victims[i].active.Before(victims[j].active) })
	counted := map[Identity]bool{}
	for _, st := range victims {
		if load <= topicLoadBytes*3/4 {
			return
		}
		st.shed = true
		load -= st.bytes
		for _, q := range st.queue {
			if q.hm != nil {
				q.hm.queued = nil
			}
		}
		clear(st.queue)
		st.queue = nil
		st.grow(-st.bytes)
		// Held messages are freed when the stream ends and the family
		// chooses (default Drop for GoneShed); count them as going now.
		if hp := h.held[st.peer.Key]; hp != nil && !counted[st.peer.Key] {
			counted[st.peer.Key] = true
			load -= hp.bytes
		}
		st.stream.CancelRead(0)
		st.stream.CancelWrite(0)
	}
}

func (st *topicStream) signal() {
	select {
	case st.wake <- struct{}{}:
	default:
	}
}

// enqueueLocked adds m (hm for must-deliver) to the stream's queue.
func (st *topicStream) enqueueLocked(m *outMsg, hm *heldMsg) {
	if st.closed {
		return
	}
	if m.flags&topicReplace != 0 {
		for i, q := range st.queue {
			if q.m.topic == m.topic {
				if q.hm != nil {
					if q.hm == hm {
						return
					}
					continue // a held message is replaced by holdLocked
				}
				st.grow(m.size() - q.m.size())
				st.queue[i] = &queued{m: m, hm: hm}
				if hm != nil {
					hm.queued = st
				}
				st.notifyLocked()
				return
			}
		}
	}
	if hm == nil && st.bytes+m.size() > topicQueueBytes {
		st.dropBestEffortLocked()
	}
	st.queue = append(st.queue, &queued{m: m, hm: hm})
	st.grow(m.size())
	if hm != nil {
		hm.queued = st
	}
	st.notifyLocked()
}

func (st *topicStream) dropBestEffortLocked() {
	kept := st.queue[:0]
	st.grow(-st.bytes)
	for _, q := range st.queue {
		if q.hm != nil {
			kept = append(kept, q)
			st.grow(q.m.size())
		}
	}
	clear(st.queue[len(kept):])
	st.queue, st.lost = kept, true
}

func (st *topicStream) unqueueLocked(hm *heldMsg) {
	for i, q := range st.queue {
		if q.hm == hm {
			st.grow(-q.m.size())
			st.queue = append(st.queue[:i], st.queue[i+1:]...)
			break
		}
	}
	hm.queued = nil
}

// notifyLocked wakes the writer (push) or sends Available once (pull).
func (st *topicStream) notifyLocked() {
	if st.push {
		st.signal()
		return
	}
	if !st.available {
		st.available = true
		b := binary.LittleEndian.AppendUint32(nil, uint32(len(st.queue)))
		b = binary.LittleEndian.AppendUint32(b, uint32(st.bytes))
		st.ctrl = append(st.ctrl, topicFrame(KindTopicAvailable, st.request, b))
		st.signal()
	}
}

// takeLocked removes up to max messages (maxBytes) matching patterns
// (nil: all) from the queue. Expired ones are dropped on the way.
func (st *topicStream) takeLocked(patterns [][]string, max, maxBytes int, now time.Time) []*queued {
	var out []*queued
	kept := st.queue[:0]
	size := 0
	for _, q := range st.queue {
		if !q.m.expires.After(now) {
			st.grow(-q.m.size())
			if q.hm != nil {
				q.hm.queued = nil
			}
			continue
		}
		if len(out) >= max || size+q.m.size() > maxBytes || !matchAny(patterns, q.m.topic) {
			kept = append(kept, q)
			continue
		}
		out = append(out, q)
		size += q.m.size()
		st.grow(-q.m.size())
		if q.hm != nil {
			q.hm.queued = nil
		}
	}
	clear(st.queue[len(kept):])
	st.queue = kept
	if len(out) > 0 {
		st.active = now
	}
	return out
}

func matchAny(patterns [][]string, topic string) bool {
	if patterns == nil {
		return true
	}
	segs, _ := splitTopic(topic, false)
	for _, p := range patterns {
		if matchTopic(p, segs) {
			return true
		}
	}
	return false
}

// handLocked marks held messages as handed and starts their redelivery timer.
func (st *topicStream) handLocked(items []*queued) {
	for _, q := range items {
		hm := q.hm
		if hm == nil {
			continue
		}
		hm.handed = true
		wait := topicPullRequeue
		if st.push {
			wait = hm.backoff
			hm.backoff = min(hm.backoff*2, topicPushRetryLast)
		}
		if hm.retry != nil {
			hm.retry.Stop()
		}
		peer, key := st.peer.Key, topicAckKey{st.peer.Key, hm.m.topic, hm.m.seq}
		hm.retry = st.h.after(wait, func() { st.h.requeue(peer, key) })
	}
}

// messageFrames packs messages into frames of at most the frame budget.
func messageFrames(items []*queued, request uint64, now time.Time, bulk bool) []Frame {
	var frames []Frame
	var body []byte
	flush := func() {
		if len(body) == 0 {
			return
		}
		f := topicFrame(KindTopicMessages, request, body)
		if bulk {
			f.Fields = append(f.Fields, Field{Tag: 128, Value: []byte{1}})
		}
		frames, body = append(frames, f), nil
	}
	for _, q := range items {
		if len(body)+q.m.size() > topicFrameBudget {
			flush()
		}
		body = appendMessage(body, q.m, now)
	}
	flush()
	return frames
}

// serve is the publisher side of one subscription stream.
func (h *Topics) serve(ctx context.Context, s *Session, stream *quic.Stream, first Frame) error {
	if first.Kind != KindRequest {
		return ErrFrame
	}
	_ = stream.SetDeadline(time.Time{})
	peer, ok := h.t.lookupFor(s.peer.Key, Topic)
	if !ok {
		return ErrAdmission
	}
	st := &topicStream{h: h, sess: s, peer: peer, stream: stream, request: first.Request, wake: make(chan struct{}, 1), active: h.now()}
	h.mu.Lock()
	h.streams[st] = struct{}{}
	h.mu.Unlock()
	writerDone := make(chan struct{})
	ctx, cancel := context.WithCancel(ctx)
	go func() { defer close(writerDone); st.write(ctx) }()
	reason := GoneUnsubscribed
	err := st.change(first)
	for err == nil {
		var f Frame
		f, err = ReadFrame(stream, MaxBody)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				reason = GoneLost
			}
			break
		}
		if err = s.Admit(f, Topic, false); err != nil {
			break
		}
		switch f.Kind {
		case KindRequest:
			err = st.change(f)
		case KindTopicBulkGet:
			err = st.bulkGet(f)
		case KindStored:
			keys, ok := decodeAcks(topicBody(f))
			if !ok {
				err = ErrFrame
				break
			}
			h.ack(st.peer.Key, keys)
		default:
			err = ErrFrame
		}
	}
	if p, ok := h.t.lookupFor(s.peer.Key, Topic); !ok || !p.Member {
		reason = GoneRemoved
	}
	h.mu.Lock()
	if st.shed {
		reason = GoneShed
	}
	h.mu.Unlock()
	cancel()
	<-writerDone
	h.closeStream(st, reason)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// change applies a subscription change and answers it.
func (st *topicStream) change(f Frame) error {
	c, ok := decodeChange(topicBody(f))
	if !ok {
		return ErrFrame
	}
	h := st.h
	results := make([]byte, 0, len(c.add))
	var added, removed []string
	h.mu.Lock()
	st.active = h.now()
	st.push = c.flags&topicPush != 0
	for _, raw := range c.remove {
		for i, r := range st.raw {
			if r == raw {
				st.raw = append(st.raw[:i], st.raw[i+1:]...)
				st.patterns = append(st.patterns[:i], st.patterns[i+1:]...)
				removed = append(removed, raw)
				break
			}
		}
	}
	for _, raw := range c.add {
		segs, ok := splitTopic(raw, true)
		var acl *TopicACL
		if ok {
			acl = h.acls[segs[0]]
		}
		switch {
		case !ok:
			results = append(results, TopicInvalid)
		case acl == nil || !st.subscribeAllowed(acl, raw):
			results = append(results, TopicDenied)
		case len(st.raw) >= topicMaxPatterns:
			results = append(results, TopicOverLimit)
		default:
			results = append(results, TopicAccepted)
			dup := false
			for _, r := range st.raw {
				dup = dup || r == raw
			}
			if !dup {
				st.raw, st.patterns = append(st.raw, raw), append(st.patterns, segs)
				added = append(added, raw)
			}
		}
	}
	// Held messages waiting for this subscriber join the new patterns.
	if hp := h.held[st.peer.Key]; hp != nil {
		for k, hm := range hp.msgs {
			if hm.queued == nil && !hm.handed {
				h.placeLocked(st.peer.Key, k, hm)
			}
		}
	}
	if st.push && len(st.queue) > 0 {
		st.available = false
	}
	st.signal()
	listeners := h.interest
	h.mu.Unlock()
	// Interest callbacks run first, so what they publish for the new
	// subscription is in its queue before the kind 2 reply goes out.
	h.tell(listeners, st, added, true)
	h.tell(listeners, st, removed, false)
	reply := binary.LittleEndian.AppendUint16(nil, uint16(len(results)))
	reply = append(reply, results...)
	h.mu.Lock()
	if !st.closed {
		st.ctrl = append(st.ctrl, topicFrame(KindResponse, st.request, reply))
		st.signal()
	}
	h.mu.Unlock()
	return nil
}

func (st *topicStream) subscribeAllowed(acl *TopicACL, pattern string) bool {
	if acl.Subscribe != nil {
		return acl.Subscribe(st.peer, pattern)
	}
	return st.peer.Member
}

func (h *Topics) tell(listeners []func(Interest), st *topicStream, patterns []string, added bool) {
	for _, p := range patterns {
		for _, f := range listeners {
			f(Interest{Peer: st.peer.Key, PeerID: st.peer.ID, Pattern: p, Added: added, st: st})
		}
	}
}

// bulkGet answers one BulkGet with message frames and a BulkEnd.
func (st *topicStream) bulkGet(f Frame) error {
	b := topicBody(f)
	if len(b) < 8 {
		return ErrFrame
	}
	max := min(int(binary.LittleEndian.Uint32(b)), topicBulkMax)
	maxBytes := min(int(binary.LittleEndian.Uint32(b[4:])), topicBulkBytes)
	raw, rest, ok := readStrings(b[8:])
	if !ok || len(rest) != 0 || max <= 0 || maxBytes <= 0 {
		return ErrFrame
	}
	var patterns [][]string
	for _, r := range raw {
		segs, ok := splitTopic(r, true)
		if !ok {
			return ErrFrame
		}
		patterns = append(patterns, segs)
	}
	h := st.h
	h.mu.Lock()
	now := h.now()
	items := st.takeLocked(patterns, max, maxBytes, now)
	st.handLocked(items)
	frames := messageFrames(items, st.request, now, true)
	var flags uint8
	if len(st.queue) > 0 {
		flags |= 1 // more
	}
	if st.lost {
		flags |= 2
		st.lost = false
	}
	if len(st.queue) == 0 {
		st.available = false
	}
	end := binary.LittleEndian.AppendUint32(nil, uint32(len(items)))
	end = append(end, flags)
	st.ctrl = append(st.ctrl, frames...)
	st.ctrl = append(st.ctrl, topicFrame(KindTopicBulkEnd, st.request, end))
	st.signal()
	h.mu.Unlock()
	return nil
}

// write sends control frames and, for push, queued messages, whenever woken.
func (st *topicStream) write(ctx context.Context) {
	h := st.h
	for {
		select {
		case <-ctx.Done():
			return
		case <-st.wake:
		}
		h.mu.Lock()
		frames := st.ctrl
		st.ctrl = nil
		if st.push && (len(st.queue) > 0 || st.lost) {
			now := h.now()
			items := st.takeLocked(nil, len(st.queue), int(^uint(0)>>1), now)
			st.handLocked(items)
			frames = append(frames, messageFrames(items, st.request, now, false)...)
			if st.lost {
				st.lost = false
				frames = append(frames, topicFrame(KindTopicLost, st.request, appendStrings(nil, nil)))
			}
		}
		h.mu.Unlock()
		for _, f := range frames {
			if err := WriteFrame(st.stream, f); err != nil {
				st.stream.CancelRead(0)
				return
			}
		}
	}
}

// closeStream forgets a stream and asks the family what to do with the
// subscriber's held messages.
func (h *Topics) closeStream(st *topicStream, reason GoneReason) {
	h.mu.Lock()
	st.closed = true
	delete(h.streams, st)
	for _, q := range st.queue {
		if q.hm != nil {
			q.hm.queued = nil
		}
	}
	clear(st.queue)
	st.queue = nil
	st.grow(-st.bytes)
	patterns := append([]string(nil), st.raw...)
	listeners := h.interest
	stillThere := false
	for other := range h.streams {
		stillThere = stillThere || other.peer.Key == st.peer.Key
	}
	type choice struct {
		family string
		acl    *TopicACL
	}
	var choices []choice
	if hp := h.held[st.peer.Key]; hp != nil && !stillThere {
		fams := map[string]bool{}
		for _, hm := range hp.msgs {
			fams[hm.m.family] = true
		}
		for f := range fams {
			choices = append(choices, choice{f, h.acls[f]})
		}
	}
	h.mu.Unlock()
	h.tell(listeners, st, patterns, false)
	gone := Gone{Peer: st.peer.Key, PeerID: st.peer.ID, Reason: reason, Patterns: patterns}
	for _, c := range choices {
		action := Drop
		if reason == GoneLost {
			action = Keep
		}
		if c.acl != nil && c.acl.SubscriberGone != nil {
			action = c.acl.SubscriberGone(gone)
		}
		if action != Drop {
			continue
		}
		h.mu.Lock()
		if hp := h.held[st.peer.Key]; hp != nil {
			for k, hm := range hp.msgs {
				if hm.m.family == c.family {
					h.forgetLocked(st.peer.Key, k, hm)
				}
			}
		}
		h.mu.Unlock()
	}
}

// ---- subscriber ----

// SubscribeOptions open a subscription. Push asks for every message at once;
// the default is pull (design 3-10).
type SubscribeOptions struct {
	Patterns []string
	Push     bool
}

// Subscription is one subscription stream to one publisher.
type Subscription struct {
	h       *Topics
	sess    *Session
	stream  *quic.Stream
	request uint64

	wmu     sync.Mutex // frame writes
	cmu     sync.Mutex // one Change or BulkGet at a time
	push    bool
	closing atomic.Bool // Close sent FIN; do not reset the send side

	mu        sync.Mutex
	inbox     []Message
	inboxSize int // bytes of inbox data, at most topicQueueBytes
	lost      bool
	bulk      []Message
	results   chan []uint8
	bulkEnd   chan bulkEnd
	inboxWake chan struct{}
	available chan struct{}
	done      chan struct{}
	err       error
}

type bulkEnd struct {
	count uint32
	more  bool
	lost  bool
}

// Subscribe opens a subscription on s. The results say, per pattern, whether
// the publisher accepted it.
func (h *Topics) Subscribe(ctx context.Context, s *Session, o SubscribeOptions) (*Subscription, []uint8, error) {
	if !s.Supports(Topic, KindRequest) {
		return nil, nil, ErrUnsupported
	}
	if len(o.Patterns) == 0 || len(o.Patterns) > topicMaxPatterns || !patternsFit(o.Patterns) {
		return nil, nil, ErrTopic
	}
	for _, p := range o.Patterns {
		if _, ok := splitTopic(p, true); !ok {
			return nil, nil, ErrTopic
		}
	}
	stream, err := s.Open(ctx)
	if err != nil {
		return nil, nil, err
	}
	sub := &Subscription{
		h: h, sess: s, stream: stream, request: h.t.NextRequest(), push: o.Push,
		results: make(chan []uint8, 1), bulkEnd: make(chan bulkEnd, 1),
		inboxWake: make(chan struct{}, 1), available: make(chan struct{}, 1), done: make(chan struct{}),
	}
	_ = stream.SetDeadline(time.Time{})
	go sub.read()
	results, err := sub.change(ctx, topicChange{flags: sub.flags(), add: o.Patterns})
	if err != nil {
		sub.Close()
		return nil, nil, err
	}
	return sub, results, nil
}

func (sub *Subscription) flags() uint8 {
	if sub.push {
		return topicPush
	}
	return 0
}

func (sub *Subscription) writeFrame(f Frame) error {
	sub.wmu.Lock()
	defer sub.wmu.Unlock()
	return WriteFrame(sub.stream, f)
}

// Change adds and removes patterns and may switch between push and pull.
func (sub *Subscription) Change(ctx context.Context, add, remove []string, push bool) ([]uint8, error) {
	all := append(append([]string(nil), add...), remove...)
	if !patternsFit(all) {
		return nil, ErrTopic
	}
	for _, p := range all {
		if _, ok := splitTopic(p, true); !ok {
			return nil, ErrTopic
		}
	}
	sub.cmu.Lock()
	sub.push = push
	sub.cmu.Unlock()
	return sub.change(ctx, topicChange{flags: sub.flags(), add: add, remove: remove})
}

func (sub *Subscription) change(ctx context.Context, c topicChange) ([]uint8, error) {
	sub.cmu.Lock()
	defer sub.cmu.Unlock()
	if err := sub.writeFrame(topicFrame(KindRequest, sub.request, encodeChange(c))); err != nil {
		return nil, err
	}
	select {
	case r := <-sub.results:
		if len(r) != len(c.add) {
			return nil, ErrFrame
		}
		return r, nil
	case <-sub.done:
		return nil, sub.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// BulkGetOptions bound one BulkGet. Nil Patterns means every pattern of the
// subscription.
type BulkGetOptions struct {
	Patterns      []string
	Max, MaxBytes int
}

// BulkGet takes queued messages from the publisher in one exchange. more
// says some are still queued; lost says best-effort messages were dropped
// since the last BulkGet.
func (sub *Subscription) BulkGet(ctx context.Context, o BulkGetOptions) (msgs []Message, more, lost bool, err error) {
	if o.Max <= 0 {
		o.Max = topicBulkMax
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = topicBulkBytes
	}
	if !patternsFit(o.Patterns) {
		return nil, false, false, ErrTopic
	}
	for _, p := range o.Patterns {
		if _, ok := splitTopic(p, true); !ok {
			return nil, false, false, ErrTopic
		}
	}
	sub.cmu.Lock()
	defer sub.cmu.Unlock()
	b := binary.LittleEndian.AppendUint32(nil, uint32(min(o.Max, topicBulkMax)))
	b = binary.LittleEndian.AppendUint32(b, uint32(min(o.MaxBytes, topicBulkBytes)))
	b = appendStrings(b, o.Patterns)
	if err := sub.writeFrame(topicFrame(KindTopicBulkGet, sub.request, b)); err != nil {
		return nil, false, false, err
	}
	select {
	case end := <-sub.bulkEnd:
		sub.mu.Lock()
		msgs, sub.bulk = sub.bulk, nil
		sub.mu.Unlock()
		return msgs, end.more, end.lost, nil
	case <-sub.done:
		return nil, false, false, sub.Err()
	case <-ctx.Done():
		return nil, false, false, ctx.Err()
	}
}

// BulkAck acknowledges handled must-deliver messages; others are ignored.
func (sub *Subscription) BulkAck(ctx context.Context, msgs ...Message) error {
	var keys []topicAckKey
	for _, m := range msgs {
		if m.MustDeliver {
			keys = append(keys, topicAckKey{m.Publisher, m.Topic, m.Seq})
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sub.h.rememberAcked(keys)
	for len(keys) > 0 {
		n, size := 0, 2
		for n < len(keys) && n < 0xffff && size+10+len(keys[n].topic) <= topicFrameBudget {
			size += 10 + len(keys[n].topic)
			n++
		}
		if err := sub.writeFrame(topicFrame(KindStored, sub.request, encodeAcks(keys[:n]))); err != nil {
			return err
		}
		keys = keys[n:]
	}
	return nil
}

// Available fires when the publisher says messages are queued (pull).
func (sub *Subscription) Available() <-chan struct{} { return sub.available }

// Next waits for pushed messages and returns at most max of them. lost says
// best-effort messages were dropped before them.
func (sub *Subscription) Next(ctx context.Context, max int) (msgs []Message, lost bool, err error) {
	if max <= 0 {
		max = topicBulkMax
	}
	for {
		sub.mu.Lock()
		if len(sub.inbox) > 0 || sub.lost {
			n := min(max, len(sub.inbox))
			msgs = append([]Message(nil), sub.inbox[:n]...)
			for _, m := range msgs {
				sub.inboxSize -= len(m.Data) + len(m.Topic)
			}
			rest := copy(sub.inbox, sub.inbox[n:])
			clear(sub.inbox[rest:])
			sub.inbox = sub.inbox[:rest]
			lost, sub.lost = sub.lost, false
			sub.mu.Unlock()
			return msgs, lost, nil
		}
		sub.mu.Unlock()
		select {
		case <-sub.inboxWake:
		case <-sub.done:
			return nil, false, sub.Err()
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

// Done is closed when the subscription stream ends.
func (sub *Subscription) Done() <-chan struct{} { return sub.done }

// Err is why the subscription ended.
func (sub *Subscription) Err() error {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return sub.err
}

// Close ends the subscription cleanly (the publisher sees unsubscribed).
func (sub *Subscription) Close() {
	sub.closing.Store(true)
	sub.wmu.Lock()
	_ = sub.stream.Close()
	sub.wmu.Unlock()
	sub.stream.CancelRead(0)
}

func (sub *Subscription) finish(err error) {
	sub.mu.Lock()
	if sub.err == nil {
		sub.err = err
	}
	sub.mu.Unlock()
	close(sub.done)
}

func (sub *Subscription) read() {
	for {
		f, err := ReadFrame(sub.stream, MaxBody)
		if err == nil {
			err = sub.sess.Admit(f, Topic, false)
		}
		if err == nil {
			err = sub.handle(f)
		}
		if err != nil {
			if !sub.closing.Load() {
				sub.stream.CancelWrite(0)
			}
			sub.finish(err)
			return
		}
	}
}

func (sub *Subscription) handle(f Frame) error {
	b := topicBody(f)
	switch f.Kind {
	case KindResponse:
		if len(b) < 2 || int(binary.LittleEndian.Uint16(b)) != len(b)-2 {
			return ErrFrame
		}
		select {
		case sub.results <- append([]uint8(nil), b[2:]...):
		default:
			return ErrFrame
		}
	case KindTopicMessages:
		ins, ok := decodeMessages(b)
		if !ok {
			return ErrFrame
		}
		bulk := false
		for _, fl := range f.Fields[1:] {
			bulk = bulk || fl.Tag == 128
		}
		sub.receive(ins, bulk)
	case KindTopicBulkEnd:
		if len(b) != 5 {
			return ErrFrame
		}
		select {
		case sub.bulkEnd <- bulkEnd{binary.LittleEndian.Uint32(b), b[4]&1 != 0, b[4]&2 != 0}:
		default:
			return ErrFrame
		}
	case KindTopicAvailable:
		select {
		case sub.available <- struct{}{}:
		default:
		}
	case KindTopicLost:
		sub.mu.Lock()
		sub.lost = true
		sub.mu.Unlock()
		select {
		case sub.inboxWake <- struct{}{}:
		default:
		}
	default:
		return ErrFrame
	}
	return nil
}

// receive checks each message on its own; a bad one is dropped alone.
func (sub *Subscription) receive(ins []inMsg, bulk bool) {
	peer, ok := sub.h.t.lookupFor(sub.sess.peer.Key, Topic)
	if !ok {
		return
	}
	now := sub.h.now()
	var ok2 []Message
	var reack []topicAckKey
	for _, in := range ins {
		segs, valid := splitTopic(in.topic, false)
		if !valid || in.ttl <= 0 || in.ttl > TopicMaxTTL || len(in.data) > TopicMaxData || in.flags&^(topicBinary|topicMustDeliver|topicReplace) != 0 {
			continue
		}
		if in.flags&topicBinary == 0 && !utf8.Valid(in.data) {
			continue
		}
		sub.h.mu.Lock()
		acl := sub.h.acls[segs[0]]
		sub.h.mu.Unlock()
		if acl == nil || !publishAllowed(acl, peer, in.topic, segs) {
			continue
		}
		m := Message{
			Publisher: peer.Key, PublisherID: peer.ID, Topic: in.topic,
			Binary: in.flags&topicBinary != 0, MustDeliver: in.flags&topicMustDeliver != 0, Replace: in.flags&topicReplace != 0,
			Seq: in.seq, Expires: now.Add(in.ttl), Data: in.data,
		}
		if m.MustDeliver && sub.h.wasAcked(topicAckKey{m.Publisher, m.Topic, m.Seq}, now) {
			reack = append(reack, topicAckKey{m.Publisher, m.Topic, m.Seq})
			continue
		}
		ok2 = append(ok2, m)
	}
	if len(reack) > 0 {
		go func() { _ = sub.writeFrame(topicFrame(KindStored, sub.request, encodeAcks(reack))) }()
	}
	sub.mu.Lock()
	if bulk {
		sub.bulk = append(sub.bulk, ok2...)
		sub.mu.Unlock()
		return
	}
	for _, m := range ok2 {
		replaced := false
		if m.Replace {
			for i, old := range sub.inbox {
				if old.Publisher == m.Publisher && old.Topic == m.Topic {
					sub.inboxSize += len(m.Data) - len(old.Data)
					sub.inbox[i], replaced = m, true
					break
				}
			}
		}
		if replaced {
			continue
		}
		// A push subscriber that does not call Next fills its inbox at
		// most to the stream queue size. Past that a best-effort message
		// is dropped and marked lost; a must-deliver one is dropped
		// without an ack, so the publisher sends it again later.
		size := len(m.Data) + len(m.Topic)
		if sub.inboxSize+size > topicQueueBytes {
			if !m.MustDeliver {
				sub.lost = true
			}
			continue
		}
		sub.inbox = append(sub.inbox, m)
		sub.inboxSize += size
	}
	sub.mu.Unlock()
	select {
	case sub.inboxWake <- struct{}{}:
	default:
	}
}

func publishAllowed(acl *TopicACL, peer Peer, topic string, segs []string) bool {
	if acl.Publish != nil {
		return acl.Publish(peer, topic)
	}
	return len(segs) > 1 && segs[1] == TopicSegment(peer.ID)
}

// rememberAcked keeps acknowledged must-deliver keys until their longest TTL
// so a redelivery is acknowledged again instead of handled twice. Expired
// keys are swept when the set grows, never on a timer loop.
func (h *Topics) rememberAcked(keys []topicAckKey) {
	if len(keys) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if len(h.acked) > 4096 {
		for k, until := range h.acked {
			if !until.After(now) {
				delete(h.acked, k)
			}
		}
	}
	// Still too many live keys: forget some. A forgotten key only means a
	// redelivery may be handed out again, which must-deliver receivers
	// already tolerate (no ordering, seq per topic).
	for k := range h.acked {
		if len(h.acked)+len(keys) <= topicAckedMax {
			break
		}
		delete(h.acked, k)
	}
	for _, k := range keys {
		h.acked[k] = now.Add(TopicMaxTTL)
	}
}

func (h *Topics) wasAcked(k topicAckKey, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	until, ok := h.acked[k]
	return ok && until.After(now)
}
