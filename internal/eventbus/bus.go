// SPDX-License-Identifier: Apache-2.0

// Package eventbus carries in-process notices from sfcd to its event
// subscribers (SFCP purpose 22 Event, the web daemon's live updates).
// A notice names what changed, never its value: a subscriber reads the item
// it cares about through the usual permission-checked read. Delivery is
// best effort and bounded: a subscriber that falls behind loses its queue
// and gets one Resync, after which it reads its screen again.
package eventbus

import (
	"context"
	"sync"
)

// Topics.
const (
	// TopicReport: a node report was accepted and changed what is stored.
	TopicReport = "report"
	// TopicEngine: this node's Seafield engine changed a container or itself.
	TopicEngine = "engine"
	// TopicAlarmPrefix starts an alarm topic, "alarm/<name>": a short
	// notice whose reach the sender chose (Scope). At most once, never
	// stored or resent.
	TopicAlarmPrefix = "alarm/"
)

// MaxAlarmNote bounds an alarm's Note.
const MaxAlarmNote = 256

// AlarmTopic returns the topic of the alarm called name: 1–64 of a–z, 0–9,
// '-' and '.'.
func AlarmTopic(name string) (string, bool) {
	if len(name) == 0 || len(name) > 64 {
		return "", false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return "", false
		}
	}
	return TopicAlarmPrefix + name, true
}

// IsAlarm reports whether topic is a valid alarm topic.
func IsAlarm(topic string) bool {
	if len(topic) <= len(TopicAlarmPrefix) || topic[:len(TopicAlarmPrefix)] != TopicAlarmPrefix {
		return false
	}
	_, ok := AlarmTopic(topic[len(TopicAlarmPrefix):])
	return ok
}

// Report kinds (Event.Kind under TopicReport).
const (
	KindNodeObservation = "node-observation" // observability.Report, Source names it
	KindNodeReport      = "node-report"      // workload.Report of one node
	KindDiagnostic      = "diagnostic"       // eventlog.Batch from one node
)

// Engine kinds (Event.Kind under TopicEngine). Reasons say what to read
// again; several within 300ms of one container arrive as one notice.
const (
	// KindEngineContainer: Container on Node; Reasons ⊆ start, stop, die,
	// oom, pressure, health. Tenant/App name its workload, empty for a
	// container outside any tenant (ManageCluster to read).
	KindEngineContainer = "engine.container"
	// KindEngineNode: the engine on Node; Reasons ⊆ boot (a new engine
	// start), lag (events were lost: read every engine view again), build.
	KindEngineNode = "engine.node"
)

// Scope is the reach the sender chose. sfcd checks it against the sender's
// permissions before publishing; an empty Scope reaches every subscriber
// that may read the referenced item.
type Scope struct {
	Nodes    []string `json:",omitempty"`
	AllNodes bool     `json:",omitempty"`
	Web      bool     `json:",omitempty"`
	User     string   `json:",omitempty"`
	Tenant   string   `json:",omitempty"`
}

// Event is one notice. Node/Source/Tenant/App reference the item; Tenant
// empty means a cluster-scoped item (ManageCluster to read). An alarm's Node
// is the node that sent it and Note its short text.
type Event struct {
	Topic  string
	Kind   string
	Node   string `json:",omitempty"`
	Source string `json:",omitempty"`
	Tenant string `json:",omitempty"`
	App    string `json:",omitempty"`
	// Container and Reasons are set under TopicEngine.
	Container string   `json:",omitempty"`
	Reasons   []string `json:",omitempty"`
	Changed   bool
	Scope     Scope  `json:",omitempty"`
	Note      string `json:",omitempty"`
}

// Bus fans events out to subscribers. The zero value is not usable; use New.
type Bus struct {
	mu   sync.Mutex
	subs map[*Sub]struct{}
}

func New() *Bus { return &Bus{subs: map[*Sub]struct{}{}} }

// Publish never blocks. A nil Bus drops the event.
func (b *Bus) Publish(e Event) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for s := range b.subs {
		s.push(e)
	}
}

// DefaultQueue matches the Event purpose's batch bound: more pending events
// than one reply carries become a Resync.
const DefaultQueue = 512

// Subscribe starts a subscription holding at most queue events (DefaultQueue
// when <= 0). keep, when set, filters events before they are queued.
func (b *Bus) Subscribe(queue int, keep func(Event) bool) *Sub {
	if queue <= 0 {
		queue = DefaultQueue
	}
	s := &Sub{bus: b, max: queue, keep: keep, wake: make(chan struct{}, 1)}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

// Sub is one subscription.
type Sub struct {
	bus  *Bus
	max  int
	keep func(Event) bool
	wake chan struct{}

	mu     sync.Mutex
	queue  []Event
	lost   bool
	closed bool
}

func (s *Sub) push(e Event) {
	if s.keep != nil && !s.keep(e) {
		return
	}
	s.mu.Lock()
	if s.closed || s.lost {
		s.mu.Unlock()
		return
	}
	if len(s.queue) >= s.max {
		s.queue, s.lost = nil, true
	} else {
		s.queue = append(s.queue, e)
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Next waits for pending events and returns all of them in publish order.
// resync reports that events were dropped since the last Next; the batch is
// then empty and the subscriber should read its state again.
func (s *Sub) Next(ctx context.Context) (batch []Event, resync bool, err error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil, false, context.Canceled
		}
		if s.lost || len(s.queue) > 0 {
			batch, resync = s.queue, s.lost
			s.queue, s.lost = nil, false
			s.mu.Unlock()
			return batch, resync, nil
		}
		s.mu.Unlock()
		select {
		case <-s.wake:
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

// Close ends the subscription; it is safe to call more than once.
func (s *Sub) Close() {
	s.bus.mu.Lock()
	delete(s.bus.subs, s)
	s.bus.mu.Unlock()
	s.mu.Lock()
	s.closed, s.queue = true, nil
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
