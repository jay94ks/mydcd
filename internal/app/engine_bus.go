// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/moby/moby/api/types/events"
)

// engineBusWait is how long one container's engine events are gathered into
// one eventbus notice.
const engineBusWait = 300 * time.Millisecond

// engineContainerReason maps an engine event to the eventbus reason a
// reader acts on; "" leaves it out.
func engineContainerReason(m events.Message) string {
	if m.Type != events.ContainerEventType {
		return ""
	}
	switch a := string(m.Action); {
	case a == "start", a == "stop", a == "die", a == "oom":
		return a
	case a == "seafield.memory":
		return "oom"
	case a == "seafield.pressure":
		return "pressure"
	case strings.HasPrefix(a, "health_status"):
		return "health"
	}
	return ""
}

// engineBus gathers engine events per container and publishes them.
type engineBus struct {
	publish func(eventbus.Event)
	node    func() string
	wait    time.Duration

	mu      sync.Mutex
	boot    string
	pending map[string]*eventbus.Event
}

func newEngineBus(publish func(eventbus.Event), node func() string) *engineBus {
	return &engineBus{publish: publish, node: node, wait: engineBusWait, pending: map[string]*eventbus.Event{}}
}

func (b *engineBus) container(id string, attrs map[string]string, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e := b.pending[id]; e != nil {
		if !slices.Contains(e.Reasons, reason) {
			e.Reasons = append(e.Reasons, reason)
		}
		return
	}
	m := logMeta(id, attrs)
	b.pending[id] = &eventbus.Event{Topic: eventbus.TopicEngine, Kind: eventbus.KindEngineContainer, Node: b.node(), Tenant: m.Tenant, App: m.App, Container: id, Reasons: []string{reason}, Changed: true}
	time.AfterFunc(b.wait, func() {
		b.mu.Lock()
		e := b.pending[id]
		delete(b.pending, id)
		b.mu.Unlock()
		if e != nil {
			b.publish(*e)
		}
	})
}

func (b *engineBus) engine(reason string) {
	b.publish(eventbus.Event{Topic: eventbus.TopicEngine, Kind: eventbus.KindEngineNode, Node: b.node(), Reasons: []string{reason}, Changed: true})
}

// handler publishes container notices, "boot" when the feed's boot changes
// and "lag" whenever every engine view must be read again (a new boot or
// lost events). "build" waits for engine build events.
func (b *engineBus) handler() engineevents.Handler {
	return engineevents.Handler{
		Name: "bus",
		Handle: func(_ context.Context, rec engineevents.Record) error {
			b.mu.Lock()
			rebooted := b.boot != "" && rec.Boot != b.boot
			b.boot = rec.Boot
			b.mu.Unlock()
			if rebooted {
				b.engine("boot")
			}
			if reason := engineContainerReason(rec.Event); reason != "" {
				b.container(rec.Event.Actor.ID, rec.Event.Actor.Attributes, reason)
			}
			return nil
		},
		Rescan: func(context.Context) error {
			b.engine("lag")
			return nil
		},
	}
}
