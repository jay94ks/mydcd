// SPDX-License-Identifier: Apache-2.0

// Package engineevents is the one place sfcd (sfcd) takes the engine's
// numbered event feed (purpose 32, seafield/docs/sfcd-socket.md) and hands
// each event to the features that want it. The cursor is (engine boot, last
// seq); a new boot or a gap makes every feature rebuild its view from the
// engine's current state instead of trusting events it may have missed.
// Transport stays with the engine session. See
// devel/refactor/18-sfcd-structure.md 5.3.
package engineevents

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/moby/moby/api/types/events"
)

// Subscribe is the purpose 32 "subscribe" request: push every event after After.
type Subscribe struct {
	engineops.Request
	After uint64
}

// Subscribed is its answer: the engine's boot and its newest seq. Batches
// follow as kind 16.
type Subscribed struct {
	engineops.Reply
	Boot string
	Last uint64
}

// Range is an inclusive run of seqs the engine dropped.
type Range struct{ From, To uint64 }

// Batch is one pushed kind 16 body. Records wrap upstream events.Message, so
// it is read with plain encoding/json, not schema.Decode.
type Batch struct {
	Boot    string
	Gap     *Range
	Records []Record
}

// Record is one numbered engine event.
type Record struct {
	Seq   uint64         `json:"seq"`
	Boot  string         `json:"boot"`
	Event events.Message `json:"event"`
}

// Cursor is what the consumer keeps across restarts of sfcd.
type Cursor struct {
	Schema uint8
	Boot   string
	Last   uint64
}

// Handler is one feature's use of the feed. Handle must be idempotent: after
// a sfcd crash the events since the last saved cursor arrive again.
type Handler struct {
	Name string
	// Wants picks the events Handle sees; nil takes every event.
	Wants func(events.Message) bool
	// Handle applies one event. An error is logged and the feed moves on;
	// the feature's own reconcile pass owns retrying.
	Handle func(ctx context.Context, r Record) error
	// Rescan rebuilds the feature's view from the engine's current state. It
	// runs on a new engine boot or a gap, and again on the next batch until
	// it succeeds. Nil means the feature keeps no view.
	Rescan func(ctx context.Context) error
}

// ErrResubscribe asks the session to subscribe again from Consumer.After:
// the engine's feed is behind the saved cursor (its event store was reset).
var ErrResubscribe = errors.New("engineevents: engine feed behind cursor, subscribe again")

// Consumer dispatches the feed. One engine session drives it at a time.
type Consumer struct {
	handlers []Handler
	cursor   Cursor
	save     func(Cursor) error
	stale    map[string]bool
	logf     func(string, ...any)
	// still-failing log pacing per handler
	failing map[string]time.Time
}

// New refuses an empty or duplicate name or a nil Handle. save persists the
// cursor after each batch; cursor is the one saved last (zero at first start).
func New(handlers []Handler, cursor Cursor, save func(Cursor) error) (*Consumer, error) {
	seen := map[string]bool{}
	for _, h := range handlers {
		if h.Name == "" || h.Handle == nil || seen[h.Name] {
			return nil, fmt.Errorf("engineevents: bad or duplicate handler %q", h.Name)
		}
		seen[h.Name] = true
	}
	if cursor.Schema == 0 {
		cursor.Schema = 1
	}
	return &Consumer{handlers: handlers, cursor: cursor, save: save, stale: map[string]bool{}, logf: log.Printf, failing: map[string]time.Time{}}, nil
}

// After is the value to subscribe from.
func (c *Consumer) After() uint64 { return c.cursor.Last }

// Cursor returns the current cursor.
func (c *Consumer) Cursor() Cursor { return c.cursor }

// Subscribed takes the subscribe answer. A different boot marks every view
// stale; a feed behind the cursor resets it and returns ErrResubscribe.
func (c *Consumer) Subscribed(ctx context.Context, s Subscribed) error {
	if s.Result != engineops.Applied {
		return fmt.Errorf("engineevents: subscribe %s %s", s.Result, s.Reason)
	}
	if s.Boot != c.cursor.Boot {
		c.markStale()
	}
	if s.Last < c.cursor.Last {
		c.cursor = Cursor{Schema: 1, Boot: s.Boot}
		c.markStale()
		return errors.Join(ErrResubscribe, c.save(c.cursor))
	}
	c.cursor.Boot = s.Boot
	c.rescan(ctx)
	return c.save(c.cursor)
}

// Apply takes one pushed batch and saves the cursor after it. Only a save
// failure is returned; handler failures are logged.
func (c *Consumer) Apply(ctx context.Context, b Batch) error {
	if b.Boot != c.cursor.Boot || b.Gap != nil {
		c.markStale()
		c.cursor.Boot = b.Boot
		if b.Gap != nil && b.Gap.To > c.cursor.Last {
			c.cursor.Last = b.Gap.To
		}
	}
	c.rescan(ctx)
	for _, r := range b.Records {
		if r.Seq <= c.cursor.Last {
			continue
		}
		for _, h := range c.handlers {
			if h.Wants != nil && !h.Wants(r.Event) {
				continue
			}
			c.report(h.Name, "handle", h.Handle(ctx, r))
		}
		c.cursor.Last = r.Seq
	}
	return c.save(c.cursor)
}

func (c *Consumer) markStale() {
	for _, h := range c.handlers {
		if h.Rescan != nil {
			c.stale[h.Name] = true
		}
	}
}

func (c *Consumer) rescan(ctx context.Context) {
	for _, h := range c.handlers {
		if !c.stale[h.Name] {
			continue
		}
		err := h.Rescan(ctx)
		c.report(h.Name, "rescan", err)
		if err == nil {
			delete(c.stale, h.Name)
		}
	}
}

// report logs a handler failure when it starts and then at most every
// ten minutes while it keeps failing, and once when it clears.
func (c *Consumer) report(name, step string, err error) {
	key := name + "/" + step
	since, failing := c.failing[key]
	switch {
	case err == nil && failing:
		delete(c.failing, key)
		c.logf("engine events: %s %s recovered", name, step)
	case err != nil && !failing:
		c.failing[key] = time.Now()
		c.logf("engine events: %s %s failed: %v", name, step, err)
	case err != nil && time.Since(since) >= 10*time.Minute:
		c.failing[key] = time.Now()
		c.logf("engine events: %s %s still failing: %v", name, step, err)
	}
}
