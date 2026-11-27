// SPDX-License-Identifier: Apache-2.0

package engineevents

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/moby/moby/api/types/events"
)

func rec(seq uint64, action string) Record {
	return Record{Seq: seq, Boot: "b1", Event: events.Message{Type: events.ContainerEventType, Action: events.Action(action)}}
}

func TestConsumerDispatchesRescansAndKeepsCursor(t *testing.T) {
	var dies, all []uint64
	rescans := 0
	var rescanErr error
	var saved Cursor
	c, err := New([]Handler{
		{Name: "restart", Wants: func(m events.Message) bool { return m.Action == "die" }, Handle: func(_ context.Context, r Record) error {
			dies = append(dies, r.Seq)
			return errors.New("handler failure does not stop the feed")
		}, Rescan: func(context.Context) error { rescans++; return rescanErr }},
		{Name: "all", Handle: func(_ context.Context, r Record) error { all = append(all, r.Seq); return nil }},
	}, Cursor{}, func(c Cursor) error { saved = c; return nil })
	if err != nil {
		t.Fatal(err)
	}
	c.logf = func(string, ...any) {}
	ctx := context.Background()
	if err := c.Subscribed(ctx, Subscribed{Reply: engineops.Reply{Result: engineops.Applied}, Boot: "b1", Last: 0}); err != nil {
		t.Fatal(err)
	}
	if rescans != 1 || saved.Boot != "b1" {
		t.Fatalf("first boot: rescans %d cursor %+v", rescans, saved)
	}
	if err := c.Apply(ctx, Batch{Boot: "b1", Records: []Record{rec(1, "start"), rec(2, "die"), rec(2, "die")}}); err != nil {
		t.Fatal(err)
	}
	if len(dies) != 1 || len(all) != 2 || saved.Last != 2 || rescans != 1 {
		t.Fatalf("dispatch: dies %v all %v cursor %+v rescans %d", dies, all, saved, rescans)
	}
	// A gap marks views stale; a failing rescan is retried on the next batch.
	rescanErr = errors.New("engine busy")
	if err := c.Apply(ctx, Batch{Boot: "b1", Gap: &Range{From: 3, To: 5}, Records: []Record{rec(6, "die")}}); err != nil {
		t.Fatal(err)
	}
	rescanErr = nil
	if err := c.Apply(ctx, Batch{Boot: "b1", Records: []Record{rec(7, "start")}}); err != nil {
		t.Fatal(err)
	}
	if rescans != 3 || saved.Last != 7 {
		t.Fatalf("gap: rescans %d cursor %+v", rescans, saved)
	}
	if err := c.Apply(ctx, Batch{Boot: "b1", Records: []Record{rec(8, "start")}}); err != nil || rescans != 3 {
		t.Fatalf("rescan repeated after success: %d", rescans)
	}
	// A feed behind the cursor resets it and asks to subscribe again.
	if err := c.Subscribed(ctx, Subscribed{Reply: engineops.Reply{Result: engineops.Applied}, Boot: "b2", Last: 1}); !errors.Is(err, ErrResubscribe) || c.After() != 0 || saved.Boot != "b2" {
		t.Fatalf("reset feed: %v after %d cursor %+v", err, c.After(), saved)
	}
}

func TestRecordDecodesTheEngineEncoding(t *testing.T) {
	raw := []byte(`{"Boot":"d0","Gap":null,"Records":[{"seq":10,"boot":"d0","event":{"Type":"container","Action":"die","Actor":{"ID":"c1","Attributes":{"exitCode":"3"}},"time":1795766808,"timeNano":1795766808000000000}}]}`)
	var b Batch
	if err := json.Unmarshal(raw, &b); err != nil || len(b.Records) != 1 || b.Records[0].Seq != 10 || b.Records[0].Event.Actor.Attributes["exitCode"] != "3" {
		t.Fatalf("%v %+v", err, b)
	}
}

func TestNewRefusesBadHandlers(t *testing.T) {
	h := func(context.Context, Record) error { return nil }
	for name, list := range map[string][]Handler{
		"no name":   {{Handle: h}},
		"no handle": {{Name: "a"}},
		"duplicate": {{Name: "a", Handle: h}, {Name: "a", Handle: h}},
	} {
		if _, err := New(list, Cursor{}, func(Cursor) error { return nil }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
