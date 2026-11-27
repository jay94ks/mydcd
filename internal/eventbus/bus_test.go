// SPDX-License-Identifier: Apache-2.0

package eventbus

import (
	"context"
	"testing"
	"time"
)

func TestBusBatchFilterAndResync(t *testing.T) {
	b := New()
	all := b.Subscribe(2, nil)
	defer all.Close()
	changed := b.Subscribe(0, func(e Event) bool { return e.Changed })
	defer changed.Close()
	b.Publish(Event{Topic: TopicReport, Kind: KindNodeReport, Node: "a", Changed: true})
	b.Publish(Event{Topic: TopicReport, Kind: KindNodeReport, Node: "b"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, resync, err := all.Next(ctx)
	if err != nil || resync || len(got) != 2 || got[0].Node != "a" || got[1].Node != "b" {
		t.Fatalf("all = %v %v %v", got, resync, err)
	}
	got, resync, err = changed.Next(ctx)
	if err != nil || resync || len(got) != 1 || got[0].Node != "a" {
		t.Fatalf("changed = %v %v %v", got, resync, err)
	}
	for range 3 {
		b.Publish(Event{Topic: TopicReport, Changed: true})
	}
	got, resync, err = all.Next(ctx)
	if err != nil || !resync || len(got) != 0 {
		t.Fatalf("overflow = %v %v %v", got, resync, err)
	}
	b.Publish(Event{Topic: TopicReport, Node: "c", Changed: true})
	if got, resync, _ = all.Next(ctx); resync || len(got) != 1 {
		t.Fatalf("after resync = %v %v", got, resync)
	}
}

func TestSubCloseAndCancel(t *testing.T) {
	b := New()
	s := b.Subscribe(0, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := s.Next(ctx); err == nil {
		t.Fatal("Next returned without events")
	}
	s.Close()
	s.Close()
	b.Publish(Event{Topic: TopicReport})
	if _, _, err := s.Next(context.Background()); err == nil {
		t.Fatal("closed Sub returned events")
	}
	var nilBus *Bus
	nilBus.Publish(Event{})
}

func TestAlarmTopic(t *testing.T) {
	if got, ok := AlarmTopic("disk-full.sda"); !ok || got != "alarm/disk-full.sda" || !IsAlarm(got) {
		t.Fatal(got, ok)
	}
	for _, bad := range []string{"", "Disk", "a/b", "a b", string(make([]byte, 65))} {
		if _, ok := AlarmTopic(bad); ok || IsAlarm(TopicAlarmPrefix+bad) {
			t.Fatal("accepted", bad)
		}
	}
	if IsAlarm(TopicReport) || IsAlarm(TopicAlarmPrefix) {
		t.Fatal("non-alarm topic")
	}
}
