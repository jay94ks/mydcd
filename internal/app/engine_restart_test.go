// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/moby/moby/api/types/events"
)

func TestRestartEventsWakeAPassForOwnStoppedContainers(t *testing.T) {
	r := &Runtime{owner: "node-a", moduleWake: make(chan struct{}, 1)}
	msg := func(action string, attrs map[string]string) events.Message {
		return events.Message{Type: events.ContainerEventType, Action: events.Action(action), Actor: events.Actor{ID: "c", Attributes: attrs}}
	}
	own := map[string]string{"org.sfc.owner": "node-a"}
	for name, c := range map[string]struct {
		m    events.Message
		want bool
	}{
		"die":           {msg("die", own), true},
		"oom":           {msg("oom", own), true},
		"oom kill":      {msg("seafield.memory", map[string]string{"org.sfc.owner": "node-a", "changed": "max,oom_kill"}), true},
		"memory high":   {msg("seafield.memory", map[string]string{"org.sfc.owner": "node-a", "changed": "high"}), false},
		"start":         {msg("start", own), false},
		"other owner":   {msg("die", map[string]string{"org.sfc.owner": "node-b"}), false},
		"not ours":      {msg("die", nil), false},
		"network event": {events.Message{Type: events.NetworkEventType, Action: "die", Actor: events.Actor{Attributes: own}}, false},
	} {
		if got := r.ownStoppedContainer(c.m); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	h := r.restartEvents()
	if err := h.Handle(context.Background(), engineevents.Record{Event: msg("die", own)}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-r.moduleWake:
	default:
		t.Fatal("a stopped container did not wake a pass")
	}
	if err := h.Rescan(context.Background()); err != nil {
		t.Fatal(err)
	}
	ok, woken := waitModulePassOrWake(context.Background(), nil, r.moduleWake, false, time.Hour)
	if !ok || !woken {
		t.Fatal("rescan did not wake a pass")
	}
}
