// SPDX-License-Identifier: Apache-2.0

package clusterapp

import (
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
)

func TestReviveBackoffDoublesAndSettles(t *testing.T) {
	var b reviveBook
	now := time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)
	if !b.due(Web, now) {
		t.Fatal("first start must be due at once")
	}
	waits := []time.Duration{}
	for i := 0; i < 12; i++ {
		b.record(Web, "exit code 1", now)
		next := b.row(Web).next
		waits = append(waits, next.Sub(now))
		if b.due(Web, next.Add(-time.Millisecond)) || !b.due(Web, next) {
			t.Fatal("backoff not honoured at", i)
		}
		now = next
	}
	if waits[0] != reviveMin || waits[1] != 2*reviveMin || waits[len(waits)-1] != reviveMax {
		t.Fatal("backoff steps", waits)
	}
	if n, reason := b.stats(Web); n != 12 || reason != "exit code 1" {
		t.Fatal(n, reason)
	}
	b.running(Web, true, now)
	b.running(Web, true, now.Add(reviveSettle))
	b.record(Web, "out of memory", now.Add(reviveSettle))
	if b.row(Web).wait != reviveMin {
		t.Fatal("a container that kept running must start again after the minimum wait", b.row(Web).wait)
	}
}

func TestExitReason(t *testing.T) {
	for want, st := range map[string]container.State{
		"out of memory": {OOMKilled: true, ExitCode: 137},
		"never started": {Status: container.StateCreated},
		"dead":          {Dead: true},
		"exit code 2":   {Status: container.StateExited, ExitCode: 2},
	} {
		if got := exitReason(&st); got != want {
			t.Errorf("%+v: %q", st, got)
		}
	}
}
