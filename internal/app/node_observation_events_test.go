// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/observability"
)

// A stored report tells event subscribers only when its content changed or
// its last event is observationResend old; a report that only carries a new
// time, index and signature is stored without an event.
func TestObservationEventOnlyWhenContentChanges(t *testing.T) {
	raw := func(at uint64, load uint64) observability.Report {
		return observability.Report{Kind: "node-observation", Schema: 1, Node: "node-a", At: at, Index: at, Signature: []byte{byte(at)}, Host: &observability.Host{CPUCapacity: 1e9, MemoryUsed: &load}}
	}
	r := &Runtime{}
	now := time.Now()
	id := "node-observation/node-a/host"
	if !r.observationEventDue(id, raw(1, 10), now) {
		t.Fatal("first report sent no event")
	}
	if r.observationEventDue(id, raw(2, 10), now.Add(30*time.Second)) {
		t.Fatal("a new time alone sent an event")
	}
	if !r.observationEventDue(id, raw(3, 11), now.Add(31*time.Second)) {
		t.Fatal("changed content sent no event")
	}
	if !r.observationEventDue(id, raw(4, 11), now.Add(31*time.Second+observationResend)) {
		t.Fatal("unchanged report sent no event after observationResend")
	}
	if !r.observationEventDue("node-observation/node-b/host", raw(4, 11), now) {
		t.Fatal("another report shares the first one's event state")
	}
}

// Rounds wait observationInterval give or take a tenth.
func TestObservationWaitSpreadsRounds(t *testing.T) {
	interval := 30 * time.Second
	if got := observationWait(interval, func(int64) int64 { return 0 }); got != 27*time.Second {
		t.Fatal("shortest wait", got)
	}
	if got := observationWait(interval, func(n int64) int64 { return n - 1 }); got != 33*time.Second-1 {
		t.Fatal("longest wait", got)
	}
	if got := observationWait(time.Nanosecond, func(int64) int64 { return 0 }); got != time.Nanosecond {
		t.Fatal("tiny interval", got)
	}
}
