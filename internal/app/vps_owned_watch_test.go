// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestOwnedJudge(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	run := control.OwnedVPS{Name: "edge-1", Phase: control.OwnedRunning, Protect: control.OwnedProtectLowWeight}
	read := func(at time.Time, used int64) ownedReading {
		return ownedReading{at: at, month: control.OwnedMonthOf(at), usedMB: used, monthMB: 1_000_000}
	}
	// Far from the allowance: nothing; the forecast is shown.
	prev := read(at.Add(-time.Hour), 500_000)
	action, _, reach := ownedJudge(run, read(at, 501_000), &prev)
	if action != "" || reach != at.Unix()+499*3600 {
		t.Fatalf("calm: %q %d", action, reach)
	}
	// At this rate it runs out within 6 hours: hold, in the server's mode.
	prev = read(at.Add(-time.Hour), 800_000)
	action, limit, _ := ownedJudge(run, read(at, 900_000), &prev)
	if action != control.OwnedLimiting || limit.Mode != control.OwnedProtectLowWeight || limit.ReachAt != at.Unix()+3600 || limit.At != at.Unix() || limit.Month != "2026-11" {
		t.Fatalf("soon: %q %+v", action, limit)
	}
	// 95% with no rate known yet: hold anyway; over the allowance: ReachAt 0.
	if action, _, _ := ownedJudge(run, read(at, 960_000), nil); action != control.OwnedLimiting {
		t.Fatal("share", action)
	}
	if _, limit, _ := ownedJudge(run, read(at, 1_200_000), nil); limit == nil || limit.ReachAt != 0 {
		t.Fatalf("over: %+v", limit)
	}
	// An operator ended this month's hold: leave it.
	ended := run
	ended.Restored = &control.OwnedRestore{At: at.Unix(), Month: "2026-11", By: "admin"}
	if action, _, _ := ownedJudge(ended, read(at, 990_000), nil); action != "" {
		t.Fatal("operator restore ignored", action)
	}
	// Held: restored only once the month turned and use is low again.
	held := run
	held.Limit = &control.OwnedLimit{At: at.Unix(), Month: "2026-11", Mode: control.OwnedProtectExclude, UsedMB: 960_000, MonthMB: 1_000_000}
	if action, _, _ := ownedJudge(held, read(at.Add(time.Hour), 970_000), nil); action != "" {
		t.Fatal("same month", action)
	}
	next := time.Date(2026, 12, 1, 1, 0, 0, 0, time.UTC)
	if action, _, _ := ownedJudge(held, read(next, 980_000), nil); action != "" {
		t.Fatal("vendor not reset yet", action)
	}
	if action, _, _ := ownedJudge(held, read(next, 2_000), nil); action != control.OwnedRestoredReport {
		t.Fatal("reset", action)
	}
	// No allowance reported: never hold.
	if action, _, _ := ownedJudge(run, ownedReading{at: at, month: "2026-11", usedMB: 5}, nil); action != "" {
		t.Fatal("no allowance", action)
	}
}
