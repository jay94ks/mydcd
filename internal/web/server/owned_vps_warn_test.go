// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Subscription notices go out once at 14, 3 and 1 days, start over after a
// renewal moves the end date, and are forgotten for a detached server.
func TestOwnedVPSSubscriptionNotices(t *testing.T) {
	f, _ := newFakeFixture(t)
	now := time.Unix(1_800_000_000, 0)
	v := control.OwnedVPS{Name: "edge-9", Voter: true, AttachedBy: "u-admin"}
	servers := []control.OwnedVPS{v}
	end := now.Add(20 * 24 * time.Hour).Unix()
	round := func(at time.Time, expires int64) {
		f.srv.ownedWarn(at, servers, []control.OwnedVPSServerStatus{{Name: "edge-9", ExpiresAt: expires}})
	}
	count := func() int {
		_, n, err := f.store.ListNotifications("u-admin", false, 100)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	base := count()
	at := func(daysLeft float64) time.Time {
		return time.Unix(end, 0).Add(-time.Duration(daysLeft * float64(24*time.Hour)))
	}
	round(at(15), end) // not yet
	round(at(13.5), end)
	round(at(13), end) // same threshold again: nothing new
	round(at(2.5), end)
	round(at(0.5), end)
	round(at(0.2), end)
	if got := count() - base; got != 3 {
		t.Fatalf("notices = %d, want 3", got)
	}
	ns, _, _ := f.store.ListNotifications("u-admin", false, 1)
	if ns[0].Kind != NotifyVPSSubscription || ns[0].Severity != "error" || ns[0].Link != "/nodes/owned-vps" {
		t.Fatalf("notice = %+v", ns[0])
	}

	renewed := end + 30*24*3600
	round(time.Unix(renewed, 0).Add(-2*24*time.Hour), renewed)
	if got := count() - base; got != 4 {
		t.Fatalf("after renewal notices = %d, want 4", got)
	}

	servers = nil
	round(now, end)
	if _, err := f.store.GetOwnedVPSWarn("edge-9"); err == nil {
		t.Fatal("detached server kept its notice state")
	}
}

func TestOwnedWarnDue(t *testing.T) {
	day := 24 * time.Hour
	for left, want := range map[time.Duration]int{-time.Hour: 0, 0: 0, time.Hour: 1, day: 1, 2 * day: 3, 3 * day: 3, 10 * day: 14, 14 * day: 14, 15 * day: 0} {
		if got := ownedWarnDue(left); got != want {
			t.Errorf("ownedWarnDue(%v) = %d, want %d", left, got, want)
		}
	}
}
