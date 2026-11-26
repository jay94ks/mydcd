// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"
)

func TestLeaderLinkHeldSince(t *testing.T) {
	at := time.Now()
	was := leaderLink{ID: "node-b", Term: 4, Since: at.Add(-time.Minute)}
	for name, c := range map[string]struct {
		now  leaderLink
		want bool
	}{
		"same link":         {leaderLink{ID: "node-b", Term: 4, Since: was.Since}, true},
		"other leader":      {leaderLink{ID: "node-c", Term: 4, Since: was.Since}, false},
		"new term":          {leaderLink{ID: "node-b", Term: 5, Since: was.Since}, false},
		"reconnected after": {leaderLink{ID: "node-b", Term: 4, Since: at.Add(time.Second)}, false},
		"no link":           {leaderLink{ID: "node-b", Term: 4}, false},
		"self, same term":   {leaderLink{ID: "node-b", Term: 4, Self: true}, true},
		"no leader":         {leaderLink{}, false},
	} {
		if got := c.now.heldSince(was, at); got != c.want {
			t.Errorf("%s: heldSince = %t, want %t", name, got, c.want)
		}
	}
}

func TestObservationDueResendsChangedStaleOrRelinked(t *testing.T) {
	now := time.Now()
	digest := [32]byte{1}
	last := observationSentAt{digest: digest, at: now.Add(-10 * time.Second)}
	linked := now.Add(-time.Hour)
	if observationDue(last, true, digest, linked, true, now) {
		t.Fatal("unchanged report resent within the resend window")
	}
	for name, c := range map[string]struct {
		last        observationSentAt
		known       bool
		digest      [32]byte
		linkedSince time.Time
		linked      bool
		now         time.Time
	}{
		"never sent":         {observationSentAt{}, false, digest, linked, true, now},
		"content changed":    {last, true, [32]byte{2}, linked, true, now},
		"resend window over": {last, true, digest, linked, true, last.at.Add(observationResend)},
		"link broke since":   {last, true, digest, now.Add(-time.Second), true, now},
		"not linked":         {last, true, digest, time.Time{}, false, now},
	} {
		if !observationDue(c.last, c.known, c.digest, c.linkedSince, c.linked, c.now) {
			t.Errorf("%s: report not resent", name)
		}
	}
}
