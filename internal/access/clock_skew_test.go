// SPDX-License-Identifier: Apache-2.0

package access

import "testing"

// A report signed a few seconds in the future by another machine's clock is
// accepted on the unsigned paths too: now-at must not wrap.
func TestRecentAcceptsSmallFutureSkewWithoutUnsignedWrap(t *testing.T) {
	const now = 1_000_000
	for _, c := range []struct {
		at   uint64
		want bool
	}{{now + 5, true}, {now + MaxClockSkewSeconds, true}, {now + MaxClockSkewSeconds + 1, false}, {now, true}, {now - 30, true}, {now - 31, false}} {
		if got := Recent(c.at, uint64(now), 30); got != c.want {
			t.Fatalf("uint64 at=now%+d: %v", int64(c.at)-now, got)
		}
		if got := Recent(int64(c.at), int64(now), 30); got != c.want {
			t.Fatalf("int64 at=now%+d: %v", int64(c.at)-now, got)
		}
	}
	if !RecentMillis(uint64(now+5000), uint64(now), 30000) || RecentMillis(uint64(now+MaxClockSkewSeconds*1000+1), uint64(now), 30000) || RecentMillis(uint64(now-30001), uint64(now), 30000) {
		t.Fatal("milliseconds")
	}
}
