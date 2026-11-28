// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"
)

func TestLogsLimitAndKeep(t *testing.T) {
	for _, c := range []struct {
		limit string
		disk  int64
		want  int64
	}{
		{"", 100 << 30, 5 << 30},
		{"", 4 << 30, 1 << 30},     // 5% below 1GiB → 1GiB
		{"", 1000 << 30, 20 << 30}, // above 20GiB → 20GiB
		{"10%", 100 << 30, 10 << 30},
		{"10GiB", 1 << 30, 10 << 30}, // a size is used as given
		{"512MiB", 0, 512 << 20},
	} {
		got, err := Logs{Limit: c.limit}.LimitBytes(c.disk)
		if err != nil || got != c.want {
			t.Fatal(c, got, err)
		}
	}
	for _, bad := range []string{"10g", "0%", "-1GiB", "5", "abc", "0GiB"} {
		if _, err := (Logs{Limit: bad}).LimitBytes(1 << 30); err == nil {
			t.Fatal("accepted limit", bad)
		}
	}
	for v, want := range map[string]time.Duration{"": 7 * 24 * time.Hour, "forever": 0, "3d": 72 * time.Hour, "36h": 36 * time.Hour} {
		if got, err := (Logs{Keep: v}).KeepDuration(); err != nil || got != want {
			t.Fatal(v, got, err)
		}
	}
	for _, bad := range []string{"0d", "-1h", "never", "7days"} {
		if _, err := (Logs{Keep: bad}).KeepDuration(); err == nil {
			t.Fatal("accepted keep", bad)
		}
	}
}
