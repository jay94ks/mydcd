// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"math"
	"testing"
	"time"
)

func steady(start time.Time, minutes int, bytesPerMin int64) []TXPoint {
	var out []TXPoint
	for i := 0; i <= minutes; i++ {
		out = append(out, TXPoint{At: start.Add(time.Duration(i) * time.Minute), Bytes: int64(i) * bytesPerMin})
	}
	return out
}

func TestGuardForecastSteadyAndRising(t *testing.T) {
	start := kstTime(2026, 11, 27, 9)
	s := GuardSettings{}
	// Fewer than a window of readings: not ready.
	if f := s.Forecast(steady(start, 3, 1e6), nil, start.Add(3*time.Minute)); f.Ready {
		t.Fatalf("ready too early: %+v", f)
	}
	// Steady 1 MB/min for an hour: 21 MB over the horizon.
	pts := steady(start, 60, 1e6)
	now := start.Add(60 * time.Minute)
	f := s.Forecast(pts, nil, now)
	if !f.Ready || math.Abs(f.Bytes-21e6) > 1 || f.PatternUsed {
		t.Fatalf("steady = %+v", f)
	}
	// The last five minutes jump to 11 MB/min: the short forecast counts
	// half above the hour's average.
	for i := 56; i <= 60; i++ {
		pts[i].Bytes = pts[55].Bytes + int64(i-55)*11e6
	}
	f = s.Forecast(pts, nil, now)
	if f.ShortBytes <= f.AverageBytes || math.Abs(f.Bytes-(f.ShortBytes+f.AverageBytes)/2) > 1 {
		t.Fatalf("rising = %+v", f)
	}
	// Two minutes without a reading add the last rate.
	g := s.Forecast(pts, nil, now.Add(2*time.Minute))
	if math.Abs(g.Bytes-f.Bytes-f.RateBps*120) > 1 {
		t.Fatalf("stale = %+v vs %+v", g, f)
	}
}

func TestGuardPattern(t *testing.T) {
	now := kstTime(2026, 11, 27, 20)
	s := GuardSettings{Pattern: true}
	pts := steady(now.Add(-time.Hour), 60, 1e6)
	history := func(days int) []TXBucket {
		var h []TXBucket
		for d := 1; d <= days; d++ {
			day := now.AddDate(0, 0, -d)
			for b := day.Add(-time.Hour); b.Before(day.Add(time.Hour)); b = b.Add(GuardBucket) {
				n := int64(1e6)
				if !b.Before(day) {
					n = 500e6 // every evening at 20:00 a burst starts
				}
				h = append(h, TXBucket{Start: b, Bytes: n})
			}
		}
		return h
	}
	if f := s.Forecast(pts, history(6), now); f.PatternUsed || f.PatternDays != 6 {
		t.Fatalf("six days used: %+v", f)
	}
	f := s.Forecast(pts, history(10), now)
	// 21 minutes of 500 MB per 5 minutes is 2.1 GB, far above 21 MB.
	if !f.PatternUsed || math.Abs(f.PatternBytes-2100e6) > 1 || f.Bytes != f.PatternBytes {
		t.Fatalf("pattern = %+v", f)
	}
	s.Pattern = false
	if f := s.Forecast(pts, history(10), now); f.PatternUsed || f.Bytes > 22e6 {
		t.Fatalf("pattern off = %+v", f)
	}
}

func TestAllowedGB(t *testing.T) {
	tiers := IwinvVendor().OverageTiers
	// 10,000 KRW over a 5,000 KRW base buys 5,000/70 GB above 600.
	if got := AllowedGB(10000, 5000, 600, tiers); math.Abs(got-(600+5000.0/70)) > 1e-9 {
		t.Fatalf("allowed = %v", got)
	}
	// Through the first tier: 70,000 for 1,000 GB, then 60 per GB.
	if got := AllowedGB(80000, 0, 600, tiers); math.Abs(got-(600+1000+10000.0/60)) > 1e-9 {
		t.Fatalf("second tier = %v", got)
	}
	if got := AllowedGB(1000, 5000, 600, tiers); got != 600 {
		t.Fatalf("over by base = %v", got)
	}
	if !math.IsInf(AllowedGB(1000, 0, 600, nil), 1) {
		t.Fatal("free traffic must be unlimited")
	}
	if !ValidGuard(0, 0) || !ValidGuard(10, 20) || ValidGuard(10, 15) || ValidGuard(61, 200) || ValidGuard(-1, 0) {
		t.Fatal("ValidGuard")
	}
}
