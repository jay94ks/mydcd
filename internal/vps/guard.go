// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"math"
	"slices"
	"time"
)

// The early traffic guard (devel/design/vps-nodes.md §6a): every VPS server
// measures its own outgoing bytes each minute, and the leader forecasts how
// much it sends over the next GuardHorizon from those readings, so a server
// is stopped at least 15 minutes before its traffic would cross the cap.

// GuardHorizon is 15 minutes of warning plus what stopping takes (the DNS
// wait of 5 minutes and about a minute to power off).
const GuardHorizon = 21 * time.Minute

// GuardStale is how long the leader waits for a reading before it assumes
// the server kept sending at its last rate.
const GuardStale = 2 * time.Minute

// Guard settings bounds and defaults (Jay 2026-11-27: window 5 minutes,
// long average considered too, both changeable).
const (
	DefaultGuardWindowMin  = 5
	DefaultGuardAverageMin = 60
	MaxGuardWindowMin      = 60
	MaxGuardAverageMin     = 1440
	// GuardHistoryDays is how much each server keeps for pattern forecasts.
	GuardHistoryDays = 31
	// GuardPatternMinDays: fewer recorded days and the pattern is not used.
	GuardPatternMinDays = 7
	// GuardBucket is the history's resolution.
	GuardBucket = 5 * time.Minute
)

// GuardSettings is one account's guard configuration.
type GuardSettings struct {
	WindowMin, AverageMin int
	Pattern               bool
}

// ValidGuard checks user-entered settings (0 = default).
func ValidGuard(windowMin, averageMin int) bool {
	w, a := guardDefaults(windowMin, averageMin)
	return windowMin >= 0 && averageMin >= 0 && w <= MaxGuardWindowMin && a <= MaxGuardAverageMin && a >= 2*w
}

func guardDefaults(windowMin, averageMin int) (int, int) {
	if windowMin == 0 {
		windowMin = DefaultGuardWindowMin
	}
	if averageMin == 0 {
		averageMin = DefaultGuardAverageMin
	}
	return windowMin, averageMin
}

// TXPoint is a server's counted bytes (monotonic, since it was first seen)
// at At.
type TXPoint struct {
	At    time.Time
	Bytes int64
}

// TXBucket is one GuardBucket of a server's history: bytes sent from Start.
type TXBucket struct {
	Start time.Time
	Bytes int64
}

// Forecast is what the guard expects a server to send over GuardHorizon.
type Forecast struct {
	Ready                        bool // a window of readings exists
	RateBps, PrevBps, AverageBps float64
	ShortBytes, AverageBytes     float64
	PatternBytes                 float64
	PatternDays                  int
	PatternUsed                  bool
	// Bytes is the amount judged: the short forecast counts half when it
	// is above the average one, never below the average, and the pattern
	// wins when it is larger. Unreported time since the last reading is
	// added at the last rate.
	Bytes float64
}

// Forecast forecasts from readings (oldest first) and history at now.
func (s GuardSettings) Forecast(points []TXPoint, history []TXBucket, now time.Time) Forecast {
	var f Forecast
	if len(points) < 2 {
		return f
	}
	wMin, aMin := guardDefaults(s.WindowMin, s.AverageMin)
	w, avg := time.Duration(wMin)*time.Minute, time.Duration(aMin)*time.Minute
	end := points[len(points)-1].At
	first := points[0].At
	if end.Sub(first) < w {
		return f
	}
	f.Ready = true
	last := points[len(points)-1].Bytes
	ws := w.Seconds()
	f.RateBps = float64(last-bytesAt(points, end.Add(-w))) / ws
	f.PrevBps = f.RateBps
	if end.Sub(first) >= 2*w {
		f.PrevBps = float64(bytesAt(points, end.Add(-w))-bytesAt(points, end.Add(-2*w))) / ws
	}
	span := min(avg, end.Sub(first))
	f.AverageBps = float64(last-bytesAt(points, end.Add(-span))) / span.Seconds()
	t := GuardHorizon.Seconds()
	f.ShortBytes = f.RateBps*t + max(0, f.RateBps-f.PrevBps)/ws*t*t/2
	f.AverageBytes = f.AverageBps * t
	f.Bytes = f.AverageBytes
	if f.ShortBytes > f.AverageBytes {
		f.Bytes = (f.ShortBytes + f.AverageBytes) / 2
	}
	if s.Pattern {
		f.PatternBytes, f.PatternDays, f.PatternUsed = pattern(history, now)
		if f.PatternUsed && f.PatternBytes > f.Bytes {
			f.Bytes = f.PatternBytes
		}
	}
	if gap := now.Sub(end); gap > 0 {
		f.Bytes += f.RateBps * gap.Seconds()
	}
	return f
}

// bytesAt is the counted bytes at t, interpolated between readings.
func bytesAt(p []TXPoint, t time.Time) int64 {
	i, _ := slices.BinarySearchFunc(p, t, func(x TXPoint, t time.Time) int { return x.At.Compare(t) })
	switch {
	case i == 0:
		return p[0].Bytes
	case i == len(p):
		return p[len(p)-1].Bytes
	case p[i].At.Equal(t):
		return p[i].Bytes
	}
	a, b := p[i-1], p[i]
	frac := t.Sub(a.At).Seconds() / b.At.Sub(a.At).Seconds()
	return a.Bytes + int64(frac*float64(b.Bytes-a.Bytes))
}

// pattern is the amount sent in the same clock window on past days: the
// 90th percentile (the third largest of 30), and the same weekday's when it
// has at least four days. It is not used before GuardPatternMinDays days
// are recorded.
func pattern(history []TXBucket, now time.Time) (float64, int, bool) {
	slots := map[int64]int64{} // bucket start (unix) → bytes
	days := map[string]bool{}
	for _, b := range history {
		slots[b.Start.Unix()] = b.Bytes
		days[b.Start.In(billingZone).Format("2006-01-02")] = true
	}
	delete(days, now.In(billingZone).Format("2006-01-02"))
	if len(days) < GuardPatternMinDays {
		return 0, len(days), false
	}
	var all, weekday []float64
	for d := 1; d <= GuardHistoryDays; d++ {
		from := now.AddDate(0, 0, -d)
		sum, ok := windowSum(slots, from, from.Add(GuardHorizon))
		if !ok {
			continue
		}
		all = append(all, sum)
		if d%7 == 0 {
			weekday = append(weekday, sum)
		}
	}
	if len(all) == 0 {
		return 0, len(days), false
	}
	out := percentile90(all)
	if len(weekday) >= 4 {
		out = max(out, percentile90(weekday))
	}
	return out, len(days), true
}

// windowSum adds the buckets over [from, to), counting a partly covered
// bucket in proportion; false when a bucket in it is missing.
func windowSum(slots map[int64]int64, from, to time.Time) (float64, bool) {
	sum := 0.0
	start := from.Truncate(GuardBucket)
	for b := start; b.Before(to); b = b.Add(GuardBucket) {
		n, ok := slots[b.Unix()]
		if !ok {
			return 0, false
		}
		lo, hi := maxTime(b, from), minTime(b.Add(GuardBucket), to)
		sum += float64(n) * hi.Sub(lo).Seconds() / GuardBucket.Seconds()
	}
	return sum, true
}

func percentile90(v []float64) float64 {
	slices.SortFunc(v, func(a, b float64) int { return -compareFloat(a, b) })
	i := int(math.Ceil(float64(len(v))*0.1)) - 1
	return v[max(0, i)]
}

func compareFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// AllowedGB is the month's traffic the cap allows: the allowance plus what
// the money left after fixedKRW buys at the overage price. +Inf when
// traffic above the allowance is free.
func AllowedGB(capKRW, fixedKRW int64, includedGB float64, tiers []OverageTier) float64 {
	if len(tiers) == 0 {
		return math.Inf(1)
	}
	budget := float64(capKRW - fixedKRW)
	if budget <= 0 {
		return includedGB
	}
	gb, from := 0.0, 0.0
	for _, t := range tiers {
		if t.KRWPerGB <= 0 {
			return math.Inf(1)
		}
		width := math.Inf(1)
		if t.UpToGB > 0 {
			width = float64(t.UpToGB) - from
		}
		cost := width * float64(t.KRWPerGB)
		if budget < cost {
			return includedGB + gb + budget/float64(t.KRWPerGB)
		}
		budget -= cost
		gb += width
		from = float64(t.UpToGB)
	}
	return includedGB + gb
}

// GB converts counted bytes to the vendor's GB (decimal MB / 1024, as the
// vendor reports MB): a little more than binary GB, the safe side.
func GB(bytes float64) float64 { return bytes / 1e6 / 1024 }
