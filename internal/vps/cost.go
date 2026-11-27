// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"math"
	"time"
)

// Billing months follow Korean time, as iwinv bills.
var billingZone = time.FixedZone("KST", 9*3600)

// Sample is one traffic reading: the month's cumulative MB at At.
type Sample struct {
	At time.Time
	MB int64
}

// CostInput is everything Project needs. It does no I/O.
type CostInput struct {
	Now     time.Time
	Started time.Time // when the instance's service started (zero = unknown)
	Flavor  Flavor
	// IncludedGB per IncludedPeriod ("MONTH" or "DAY") is free traffic.
	// A "DAY" allowance adds up over the days in service, to at most
	// IncludedMaxGB a month (0 = no ceiling).
	IncludedGB     int64
	IncludedPeriod string
	IncludedMaxGB  int64
	// OverageKRWPerGB is the user-entered price of traffic above the
	// allowance (the vendor API does not report it). 0 = traffic is free.
	OverageKRWPerGB int64
	// OverageTiers, when the vendor publishes them, replace
	// OverageKRWPerGB: each tier's price applies to the GB above the
	// allowance that fall in it.
	OverageTiers []OverageTier
	Traffic      Traffic
	// Recent are this month's readings, oldest first (the 10-minute polls).
	Recent []Sample
}

// Estimate is this month's cost of one VPS node.
type Estimate struct {
	MonthStart, MonthEnd time.Time
	UsedGB, ProjectedGB  float64
	// IncludedGB is the month's free traffic the overage is counted from.
	IncludedGB      float64
	BaseSoFarKRW    int64
	BaseMonthKRW    int64
	TrafficSoFarKRW int64
	TrafficMonthKRW int64
	SoFarKRW        int64 // BaseSoFar + TrafficSoFar
	ProjectedKRW    int64 // BaseMonth + TrafficMonth
	// Judgeable is true once the readings cover at least MinJudgeSpan; until
	// then the projection is shown but never stops a server.
	Judgeable bool
}

// MinJudgeSpan is how long the readings must cover before a projection can
// stop a server (Jay 2026-11-27: at least one hour, six 10-minute polls).
const MinJudgeSpan = time.Hour

// Over reports whether the month will exceed capKRW (0 = no cap): the
// charge so far already does, or the projection does and is Judgeable.
func (e Estimate) Over(capKRW int64) bool {
	return capKRW > 0 && (e.SoFarKRW > capKRW || e.Judgeable && e.ProjectedKRW > capKRW)
}

// TodayMB is the use on now's day (KST) when t is now's month, else 0.
func TodayMB(t Traffic, now time.Time) int64 {
	k := now.In(billingZone)
	if t.Year != k.Year() || t.Month != int(k.Month()) {
		return 0
	}
	return t.DailyMB[k.Day()]
}

// TrafficDay is one day's use.
type TrafficDay struct {
	Day string // YYYY-MM-DD (KST)
	MB  int64
}

// LastDays is the use of the last n days up to now's day (KST), oldest
// first, within t's month; days without a record count as 0.
func LastDays(t Traffic, now time.Time, n int) []TrafficDay {
	k := now.In(billingZone)
	if t.Year != k.Year() || t.Month != int(k.Month()) {
		return nil
	}
	from := max(1, k.Day()-n+1)
	out := make([]TrafficDay, 0, k.Day()-from+1)
	for d := from; d <= k.Day(); d++ {
		day := time.Date(k.Year(), k.Month(), d, 0, 0, 0, 0, billingZone)
		out = append(out, TrafficDay{Day: day.Format("2006-01-02"), MB: t.DailyMB[d]})
	}
	return out
}

// MonthOf names the billing month containing t ("2006-01", KST).
func MonthOf(t time.Time) string { return t.In(billingZone).Format("2006-01") }

// MonthBounds returns the billing month containing t.
func MonthBounds(t time.Time) (time.Time, time.Time) {
	k := t.In(billingZone)
	start := time.Date(k.Year(), k.Month(), 1, 0, 0, 0, 0, billingZone)
	return start, start.AddDate(0, 1, 0)
}

// Project projects the month's cost. Base price: the cheaper of the
// fixed-period price and the partial (hourly/daily) price over the hours the
// instance is in service this month; powered-off hours still count, because
// the vendor keeps billing a stopped instance. Traffic: the month's
// cumulative use plus the faster of the month's average rate and the rate
// over the recent readings, carried to the end of the month.
func Project(in CostInput) Estimate {
	start, end := MonthBounds(in.Now)
	e := Estimate{MonthStart: start, MonthEnd: end}
	now := in.Now
	if now.After(end) {
		now = end
	}
	from := start
	if in.Started.After(from) {
		from = in.Started
	}
	if from.After(now) {
		from = now
	}
	monthHours := end.Sub(start).Hours()
	elapsed := now.Sub(from).Hours()
	service := end.Sub(from).Hours()
	e.BaseSoFarKRW = basePrice(in.Flavor, elapsed, monthHours)
	e.BaseMonthKRW = basePrice(in.Flavor, service, monthHours)

	used := float64(in.Traffic.TotalMB)
	if n := len(in.Recent); n > 0 && float64(in.Recent[n-1].MB) > used {
		used = float64(in.Recent[n-1].MB)
	}
	rate := 0.0 // MB per hour
	if elapsed >= 1 {
		rate = used / elapsed
	}
	if r := recentRate(in.Recent, in.Now); r > rate {
		rate = r
	}
	remaining := end.Sub(now).Hours()
	projected := used + rate*remaining
	e.UsedGB = used / 1024
	e.ProjectedGB = projected / 1024

	included := float64(in.IncludedGB)
	if in.IncludedPeriod == "DAY" {
		included *= math.Ceil(service/24 - 1e-9)
	}
	if in.IncludedMaxGB > 0 && included > float64(in.IncludedMaxGB) {
		included = float64(in.IncludedMaxGB)
	}
	e.IncludedGB = included
	tiers := in.OverageTiers
	if len(tiers) == 0 && in.OverageKRWPerGB > 0 {
		tiers = []OverageTier{{KRWPerGB: in.OverageKRWPerGB}}
	}
	e.TrafficSoFarKRW = overage(e.UsedGB, included, tiers)
	e.TrafficMonthKRW = overage(e.ProjectedGB, included, tiers)
	if n := len(in.Recent); n > 1 && in.Recent[n-1].At.Sub(in.Recent[0].At) >= MinJudgeSpan {
		e.Judgeable = true
	}
	e.SoFarKRW = e.BaseSoFarKRW + e.TrafficSoFarKRW
	e.ProjectedKRW = e.BaseMonthKRW + e.TrafficMonthKRW
	return e
}

// basePrice is the charge for hours of service in a month of monthHours.
func basePrice(f Flavor, hours, monthHours float64) int64 {
	if hours <= 0 {
		return 0
	}
	full := periodPrice(f.Full, hours, monthHours)
	if f.Partial != nil {
		if p := periodPrice(*f.Partial, hours, monthHours); p >= 0 && (full < 0 || p < full) {
			return p
		}
	}
	if full < 0 {
		return 0
	}
	return full
}

// periodPrice is p over hours, rounded up to whole periods; -1 when the
// unit is unknown.
func periodPrice(p Price, hours, monthHours float64) int64 {
	if p.KRW <= 0 {
		return -1
	}
	switch p.Per {
	case "month":
		return p.KRW * int64(math.Ceil(hours/monthHours-1e-9))
	case "day":
		return p.KRW * int64(math.Ceil(hours/24-1e-9))
	case "hour":
		return p.KRW * int64(math.Ceil(hours-1e-9))
	}
	return -1
}

// recentRate is MB per hour between the oldest reading of the last six
// hours and the newest one, needing at least 30 minutes between them.
func recentRate(s []Sample, now time.Time) float64 {
	if len(s) < 2 {
		return 0
	}
	last := s[len(s)-1]
	first := -1
	for i, x := range s {
		if now.Sub(x.At) <= 6*time.Hour {
			first = i
			break
		}
	}
	if first < 0 || first == len(s)-1 {
		return 0
	}
	span := last.At.Sub(s[first].At).Hours()
	grow := float64(last.MB - s[first].MB)
	if span < 0.5 || grow <= 0 {
		return 0
	}
	return grow / span
}

// OverageTier prices the extra GB up to UpToGB (counted from the
// allowance; 0 = no upper end, the last tier).
type OverageTier struct {
	UpToGB   int64
	KRWPerGB int64
}

func overage(gb, included float64, tiers []OverageTier) int64 {
	extra := gb - included
	if extra <= 0 {
		return 0
	}
	sum, from := 0.0, 0.0
	for _, t := range tiers {
		to := float64(t.UpToGB)
		if t.UpToGB <= 0 || to > extra {
			to = extra
		}
		if to > from {
			sum += (to - from) * float64(t.KRWPerGB)
			from = to
		}
		if from >= extra {
			break
		}
	}
	return int64(math.Ceil(sum - 1e-9))
}
