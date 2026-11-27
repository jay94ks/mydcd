// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"fmt"
	"testing"
	"time"
)

func kstTime(y int, m time.Month, d, h int) time.Time {
	return time.Date(y, m, d, h, 0, 0, 0, billingZone)
}

func TestProjectBaseAndTraffic(t *testing.T) {
	f := Flavor{Full: Price{KRW: 30000, Per: "month"}, Partial: &Price{KRW: 50, Per: "hour"}}
	// November has 720 hours. Started at the month start; now = day 11 00:00 (240 h).
	in := CostInput{Now: kstTime(2026, 11, 11, 0), Flavor: f, IncludedGB: 100, IncludedPeriod: "MONTH", OverageKRWPerGB: 100,
		Traffic: Traffic{TotalMB: 60 * 1024}}
	e := Project(in)
	if e.BaseSoFarKRW != 12000 || e.BaseMonthKRW != 30000 {
		t.Fatalf("base = %d / %d", e.BaseSoFarKRW, e.BaseMonthKRW)
	}
	// 60 GB in 240 h → 180 GB by month end → 80 GB over at 100 KRW.
	if e.ProjectedGB < 179.99 || e.ProjectedGB > 180.01 || e.TrafficMonthKRW != 8000 || e.TrafficSoFarKRW != 0 {
		t.Fatalf("traffic = %+v", e)
	}
	if e.ProjectedKRW != 38000 || e.Judgeable || e.Over(37999) {
		t.Fatalf("judged without an hour of readings: %+v", e)
	}
	in.Recent = []Sample{{At: in.Now.Add(-50 * time.Minute), MB: 60*1024 - 256}, {At: in.Now, MB: 60 * 1024}}
	if e := Project(in); e.Judgeable {
		t.Fatal("50 minutes judged")
	}
	in.Recent[0].At = in.Now.Add(-time.Hour)
	e = Project(in)
	if e.ProjectedKRW != 38000 || !e.Judgeable || !e.Over(37999) || e.Over(38000) || e.Over(0) {
		t.Fatalf("projected = %d", e.ProjectedKRW)
	}
}

func TestProjectLateStartUsesPartial(t *testing.T) {
	f := Flavor{Full: Price{KRW: 30000, Per: "month"}, Partial: &Price{KRW: 50, Per: "hour"}}
	in := CostInput{Now: kstTime(2026, 11, 30, 0), Started: kstTime(2026, 11, 29, 0), Flavor: f}
	e := Project(in)
	if e.BaseSoFarKRW != 24*50 || e.BaseMonthKRW != 48*50 {
		t.Fatalf("base = %d / %d", e.BaseSoFarKRW, e.BaseMonthKRW)
	}
}

func TestProjectRecentBurst(t *testing.T) {
	now := kstTime(2026, 11, 11, 0)
	in := CostInput{Now: now, Flavor: Flavor{Full: Price{KRW: 10000, Per: "month"}}, OverageKRWPerGB: 10,
		Traffic: Traffic{TotalMB: 10 * 1024},
		Recent:  []Sample{{At: now.Add(-2 * time.Hour), MB: 10 * 1024}, {At: now, MB: 30 * 1024}}}
	e := Project(in)
	// 20 GB in the last 2 hours → 10 GB/h for the remaining 480 h.
	if !e.Judgeable || e.UsedGB != 30 || e.ProjectedGB < 4829 || e.ProjectedGB > 4831 {
		t.Fatalf("burst = %+v", e)
	}
}

func TestProjectDailyAllowanceAndNoPrice(t *testing.T) {
	in := CostInput{Now: kstTime(2026, 11, 16, 0), Flavor: Flavor{Full: Price{KRW: 1000, Per: "day"}}, IncludedGB: 10, IncludedPeriod: "DAY", OverageKRWPerGB: 1,
		Traffic: Traffic{TotalMB: 150 * 1024}}
	e := Project(in)
	if e.BaseMonthKRW != 30000 || e.TrafficMonthKRW != 0 {
		t.Fatalf("daily = %+v", e)
	}
	in.OverageKRWPerGB = 0
	in.Traffic.TotalMB = 1 << 30
	if e := Project(in); e.TrafficMonthKRW != 0 {
		t.Fatalf("free traffic billed: %+v", e)
	}
}

func TestProjectDailyAllowanceCeiling(t *testing.T) {
	// 20 GB/day, at most 600 GB a month: December has 31 days.
	in := CostInput{Now: kstTime(2026, 12, 2, 0), Flavor: Flavor{Full: Price{KRW: 1000, Per: "day"}}, IncludedGB: 20, IncludedPeriod: "DAY", IncludedMaxGB: 600,
		OverageKRWPerGB: 10, Traffic: Traffic{Year: 2026, Month: 12, DailyMB: map[int]int64{2: 5 * 1024}, TotalMB: 610 * 1024}}
	e := Project(in)
	if e.IncludedGB != 600 || e.TrafficSoFarKRW != 100 {
		t.Fatalf("ceiling = %+v", e)
	}
	// Started on the 22nd: ten days of allowance.
	in.Started = kstTime(2026, 12, 22, 0)
	in.Now = kstTime(2026, 12, 23, 0)
	in.Traffic.TotalMB = 210 * 1024
	if e := Project(in); e.IncludedGB != 200 || e.TrafficSoFarKRW != 100 {
		t.Fatalf("part month = %+v", e)
	}
	if got := TodayMB(in.Traffic, kstTime(2026, 12, 2, 9)); got != 5*1024 {
		t.Fatalf("today = %d", got)
	}
	if got := fmt.Sprint(LastDays(in.Traffic, kstTime(2026, 12, 2, 9), 7)); got != "[{2026-12-01 0} {2026-12-02 5120}]" {
		t.Fatalf("days = %s", got)
	}
	if got := TodayMB(in.Traffic, kstTime(2027, 1, 2, 9)); got != 0 {
		t.Fatalf("other month = %d", got)
	}
}

func TestMonthBoundsKST(t *testing.T) {
	// 2026-11-30 16:00 UTC is 2026-12-01 01:00 KST.
	s, e := MonthBounds(time.Date(2026, 11, 30, 16, 0, 0, 0, time.UTC))
	if s.Month() != time.December || e.Month() != time.January {
		t.Fatalf("bounds = %v %v", s, e)
	}
}

func TestOverageTiers(t *testing.T) {
	tiers := IwinvVendor().OverageTiers
	// 600 GB free, then 1,000 GB at 70 and 500 GB at 60.
	if got := overage(2100, 600, tiers); got != 1000*70+500*60 {
		t.Fatalf("two tiers = %d", got)
	}
	if got := overage(600+5000, 600, tiers); got != 1000*(70+60+50+40+30) {
		t.Fatalf("last tier = %d", got)
	}
	if got := overage(500, 600, tiers); got != 0 {
		t.Fatalf("within allowance = %d", got)
	}
	if got := overage(110, 100, []OverageTier{{KRWPerGB: 10}}); got != 100 {
		t.Fatalf("flat = %d", got)
	}
}
