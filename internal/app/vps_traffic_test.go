// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/vps"
)

func TestVPSTXRecorderBuckets(t *testing.T) {
	rec := newVPSTXRecorder(t.TempDir())
	at := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	if !rec.add("boot-1", 1000, at) { // the first reading is the baseline
		t.Fatal("first bucket not new")
	}
	rec.add("boot-1", 3000, at.Add(time.Minute))
	rec.add("boot-2", 500, at.Add(2*time.Minute)) // rebooted: 500 since boot
	if !rec.add("boot-2", 700, at.Add(6*time.Minute)) {
		t.Fatal("a new 5-minute bucket")
	}
	if err := rec.save(); err != nil {
		t.Fatal(err)
	}
	again := newVPSTXRecorder(rec.path[:len(rec.path)-len("/vps-traffic.json")])
	again.add("boot-2", 700, at.Add(7*time.Minute))
	h := again.history()
	if h.Start != at.Unix() || len(h.Bytes) != 2 || h.Bytes[0] != 2500 || h.Bytes[1] != 200 {
		t.Fatalf("history = %+v", h)
	}
	// A month and a day later the old buckets are gone.
	again.add("boot-2", 900, at.AddDate(0, 0, vps.GuardHistoryDays+2))
	if h := again.history(); len(h.Bytes) != 1 {
		t.Fatalf("old buckets kept: %d", len(h.Bytes))
	}
}

func TestVPSGuardJudges(t *testing.T) {
	w := newVPSWatch()
	now := time.Date(2026, 11, 27, 9, 0, 0, 0, time.UTC)
	server := control.VPSServer{Name: "edge-1", Phase: control.VPSRunning, CapKRW: 10000, CapAction: control.VPSCapStopAction}
	account := control.VPSAccount{Name: "main", Vendor: "iwinv"}
	if !w.observeTX("edge-1", "b", 0, now) {
		t.Fatal("a new server's history is asked for")
	}
	// The 10-minute watch read 600 GB used of a 600 GB allowance, base 5,000.
	w.setServer(control.VPSServerStatus{Name: "edge-1", UsedGB: 600, IncludedMonthGB: 600, BaseMonthKRW: 5000, SoFarKRW: 5000, ProjectedKRW: 5000})
	w.anchor("edge-1", 600)
	if _, _, ok := w.judgeGuard(server, account, now); ok {
		t.Fatal("judged before a window of counts")
	}
	// 5,000 KRW buys 71 GB at 70 KRW. Sending 1 GB a minute leaves room.
	for i := 1; i <= 10; i++ {
		w.observeTX("edge-1", "b", uint64(i)*1024*1e6, now.Add(time.Duration(i)*time.Minute))
	}
	_, g, ok := w.judgeGuard(server, account, now.Add(10*time.Minute))
	if !ok || g.Soon || g.RemainingGB < 60 || g.RemainingGB > 62 || g.ForecastGB < 20 || g.ForecastGB > 22 {
		t.Fatalf("1 GB/min = %+v", g)
	}
	// Ten more minutes at 3 GB a minute: 41 GB left, more expected in 21 minutes.
	for i := 11; i <= 20; i++ {
		w.observeTX("edge-1", "b", uint64(10+(i-10)*3)*1024*1e6, now.Add(time.Duration(i)*time.Minute))
	}
	_, g, ok = w.judgeGuard(server, account, now.Add(20*time.Minute))
	if !ok || !g.Soon || g.SoonAt == 0 {
		t.Fatalf("3 GB/min = %+v", g)
	}
	w.setGuard("edge-1", g, false)
	if st := w.status("n").Servers[0]; !st.Over || st.Guard == nil || !st.Guard.Soon {
		t.Fatalf("status = %+v", st)
	}
	// No cap: never soon.
	server.CapKRW = 0
	if _, g, _ := w.judgeGuard(server, account, now.Add(20*time.Minute)); !g.Unlimited || g.Soon {
		t.Fatalf("no cap = %+v", g)
	}
}
