// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/vps"
)

type fakeWatchProvider struct {
	vps.ManagedProvider
	trafficMB   int64
	trafficErr  error
	flavorReads int
}

func (f *fakeWatchProvider) Instance(context.Context, string) (vps.Instance, error) {
	return vps.Instance{ID: "i-1", Started: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), IncludedGB: 100, TrafficPeriod: "MONTH"}, nil
}

func (f *fakeWatchProvider) Flavor(context.Context, string) (vps.Flavor, error) {
	f.flavorReads++
	return vps.Flavor{ID: "f", Full: vps.Price{KRW: 10000, Per: "month"}}, nil
}

func (f *fakeWatchProvider) MonthTraffic(_ context.Context, _ string, year, month int) (vps.Traffic, error) {
	return vps.Traffic{Year: year, Month: month, TotalMB: f.trafficMB}, f.trafficErr
}

func TestVPSWatchJudgesOnlyAfterAnHour(t *testing.T) {
	w := newVPSWatch()
	p := &fakeWatchProvider{}
	server := control.VPSServer{Name: "edge-1", InstanceID: "i-1", Flavor: "f", CapKRW: 20000}
	now := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	if !w.due(now) || w.due(now.Add(time.Minute)) {
		t.Fatal("rounds are not 10 minutes apart")
	}
	// 1 GB every 10 minutes is about 3 TB by the end of the month: far over
	// 100 GB included at 10 KRW/GB.
	var st control.VPSServerStatus
	for i := 0; i <= 6; i++ {
		at := now.Add(time.Duration(i) * vpsWatchEvery)
		p.trafficMB = int64(50*1024 + i*1024)
		reading, err := w.readVPSServer(context.Background(), p, "acct", server, at)
		if err != nil {
			t.Fatal(err)
		}
		st, _ = w.project(server, control.VPSAccount{OverageKRWPerGB: 10}, reading, at)
		if i < 6 && (st.Judgeable || st.Over) {
			t.Fatalf("judged before an hour of readings: %d %+v", i, st)
		}
		if i > 0 && st.RecentMB != 1024 {
			t.Fatalf("recent = %d", st.RecentMB)
		}
	}
	if !st.Judgeable || !st.Over || st.ProjectedKRW <= server.CapKRW || st.SoFarKRW > server.CapKRW || st.IncludedGB != 100 || st.IncludedPeriod != "MONTH" || st.IncludedMonthGB != 100 {
		t.Fatalf("after an hour: %+v", st)
	}
	if p.flavorReads != 1 {
		t.Fatal("flavor read every round", p.flavorReads)
	}
	// A new month starts the readings again.
	next := time.Date(2026, 12, 1, 0, 30, 0, 0, time.FixedZone("KST", 9*3600))
	if !w.due(next) || len(w.samples) != 0 {
		t.Fatal("samples kept across the month")
	}
}

func TestVPSWatchChargeSoFarStopsAtOnce(t *testing.T) {
	w := newVPSWatch()
	p := &fakeWatchProvider{trafficMB: 3000 * 1024}
	server := control.VPSServer{Name: "edge-1", InstanceID: "i-1", Flavor: "f", CapKRW: 20000}
	now := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	reading, err := w.readVPSServer(context.Background(), p, "acct", server, now)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := w.project(server, control.VPSAccount{OverageKRWPerGB: 10}, reading, now); st.Judgeable || !st.Over {
		t.Fatalf("a charge already over the cap waits: %+v", st)
	}
}

func TestVPSWatchKeepsNumbersOnAFailedRead(t *testing.T) {
	w := newVPSWatch()
	w.setServer(control.VPSServerStatus{Name: "edge-1", SoFarKRW: 5})
	w.failServer("edge-1", vpsFailureCode(&vps.Error{Kind: vps.KindTransport}), time.Unix(100, 0))
	st := w.status("node-a")
	if len(st.Servers) != 1 || st.Servers[0].SoFarKRW != 5 || st.Servers[0].Failure != "PROVIDER_UNREACHABLE" || st.Leader != "node-a" {
		t.Fatalf("%+v", st)
	}
	w.keep(map[string]bool{}, map[string]bool{}, map[string]bool{})
	if len(w.status("node-a").Servers) != 0 {
		t.Fatal("deleted server kept")
	}
}

func TestVPSWatchNoTrafficYet(t *testing.T) {
	w := newVPSWatch()
	p := &fakeWatchProvider{trafficErr: &vps.Error{Kind: vps.KindEmpty}}
	server := control.VPSServer{Name: "edge-1", InstanceID: "i-1", Flavor: "f", CapKRW: 20000}
	if _, err := w.readVPSServer(context.Background(), p, "acct", server, time.Now()); err != nil {
		t.Fatal("empty traffic is a failure", err)
	}
}
