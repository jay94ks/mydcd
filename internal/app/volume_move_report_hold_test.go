// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

func TestRejectedMoveReportBacksOff(t *testing.T) {
	r := &Runtime{}
	now := time.Unix(1000, 0)
	rejected := moveReportRejected{"activate-app", state.LedgerFull}
	r.holdReport("m", rejected, now)
	if !r.reportHeld("m", now.Add(moveReportHoldMin-time.Second)) || r.reportHeld("m", now.Add(moveReportHoldMin)) {
		t.Fatal("first hold is not the minimum")
	}
	for i := 0; i < 10; i++ {
		r.holdReport("m", rejected, now)
	}
	if !r.reportHeld("m", now.Add(moveReportHoldMax-time.Second)) || r.reportHeld("m", now.Add(moveReportHoldMax)) {
		t.Fatal("hold not capped")
	}
	r.holdReport("m", errors.New("transport"), now)
	if !r.reportHeld("m", now.Add(moveReportHoldMax-time.Second)) {
		t.Fatal("a transport failure reset the hold")
	}
	r.holdReport("m", nil, now)
	if r.reportHeld("m", now) {
		t.Fatal("an applied report kept the hold")
	}
}

func TestAppProgressHoldKeySeparatesStreams(t *testing.T) {
	a := control.AppProgress{Tenant: "t", App: "web", Action: "finish"}
	b := a
	b.App = "db"
	ka, holdA := appProgressHoldKey(a)
	kb, _ := appProgressHoldKey(b)
	if ka == kb || !holdA {
		t.Fatal("two apps share one hold, or finish is not held")
	}
	// An observation is a new owner fact: a rejected one must not hold back
	// the next, different fact for the same step.
	o := control.AppProgress{Tenant: "t", App: "web", Action: "observe", Key: "workload/task/x", Observation: &deployment.Observation{Key: "workload/task/x"}}
	if _, held := appProgressHoldKey(o); held {
		t.Fatal("an observe report is held")
	}
}
