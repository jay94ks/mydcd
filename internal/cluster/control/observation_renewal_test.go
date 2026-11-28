// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

// expireAll commits expire-observation for every live stage observation,
// as the leader does once owners stop renewing them over SFCP
// (devel/refactor/14-raft-liveness.md). reporter must be a member key.
func expireAll(t *testing.T, p Policy, s state.State, reporter ed25519.PrivateKey, at uint64) state.State {
	t.Helper()
	for n := 0; ; n++ {
		a, err := p.Apps(s)
		if err != nil {
			t.Fatal(err)
		}
		var report *AppProgress
		for _, app := range a.Records() {
			e, ok := a.Execution(app.Tenant, app.App)
			if !ok {
				continue
			}
			for _, step := range e.Steps() {
				stage, _ := e.Stage(step.Key)
				if o := stage.Observation; o != nil && !o.Expired {
					report = &AppProgress{Schema: 1, Cluster: p.Cluster, Reporter: [32]byte(reporter.Public().(ed25519.PublicKey)), Tenant: app.Tenant, App: app.App, Operation: app.Operation.ID, Key: step.Key, Action: "expire-observation", Expected: app.Revision, At: at, Epoch: s.ModuleEpoch(), RootRevision: s.Object(AppsKey).Revision, RequestID: fmt.Sprintf("expire-%d-%d", at, n), ExpireSequence: o.Sequence, Stage: e.StageDigest(step.Key)}
					break
				}
			}
			if report != nil {
				break
			}
		}
		if report == nil {
			return s
		}
		report.Signature = ed25519.Sign(reporter, AppProgressBytes(*report))
		cmd, err := report.Command()
		if err != nil {
			t.Fatal(err)
		}
		var result state.Result
		s, result, err = state.ApplyTransactional(s, s.Index()+1, cmd, p.ValidateManaged, p.Reduce, p.AdmitModule, p.AdmitAppMutation, p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal("expire observation", report.Key, result, err)
		}
	}
}

// The leader admits a SFCP renewal of an unchanged signed fact without any
// Raft write, and refuses changed facts and expired observations.
func TestObservationRenewalStaysOutOfRaft(t *testing.T) {
	f, o, _ := observedTaskFixture(t, "local")
	apps, _ := f.p.Apps(f.s)
	i, _ := apps.Inventory("tenant", "source-app")
	execution, _ := apps.Execution("tenant", "source-app")
	report := func(obs deployment.Observation) AppProgress {
		obs.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(obs))
		r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "source-app", Operation: execution.ActiveOperation(), Key: obs.Key, Action: "observe", Observation: &obs, Expected: i.Revision(), At: obs.At, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "renew"}
		r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
		return r
	}
	renewal := o
	renewal.Sequence++
	renewal.At += 5
	before := f.s.Index()
	base, err := f.p.CheckObservationRenewal(f.s, report(renewal), renewal.At)
	if err != nil || base != o.Sequence || f.s.Index() != before {
		t.Fatal("renewal of an unchanged fact refused", base, err)
	}
	changed := renewal
	changed.Healthy = !changed.Healthy
	if _, err := f.p.CheckObservationRenewal(f.s, report(changed), changed.At); err == nil {
		t.Fatal("changed fact admitted as a renewal")
	}
	stale := expireAll(t, f.p, f.s, f.node, o.At+AppObservationMaxAge+1)
	if _, err := f.p.CheckObservationRenewal(stale, report(renewal), renewal.At); err == nil {
		t.Fatal("expired observation renewed without a Raft fact")
	}
	if apps, _ := f.p.Apps(stale); apps.entries[appKey("tenant", "source-app")].Inventory.Revision() == i.Revision() {
		t.Fatal("expiry did not record one inventory change")
	}
}

// Health follows the leader's recorded expiry, not the reader's clock: an
// owner that keeps renewing stays live however old its fact is, and once the
// leader expires the unrenewed observations a historical success is Unknown.
func TestObservedHealthIsUnknownOnlyAfterRecordedExpiry(t *testing.T) {
	f, o, _ := observedTaskFixture(t, "local")
	health := func(s state.State, now uint64) string {
		t.Helper()
		apps, err := f.p.Apps(s)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := f.p.Catalog(s)
		if err != nil {
			t.Fatal(err)
		}
		rows, _, err := apps.ObservedPage(catalog, "admin", "tenant", "", now)
		for _, row := range rows {
			if row.App == "source-app" {
				return row.Health
			}
		}
		t.Fatal("source-app missing from observed page", rows, err)
		return ""
	}
	live := health(f.s, o.At)
	if live == "Unknown" {
		t.Fatal("fixture has no live owner evidence")
	}
	if late := health(f.s, o.At+AppObservationLinkedMaxAge+1); late != live {
		t.Fatal("reader's clock alone changed health", live, late)
	}
	expired := expireAll(t, f.p, f.s, f.node, o.At+AppObservationMaxAge+1)
	if got := health(expired, o.At+AppObservationMaxAge+1); got != "Unknown" {
		t.Fatal("expired owner evidence kept its health", got)
	}
}
