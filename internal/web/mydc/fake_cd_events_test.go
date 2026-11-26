// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// CD events, approve/reject with a signed reason, the per-app approver.
func TestCDEventsAndApproval(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	cd := func() AppCD {
		apps, _ := alice.Apps(ctx, "shop", "")
		for _, a := range apps.Items {
			if a.App == "php-shop" {
				return *a.CD
			}
		}
		t.Fatal("no php-shop")
		return AppCD{}
	}
	start, _ := seedEvents(alice, "shop", "")
	since := start.Next
	if len(start.Items) > 0 {
		since = start.Items[len(start.Items)-1].Cursor
	}
	events := func() []string {
		p, err := seedEvents(alice, "shop", since)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range p.Items {
			if strings.HasPrefix(e.Kind, "cd-") {
				s := e.Kind + ":" + e.CD.Commit
				if e.CD.Actor != "" {
					s += ":" + e.CD.Actor
				}
				if e.CD.Reason != "" {
					s += ":" + e.CD.Reason
				}
				out = append(out, s)
			}
			since = e.Cursor
		}
		return out
	}
	decide := func(c Conn, action, reason string) Result {
		t.Helper()
		cur := cd()
		op, err := c.PrepareReason(ctx, Change{Action: action, Expected: cur.Revision, Payload: mustPayload(t, CDDecision{Strict: true, Tenant: "shop", App: "php-shop", Candidate: cur.CandidateDigest, Target: cur.Target})}, rootFor(t, c, action), OperationReason{Reason: reason})
		if err != nil {
			return Result{Code: ResultInvalid}
		}
		res, err := c.Submit(ctx, op)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	grant := func(action, user string) Result {
		t.Helper()
		_, res := submit(t, alice, action, cd().Revision, CDApproverGrant{Tenant: "shop", App: "php-shop", User: user}, root(t, alice))
		return res
	}

	// Manual mode: a new commit → candidate-created, approval-required.
	doc := strings.Replace(phpShopYAML, "php-shop:1.4.2", "php-shop:1.5.0", 1)
	f.SetCDCandidate("shop", "php-shop", "c0ffee1", doc)
	if got := events(); !slices.Equal(got, []string{"cd-candidate-created:c0ffee1", "cd-approval-required:c0ffee1"}) {
		t.Fatalf("candidate events %v", got)
	}

	// bob (viewer) cannot approve until granted ApproveCD on php-shop.
	if res := decide(bob, ActionApproveAppCD, "웹훅 통과"); res.Code != ResultForbidden {
		t.Fatalf("ungranted %+v", res)
	}
	if res := grant(ActionGrantCDApprover, "u-bob"); res.Code != ResultApplied {
		t.Fatalf("grant %+v", res)
	}
	if who := cd().Approvers; !slices.Equal(who, []string{"u-bob"}) {
		t.Fatalf("approvers %v", who)
	}
	if res := grant(ActionGrantCDApprover, "u-bob"); res.Code != ResultConditionFailed {
		t.Fatalf("grant again %+v", res)
	}
	// The grant is approve/reject only: no pause, no sync, no other app.
	cur := cd()
	if _, res := submit(t, bob, ActionPauseAppCD, cur.Revision, control.AppCDChange{Tenant: "shop", App: "php-shop"}, rootFor(t, bob, ActionPauseAppCD)); res.Code != ResultForbidden {
		t.Fatalf("pause by approver %+v", res)
	}
	f.SetAppCD("shop", "shop-worker", &AppCD{Revision: 5, Mode: "manual", Running: "1", Candidate: "2"})
	if _, res := submit(t, bob, ActionApproveAppCD, 5, CDDecision{Tenant: "shop", App: "shop-worker", Candidate: candidateDigest("shop", "shop-worker", "2"), Target: [32]byte{1}}, rootFor(t, bob, ActionApproveAppCD)); res.Code != ResultForbidden {
		t.Fatalf("other app %+v", res)
	}
	if res := decide(bob, ActionApproveAppCD, strings.Repeat("가", 513)); res.Code != ResultInvalid {
		t.Fatalf("long reason %+v", res)
	}

	// Approve with a reason: approved, sync started, succeeded.
	if res := decide(bob, ActionApproveAppCD, "웹훅 통과"); res.Code != ResultApplied {
		t.Fatalf("approve %+v", res)
	}
	if got := events(); !slices.Equal(got, []string{"cd-approved:c0ffee1:bob:웹훅 통과", "cd-sync-started:c0ffee1:bob", "cd-sync-succeeded:c0ffee1:bob"}) {
		t.Fatalf("approve events %v", got)
	}
	if c := cd(); c.Running != "c0ffee1" {
		t.Fatalf("running %+v", c)
	}
	h, _ := bob.AppDeliveryHistory(ctx, "shop", "php-shop", "")
	if h.Items[0].Commit != "c0ffee1" || h.Items[0].Result != CDSucceeded || h.Items[0].Actor != "bob" || h.Items[0].Note != "웹훅 통과" {
		t.Fatalf("history %+v", h.Items[0])
	}

	// Reject: the same commit does not come back; replan does.
	f.SetCDCandidate("shop", "php-shop", "bad0001", doc)
	events()
	if res := decide(bob, ActionRejectAppCD, "점검 실패"); res.Code != ResultApplied {
		t.Fatalf("reject %+v", res)
	}
	if got := events(); !slices.Equal(got, []string{"cd-rejected:bad0001:bob:점검 실패"}) {
		t.Fatalf("reject events %v", got)
	}
	if c := cd(); c.Candidate != c.Running {
		t.Fatalf("rejected candidate stays %+v", c)
	}
	f.SetCDCandidate("shop", "php-shop", "bad0001", doc)
	if c := cd(); c.Candidate != "c0ffee1" || len(events()) != 0 {
		t.Fatalf("revived %+v", c)
	}
	if _, res := submit(t, bob, ActionReplanApp, cd().Revision, control.AppCDChange{Tenant: "shop", App: "php-shop"}, rootFor(t, bob, ActionReplanApp)); res.Code != ResultForbidden {
		t.Fatalf("replan by approver %+v", res)
	}
	if _, res := submit(t, alice, ActionReplanApp, cd().Revision, control.AppCDChange{Tenant: "shop", App: "php-shop"}, rootFor(t, alice, ActionReplanApp)); res.Code != ResultApplied {
		t.Fatalf("replan %+v", res)
	}
	if c := cd(); c.Candidate != "bad0001" {
		t.Fatalf("replan candidate %+v", c)
	}
	if got := events(); !slices.Equal(got, []string{"cd-candidate-created:bad0001", "cd-approval-required:bad0001"}) {
		t.Fatalf("replan events %v", got)
	}

	// Pause/resume, drift, rollback.
	cur = cd()
	if _, res := submit(t, alice, ActionPauseAppCD, cur.Revision, control.AppCDChange{Tenant: "shop", App: "php-shop"}, rootFor(t, alice, ActionPauseAppCD)); res.Code != ResultApplied {
		t.Fatalf("pause %+v", res)
	}
	if res := decide(bob, ActionApproveAppCD, ""); res.Code != ResultConditionFailed {
		t.Fatalf("approve paused %+v", res)
	}
	f.ReportCDDrift("shop", "php-shop")
	f.RollBackCD("shop", "php-shop", "a1b2c3d", "alice")
	if got := events(); !slices.Equal(got, []string{"cd-paused:c0ffee1:alice", "cd-drift-detected:c0ffee1", "cd-rolled-back:a1b2c3d:alice"}) {
		t.Fatalf("pause events %v", got)
	}

	// Revoke: bob is refused again.
	if res := grant(ActionDropCDApprover, "u-bob"); res.Code != ResultApplied {
		t.Fatalf("revoke %+v", res)
	}
	if res := decide(bob, ActionRejectAppCD, ""); res.Code != ResultForbidden {
		t.Fatalf("revoked %+v", res)
	}
}
