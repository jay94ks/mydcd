// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// f4e1a7e: a build whose context mounts a Secret of a protected Group needs
// a compose approval of the begin-image-build original before it is sent.
func TestBuildSecretGroupApproval(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	f.SetGroupPassword("shop", "shop-db", "open-sesame") // worker mounts shop/mysql (Group shop-db)
	vs, _ := alice.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "versions", ID: "worker"}, "")
	v2 := vs.Versions[len(vs.Versions)-1].ID
	original := func(id string) (SignedOp, UserOperation) {
		t.Helper()
		plan, err := alice.PlanImageBuildJob(ctx, "shop", control.ImageBuildJobQuery{ID: id, Context: "worker", Version: v2})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := alice.Prepare(ctx, Change{Action: ActionBeginImageBuild, Payload: mustPayload(t, plan.Change)}, rootFor(t, alice, ActionBeginImageBuild))
		if err != nil {
			t.Fatal(err)
		}
		op, err := DecodeOperation(signed)
		if err != nil {
			t.Fatal(err)
		}
		return signed, op
	}

	// Unapproved: refused (Invalid), as begin-app.
	if _, res := submit(t, alice, ActionBeginImageBuild, 0, mustPlan(t, alice, "b-no", v2), rootFor(t, alice, ActionBeginImageBuild)); res.Code != ResultInvalid {
		t.Fatalf("unapproved build %v", res.Code)
	}

	signed, origin := original("b-ok")
	req := VaultApprovalPlanRequest{Realm: "shop", ID: "compose/" + origin.RequestID, Origin: &origin}
	if _, err := bob.PlanVaultApprovals(ctx, "shop", req); err == nil {
		t.Fatal("bob planned alice's build")
	}
	plan, err := alice.PlanVaultApprovals(ctx, "shop", req)
	if err != nil || len(plan.Targets) != 1 || plan.Targets[0].Existing != nil {
		t.Fatalf("plan %+v %v", plan, err)
	}
	tg := plan.Targets[0].Target
	if tg.Purpose != secrets.PurposeImageBuild || tg.Group != "shop-db" || tg.App != control.ImageBuildSecretScope("shop", "worker") || tg.Deployment != "b-ok" ||
		len(tg.Services) != 1 || tg.Services[0] != "builder" || len(tg.Nodes) != 1 || tg.Nodes[0].ID != "node-a" || tg.Actions != [2]string{"resolve", "build"} || tg.User != "u-alice" {
		t.Fatalf("target %+v", tg)
	}
	if code, _ := alice.ApproveVault(ctx, "shop", *plan.Targets[0].Approver, VaultApprove{Target: tg, Password: []byte("wrong"), Origin: &origin}); code != "denied" {
		t.Fatalf("wrong password %s", code)
	}
	if code, err := alice.ApproveVault(ctx, "shop", *plan.Targets[0].Approver, VaultApprove{Target: tg, Password: []byte("open-sesame"), Origin: &origin}); err != nil || code != "ok" {
		t.Fatalf("approve %s %v", code, err)
	}
	if !f.GroupApproved("shop", "shop-db", origin.RequestID) {
		t.Fatal("approval not kept")
	}
	if again, _ := alice.PlanVaultApprovals(ctx, "shop", req); again.Targets[0].Existing == nil {
		t.Fatal("no Existing after approve")
	}
	if res, err := alice.Submit(ctx, signed); err != nil || res.Code != ResultApplied {
		t.Fatalf("approved build %v %v", res.Code, err)
	}
	// An unprotected Group needs nothing.
	f.SetGroupPassword("shop", "shop-db", "")
	if _, res := submit(t, alice, ActionBeginImageBuild, 0, mustPlan(t, alice, "b-open", v2), rootFor(t, alice, ActionBeginImageBuild)); res.Code != ResultApplied {
		t.Fatalf("open build %v", res.Code)
	}
}

func mustPlan(t *testing.T, c Conn, id string, version [32]byte) control.ImageBuildJobStart {
	t.Helper()
	p, err := c.PlanImageBuildJob(ctx, "shop", control.ImageBuildJobQuery{ID: id, Context: "worker", Version: version})
	if err != nil {
		t.Fatal(err)
	}
	return p.Change
}
