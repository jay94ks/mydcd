// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

func completedRegisteredApp(t *testing.T) (*fixture, PlanningContext, Delivery, *executionFixture) {
	t.Helper()
	f, ctx, b, d := acceptedDeliveryAdapterFixture(t)
	e, _ := d.Inventory().Execution()
	shared, _ := state.New("user/original")
	x := &executionFixture{f: f, b: b, e: e, shared: shared, now: 100}
	for _, step := range b.Steps() {
		x.completeStep(step.Key)
	}
	x.save(x.e.Finish(x.e.Revision(), 100))
	i := d.Inventory()
	i, err := i.Advance(i.Revision(), x.e, x.shared)
	if err == nil {
		d, err = d.FollowInventory(d.Revision(), i)
	}
	if err != nil {
		t.Fatal(err)
	}
	for key, object := range x.shared.Objects("") {
		ctx.Current[key] = object
	}
	return f, ctx, d, x
}

func TestAppOverrideUsesExactOwnedTaskAndKeepsGitAndRunning(t *testing.T) {
	f, ctx, d, _ := completedRegisteredApp(t)
	path := []string{"services", "web", "environment", "APP_MODE"}
	key := ResourceKey("task", "tenant", d.Inventory().Scope().App, "web")
	current := ctx.Current[key]
	refs := []ObjectRef{{key, current.Revision, current.Generation}}
	body := bytes.Clone(d.d.Candidate.Artifact.Body)
	running := bytes.Clone(goal(d.d.Running))
	inventory, _ := d.Inventory().Encode()
	n, err := d.PutOverride(d.Revision(), 0, f.c, ctx, "alice", path, goal("debug"), refs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, n.d.Candidate.Artifact.Body) || !bytes.Equal(running, goal(n.d.Running)) || n.d.Candidate.Plan.Input.Services["web"].Environment["APP_MODE"] != "debug" {
		t.Fatal("field changed Git or accepted execution")
	}
	after, _ := n.Inventory().Encode()
	if !bytes.Equal(inventory, after) || ctx.Current[key] != current {
		t.Fatal("field intent performed a native effect")
	}
	raw, err := n.Encode()
	if err == nil {
		n, err = DecodeDelivery(raw)
	}
	if err != nil {
		t.Fatal("override did not survive snapshot", err)
	}
	if _, err := n.PutOverride(n.Revision(), 0, f.c, ctx, "alice", path, goal("another"), refs); err == nil {
		t.Fatal("field ownership revision ignored")
	}
	o := n.Overrides()[0]
	released, err := n.ReleaseOverride(n.Revision(), o.Revision, f.c, ctx, "alice", path)
	if err != nil || len(released.Overrides()) != 0 || released.d.Approval == nil || !bytes.Equal(body, released.d.Candidate.Artifact.Body) {
		t.Fatal("explicit release did not return only the field", err)
	}
	if _, exists := released.d.Candidate.Plan.Input.Services["web"].Environment["APP_MODE"]; exists {
		t.Fatal("returned field still masks Git")
	}
}

func TestAppOverrideRejectsManagementFieldsBadAnchorsAndInvalidValue(t *testing.T) {
	f, ctx, d, _ := completedRegisteredApp(t)
	key := ResourceKey("task", "tenant", d.Inventory().Scope().App, "web")
	object := ctx.Current[key]
	refs := []ObjectRef{{key, object.Revision, object.Generation}}
	before, _ := d.Encode()
	for _, path := range [][]string{
		{"networks", "app", "x-sfc", "mtu"},
		{"networks", "app", "x-sfc", "dns", "ttl_seconds"},
		{"services", "web", "x-sfc", "node"},
		{"services", "web", "volumes"}, {"services", "web", "secrets"},
		{"services", "web", "read_only"}, {"services", "web", "environment"},
		{"x-sfc", "delivery", "source", "credential_profile"},
	} {
		if AllowedAppOverride(path) {
			t.Fatal("non-app/whole-subtree field whitelisted", path)
		}
		if _, err := d.PutOverride(d.Revision(), 0, f.c, ctx, "alice", path, goal(60), refs); err == nil {
			t.Fatal("management field became an app override", path)
		}
	}
	for _, changed := range [][]ObjectRef{nil, {{key, object.Revision + 1, object.Generation}}, {{key, object.Revision, object.Generation + 1}}, {{ResourceKey("task", "other", d.Inventory().Scope().App, "web"), object.Revision, object.Generation}}} {
		if _, err := d.PutOverride(d.Revision(), 0, f.c, ctx, "alice", []string{"services", "web", "cpus"}, goal("0.1"), changed); err == nil {
			t.Fatal("foreign/stale/missing current anchor accepted")
		}
	}
	if _, err := d.PutOverride(d.Revision(), 0, f.c, ctx, "alice", []string{"services", "web", "cpus"}, goal("invalid"), refs); err == nil {
		t.Fatal("invalid field bypassed normal app parser")
	}
	after, _ := d.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("rejected intent changed source/ownership")
	}
}

func TestStoppedAppOverrideReleaseUsesCurrentCleanupWithoutRevivingSource(t *testing.T) {
	f, ctx, d, x := completedRegisteredApp(t)
	path := []string{"services", "web", "environment", "APP_MODE"}
	key := ResourceKey("task", "tenant", d.Inventory().Scope().App, "web")
	object := ctx.Current[key]
	d, err := d.PutOverride(d.Revision(), 0, f.c, ctx, "alice", path, goal("debug"), []ObjectRef{{key, object.Revision, object.Generation}})
	if err != nil {
		t.Fatal(err)
	}
	old := d.Overrides()[0]
	df := &deliveryFixture{executionFixture: x, d: d, ctx: ctx}
	df.beginTransition("stop", DeliveryDown)
	df.closeTargets()
	df.finishRetirement()
	df.continueTransition()
	m, _ := f.c.Membership("tenant", "alice")
	f.c, err = f.c.SetMembership("admin", m.Revision, access.Membership{Tenant: "tenant", User: "alice", Role: access.Manager, Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	d, err = df.d.ReleaseOverride(df.d.Revision(), old.Revision, f.c, df.ctx, "admin", path)
	if err != nil {
		t.Fatal("current administrator could not return stopped field", err)
	}
	if !d.Paused() || len(d.Overrides()) != 0 || d.d.Approval != nil {
		t.Fatal("cleanup restarted/reapproved source")
	}
	if _, active := d.Inventory().Execution(); active {
		t.Fatal("metadata release revived execution")
	}
	if _, err := d.Sync(d.Revision(), f.c, df.ctx, "admin", "revived", "user/original", 1, false); err == nil {
		t.Fatal("cleanup became a new source grant")
	}
	if raw, err := d.Encode(); err != nil {
		t.Fatal(err)
	} else if _, err := DecodeDelivery(raw); err != nil {
		t.Fatal("stale stopped candidate could not restore", err)
	}
}
