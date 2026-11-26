// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"gopkg.in/yaml.v3"
)

func newOverrideFixture(t *testing.T) *deliveryFixture {
	t.Helper()
	return newTransitionFixture(t, true, false)
}

func appModeOverridePath() []string {
	return []string{"services", "web", "environment", "APP_MODE"}
}

func (f *deliveryFixture) currentTaskRefs(service string) []ObjectRef {
	f.f.t.Helper()
	key := ResourceKey("task", "tenant", "php-mysql", service)
	current := f.shared.Object(key)
	return []ObjectRef{{key, current.Revision, current.Generation}}
}

func (f *deliveryFixture) overrideMode(value string) {
	f.f.t.Helper()
	f.saveDelivery(f.d.PutOverride(f.d.Revision(), 0, f.f.c, f.ctx, "alice", appModeOverridePath(), goal(value), f.currentTaskRefs("web")))
}

func TestDeliveryAppOverrideMasksOneFieldAcrossSourceChanges(t *testing.T) {
	f := newOverrideFixture(t)
	source, running := bytes.Clone(f.d.d.Candidate.Artifact.Body), bytes.Clone(goal(f.d.d.Running))
	f.overrideMode("debug")
	if !bytes.Equal(source, f.d.d.Candidate.Artifact.Body) || !bytes.Equal(running, goal(f.d.d.Running)) {
		t.Fatal("field intent rewrote Git or accepted execution")
	}
	input, err := ParseApp(f.body)
	if err != nil {
		t.Fatal(err)
	}
	service := input.Services["web"]
	service.Environment["APP_MODE"], service.Environment["APP_OTHER"] = "production", "new-source-value"
	input.Services["web"] = service
	body, _ := yaml.Marshal(input)
	f.receive(body)
	effective := f.d.d.Candidate.Plan.Input.Services["web"].Environment
	if effective["APP_MODE"] != "debug" || effective["APP_OTHER"] != "new-source-value" {
		t.Fatal("override masked unrelated source fields", effective)
	}
	status, err := f.d.Status(f.f.c, f.ctx, f.now)
	if err != nil || status.Sync != "OutOfSync" || len(status.OverridePaths) != 1 {
		t.Fatal(status, err)
	}
	returned := f.d.Overrides()
	returned[0].Path[0], returned[0].Value[0] = "networks", '0'
	if f.d.Overrides()[0].Path[0] != "services" || string(f.d.Overrides()[0].Value) != `"debug"` {
		t.Fatal("caller changed committed override")
	}
}

func TestDeliveryAppOverrideRequiresCurrentOwnedTaskAndManager(t *testing.T) {
	f := newOverrideFixture(t)
	refs := f.currentTaskRefs("web")
	stale, generation := refs[0], refs[0]
	stale.Revision++
	generation.Generation++
	before := deliveryRaw(t, f.d)
	for _, anchors := range [][]ObjectRef{nil, {refs[0], refs[0]}, {stale}, {generation}, f.currentTaskRefs("db")} {
		if _, err := f.d.PutOverride(f.d.Revision(), 0, f.f.c, f.ctx, "alice", appModeOverridePath(), goal("debug"), anchors); err == nil {
			t.Fatal("missing, duplicate, foreign or stale Task accepted")
		}
	}
	member, _ := f.f.c.Membership("tenant", "alice")
	revoked, err := f.f.c.SetMembership("admin", member.Revision, access.Membership{Tenant: "tenant", User: "alice", Role: access.Manager, Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.PutOverride(f.d.Revision(), 0, revoked, f.ctx, "alice", appModeOverridePath(), goal("debug"), refs); err == nil {
		t.Fatal("revoked manager changed an app field")
	}
	if !bytes.Equal(before, deliveryRaw(t, f.d)) {
		t.Fatal("denied intent changed state")
	}
}

func TestDeliveryAppOverrideSnapshotRejectsMissingMaskAnchorsAndGeneration(t *testing.T) {
	f := newOverrideFixture(t)
	f.overrideMode("debug")
	raw := deliveryRaw(t, f.d)
	for _, change := range []func(*deliveryRecord){
		func(r *deliveryRecord) { r.Overrides = nil },
		func(r *deliveryRecord) { r.OverrideRevision = 0 },
		func(r *deliveryRecord) { r.Candidate.Overrides = nil },
		func(r *deliveryRecord) { r.Overrides[0].Anchors = nil },
		func(r *deliveryRecord) { r.Overrides[0].Anchors[0].Owner[0]++ },
		func(r *deliveryRecord) { r.Candidate.Plan.Input.Services["web"].Environment["APP_MODE"] = "tampered" },
	} {
		var record deliveryRecord
		if json.Unmarshal(raw, &record) != nil {
			t.Fatal("original snapshot")
		}
		change(&record)
		bad, _ := json.Marshal(record)
		if _, err := DecodeDelivery(bad); err == nil {
			t.Fatal("incomplete mask/anchor/source accepted")
		}
	}
}

func TestDeliveryAppOverrideUnknownCannotBeReplacedByFieldRelease(t *testing.T) {
	f := newOverrideFixture(t)
	f.overrideMode("debug")
	f.approve()
	f.beginTransition("second", DeliveryUpdate)
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	key := ResourceKey("task", "tenant", "php-mysql", "web")
	f.before(key)
	f.prepare(key)
	f.send(key)
	f.save(f.e.Unknown(f.e.Revision(), key))
	f.syncDelivery()
	before := deliveryRaw(t, f.d)
	if _, err := f.d.ReleaseOverride(f.d.Revision(), 1, f.f.c, f.ctx, "alice", appModeOverridePath()); err == nil {
		t.Fatal("field release replaced Unknown")
	}
	if !bytes.Equal(before, deliveryRaw(t, f.d)) {
		t.Fatal("rejected release changed original journal")
	}
}

func TestDeliveryAppOverrideValueBudgetAndExplicitResolverEmptiness(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"duplicate":1,"duplicate":2}`), []byte(strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17))} {
		if _, err := overrideValue(raw); err == nil {
			t.Fatal("duplicate key or excessive nesting accepted")
		}
	}
	f := newOverrideFixture(t)
	f.overrideMode("debug")
	input, err := ParseApp(f.body)
	if err != nil {
		t.Fatal(err)
	}
	service := input.Services["web"]
	service.DNS, service.DNSSearch = []string{}, []string{}
	input.Services["web"] = service
	effective, err := applyDeliveryOverrides(input, f.d.Overrides())
	if err != nil || effective.Services["web"].DNS == nil || effective.Services["web"].DNSSearch == nil {
		t.Fatal("projection erased explicit resolver emptiness", err)
	}
	plan, err := CompileApp(effective, f.f.c, f.ctx)
	if err != nil || plan.d.Input.Services["web"].DNS == nil || len(plan.d.Input.Services["web"].DNS) != 0 {
		t.Fatal("app planning replaced explicitly empty resolver", err)
	}
}
