// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestBuildPurposeRequiresIndependentApprovalAndCannotReleaseAppUsage(t *testing.T) {
	f := makeFixture(t)
	app := web(f)
	app.Sources = []string{"runtime"}
	for _, target := range plan(t, f, app).Required {
		f = commit(t, f, signed(f, target))
	}
	build := app
	build.Purpose = PurposeImageBuild
	if _, _, err := f.a.Acquire(f.c, f.t, build, "same-consumer", 1, f.a.Revision(), 110); err == nil {
		t.Fatal("build borrowed app approval")
	}
	for _, target := range plan(t, f, build).Required {
		if target.Actions != ([2]string{"resolve", "build"}) {
			t.Fatal("wrong signed build actions")
		}
		a := signed(f, target)
		a.Payload.Target.ApprovalID = "build-" + target.Group
		a.Signature = ed25519.Sign(f.issuer, ApprovalBytes(a))
		f = commit(t, f, a)
	}
	f, appGrant := acquire(t, f, app, "same-consumer", 1)
	f, buildGrant := acquire(t, f, build, "same-consumer", 1)
	proof := useGone(f, buildGrant)
	if _, err := f.a.ReleaseUse(proof); err == nil {
		t.Fatal("purpose-free proof returned build grant")
	}
	proof.Purpose = PurposeImageBuild
	proof.Signature = ed25519.Sign(f.na, UseGoneBytes(proof))
	var err error
	f.a, err = f.a.ReleaseUse(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.a.Usage(appGrant); !ok {
		t.Fatal("build closure released app grant")
	}
	if _, ok := f.a.Usage(buildGrant); ok {
		t.Fatal("build grant remained")
	}
	if _, err := DecodeApprovals(encodedBook(t, f.a)); err != nil {
		t.Fatal("purpose lifetime restore", err)
	}
}

func TestRegistryPurposeCannotBorrowAppApprovalOrReleaseItsUsage(t *testing.T) {
	f := makeFixture(t)
	app := web(f)
	app.Sources = []string{"runtime"}
	registry := app
	registry.Purpose = PurposeRegistrySource
	appPlan := plan(t, f, app)
	for _, target := range appPlan.Required {
		f = commit(t, f, signed(f, target))
	}
	if _, _, err := f.a.Acquire(f.c, f.t, registry, "same-consumer", 1, f.a.Revision(), 110); err == nil {
		t.Fatal("registry borrowed app mount consent")
	}
	registryPlan := plan(t, f, registry)
	for _, target := range registryPlan.Required {
		if target.Purpose != PurposeRegistrySource || target.Actions != ([2]string{"resolve", "registry"}) {
			t.Fatal("source purpose absent from signed target")
		}
		approval := signed(f, target)
		approval.Payload.Target.ApprovalID = "registry-" + target.Group
		approval.Signature = ed25519.Sign(f.issuer, ApprovalBytes(approval))
		f = commit(t, f, approval)
	}
	f, appGrant := acquire(t, f, app, "same-consumer", 1)
	f, registryGrant := acquire(t, f, registry, "same-consumer", 1)
	if _, ok := f.a.Usage(appGrant); !ok {
		t.Fatal("purpose usage collision lost app")
	}
	if _, ok := f.a.Usage(registryGrant); !ok {
		t.Fatal("purpose usage collision lost registry")
	}
	encoded := encodedBook(t, f.a)
	var err error
	f.a, err = DecodeApprovals(encoded)
	if err != nil {
		t.Fatal("purpose checkpoint", err)
	}
	proof := useGone(f, registryGrant)
	if _, err = f.a.ReleaseUse(proof); err == nil {
		t.Fatal("purpose-free proof released a different use")
	}
	proof.Purpose = PurposeRegistrySource
	proof.Signature = ed25519.Sign(f.na, UseGoneBytes(proof))
	f.a, err = f.a.ReleaseUse(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.a.Usage(appGrant); !ok {
		t.Fatal("registry closure released app")
	}
	if _, ok := f.a.Usage(registryGrant); ok {
		t.Fatal("registry use remained")
	}
	bad := registry
	bad.Purpose = "unknown"
	if _, err = f.t.Plan(f.c, []Use{bad}); err == nil {
		t.Fatal("unknown purpose accepted")
	}
}

func TestEmptyPurposePreservesExistingSignedJSON(t *testing.T) {
	f := makeFixture(t)
	use := web(f)
	encoded, _ := json.Marshal(use)
	if bytes.Contains(encoded, []byte("Purpose")) {
		t.Fatal("legacy use bytes changed")
	}
	target := plan(t, f, use).Required[0]
	encoded, _ = json.Marshal(target)
	if bytes.Contains(encoded, []byte("purpose")) {
		t.Fatal("legacy target bytes changed")
	}
	encoded, _ = json.Marshal(UseGone{})
	if bytes.Contains(encoded, []byte("Purpose")) {
		t.Fatal("legacy closure bytes changed")
	}
}

// An sfev.sock approval is its own namespace: a file approval does not open
// the socket, the socket's grant keeps its own consumer and generation, and
// renewing it (release, then a new generation) leaves the file grant alone.
func TestSecretSocketPurposeIsSeparateAndRenewable(t *testing.T) {
	f := makeFixture(t)
	app := web(f)
	app.Sources = []string{"runtime"}
	for _, target := range plan(t, f, app).Required {
		f = commit(t, f, signed(f, target))
	}
	socket := app
	socket.Purpose = PurposeSecretSocket
	if _, _, err := f.a.Acquire(f.c, f.t, socket, "sfev-consumer", 1, f.a.Revision(), 110); err == nil {
		t.Fatal("socket borrowed the file approval")
	}
	for _, target := range plan(t, f, socket).Required {
		if target.Purpose != PurposeSecretSocket || target.Actions != ([2]string{"resolve", "socket"}) {
			t.Fatalf("socket target = %+v", target)
		}
		a := signed(f, target)
		a.Payload.Target.ApprovalID = "socket-" + target.Group
		a.Signature = ed25519.Sign(f.issuer, ApprovalBytes(a))
		f = commit(t, f, a)
	}
	f, appGrant := acquire(t, f, app, "app-consumer", 1)
	f, first := acquire(t, f, socket, "sfev-consumer", 1)
	proof := useGone(f, first)
	proof.Purpose = PurposeSecretSocket
	proof.Signature = ed25519.Sign(f.na, UseGoneBytes(proof))
	var err error
	if f.a, err = f.a.ReleaseUse(proof); err != nil {
		t.Fatal(err)
	}
	f, second := acquire(t, f, socket, "sfev-consumer", 2)
	if second.Generation != 2 {
		t.Fatalf("renewed grant = %+v", second)
	}
	if _, ok := f.a.Usage(appGrant); !ok {
		t.Fatal("socket renewal released the file grant")
	}
	if _, err := DecodeApprovals(encodedBook(t, f.a)); err != nil {
		t.Fatal(err)
	}
}

// One batch may hold a service's file use and its sfev.sock use: the same
// protected group is then two required targets, one per purpose.
func TestPlanSplitsTargetsByPurpose(t *testing.T) {
	f := makeFixture(t)
	app := web(f)
	app.Sources = []string{"runtime"}
	socket := app
	socket.Purpose = PurposeSecretSocket
	p, err := f.t.Plan(f.c, []Use{app, socket})
	if err != nil {
		t.Fatal(err)
	}
	purposes := map[string]int{}
	for _, target := range p.Required {
		purposes[target.Purpose]++
	}
	if purposes[""] == 0 || purposes[""] != purposes[PurposeSecretSocket] || len(p.Uses) != 2 {
		t.Fatalf("required by purpose = %v", purposes)
	}
	other := app
	other.App = "other-app"
	if _, err := f.t.Plan(f.c, []Use{app, other}); err == nil {
		t.Fatal("different bases planned together")
	}
}
