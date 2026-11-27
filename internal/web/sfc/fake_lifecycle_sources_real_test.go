// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// REQ-39/40 in sfcd's real shape: stage (ZIPs first, then source) with the
// caller's original upload ID, recover, put-lifecycle-script with the fact,
// and lifecycle-source pages. Answers pass userauth's own checks.
func TestLifecycleSourcesReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	desc := func(src []byte, mods ...checker.ModulePin) checker.SourceDescriptor {
		return checker.SourceDescriptor{Tenant: "shop", Digest: sha256.Sum256(src), Length: uint64(len(src)), SDK: contract.Schema, Modules: mods}
	}
	upload := func(b byte) (u [32]byte) { u[0], u[31] = b, 1; return }

	// A big source (two pages) that type checks.
	src := []byte(fixtureCheckSource + "\n// " + strings.Repeat("x", 30<<10) + "\n")
	d := desc(src)
	if _, err := bob.LifecycleSourceStage(ctx, "", d, upload(1), src); err == nil {
		t.Fatal("viewer staged")
	}
	if _, err := alice.LifecycleSourceStage(ctx, "", d, [32]byte{}, src); err == nil {
		t.Fatal("zero upload")
	}
	if _, err := alice.LifecycleSourceStage(ctx, "", d, upload(1), src[1:]); err == nil {
		t.Fatal("bytes not matching the descriptor")
	}
	r, err := alice.LifecycleSourceStage(ctx, "", d, upload(1), src)
	if err != nil || !r.Valid(false) || r.Source == nil || r.Node != "node-a" || r.Source.Cluster != f.w.cluster {
		t.Fatalf("stage %+v %v", r, err)
	}
	if again, err := alice.LifecycleSourceStage(ctx, "", d, upload(1), src); err != nil || string(again.Source.Signature) != string(r.Source.Signature) {
		t.Fatalf("same upload again %+v %v", again, err)
	}
	other := []byte(fixtureCheckSource + "\n// other\n")
	if _, err := alice.LifecycleSourceStage(ctx, "node-a", desc(other), upload(1), other); err == nil {
		t.Fatal("upload reused for other bytes")
	}
	if rec, err := alice.LifecycleSourceRecover(ctx, "node-a", d, upload(1)); err != nil || !rec.Valid(false) || rec.Source.Signature == nil {
		t.Fatalf("recover %+v %v", rec, err)
	}
	if _, err := alice.LifecycleSourceRecover(ctx, "node-b", d, upload(1)); err == nil {
		t.Fatal("recover on another node")
	}
	if _, err := alice.LifecycleSourceRecover(ctx, "", d, upload(1)); err == nil {
		t.Fatal("recover without node")
	}

	// Put it and read it back in pages.
	if _, res := submit(t, alice, ActionPutLifecycleScript, 0, control.LifecycleScriptPut{Tenant: "shop", Name: "big-ready", Source: *r.Source}, rootFor(t, alice, ActionPutLifecycleScript)); res.Code != ResultApplied {
		t.Fatalf("put %+v", res)
	}
	p0, err := alice.LifecycleSourcePage(ctx, "shop", control.LifecycleSourceQuery{Name: "big-ready", Revision: 1})
	if err != nil || !p0.Valid() || p0.Next != checker.SourcePageBytes || p0.Total != uint64(len(src)) {
		t.Fatalf("page 0 %+v %v", p0.Next, err)
	}
	text, err := ReadLifecycleSource(ctx, alice, "shop", "big-ready", 1)
	if err != nil || text.Source != string(src) || text.Digest != d.Digest {
		t.Fatalf("read %v", err)
	}
	if _, err := alice.LifecycleSourcePage(ctx, "shop", control.LifecycleSourceQuery{Name: "big-ready", Revision: 9}); err == nil {
		t.Fatal("unknown revision")
	}
	if _, err := alice.LifecycleSourcePage(ctx, "shop", control.LifecycleSourceQuery{Name: "big-ready", Revision: 1, Offset: 3 * checker.SourcePageBytes}); err == nil {
		t.Fatal("offset past the end")
	}
	if _, err := bob.LifecycleSourcePage(ctx, "shop", control.LifecycleSourceQuery{Name: "big-ready", Revision: 1}); err == nil {
		t.Fatal("viewer read")
	}

	// Diagnostics: a real check problem and the injection hook.
	bad := []byte("package main\nfunc Check() {}\n")
	r, err = alice.LifecycleSourceStage(ctx, "", desc(bad), upload(2), bad)
	if err != nil || r.Source != nil || len(r.Diagnostics) == 0 || !r.Valid(false) || r.Diagnostics[0].Line != 1 {
		t.Fatalf("diagnostics %+v %v", r, err)
	}
	f.FailNextLifecycleStage([]checker.SourceDiagnostic{{Line: 3, Column: 2, Message: "injected"}})
	if r, err = alice.LifecycleSourceStage(ctx, "", desc(other), upload(3), other); err != nil || r.Source != nil || len(r.Diagnostics) != 1 || r.Diagnostics[0].Message != "injected" {
		t.Fatalf("injected %+v %v", r, err)
	}
	if r, err = alice.LifecycleSourceStage(ctx, "", desc(other), upload(3), other); err != nil || r.Source == nil {
		t.Fatalf("after the hook %+v %v", r, err)
	}

	// Module lock: the ZIP first, on the same node and upload.
	// The fixture policy's module: FixtureModuleZIP matches FixtureModulePin.
	zip, pin := FixtureModuleZIP, FixtureModulePin
	modSrc := []byte(strings.Replace(fixtureCheckSource, "import (", "import (\n\t_ \"golang.org/x/text/cases\"", 1))
	md := desc(modSrc, pin)
	if _, err := alice.LifecycleSourceStage(ctx, "node-b", md, upload(4), modSrc); err == nil {
		t.Fatal("source before its module ZIP")
	}
	if _, err := alice.LifecycleModuleStage(ctx, "node-b", md, upload(4), checker.ModuleArchive{Pin: pin, ZIP: zip[1:]}); err == nil {
		t.Fatal("ZIP not matching the pin")
	}
	mr, err := alice.LifecycleModuleStage(ctx, "node-b", md, upload(4), checker.ModuleArchive{Pin: pin, ZIP: zip})
	if err != nil || !mr.Valid(true) || mr.Module.Module != pin || mr.Node != "node-b" {
		t.Fatalf("module %+v %v", mr, err)
	}
	if rec, err := alice.LifecycleModuleRecover(ctx, "node-b", md, upload(4), pin); err != nil || !rec.Valid(true) {
		t.Fatalf("module recover %+v %v", rec, err)
	}
	if r, err = alice.LifecycleSourceStage(ctx, "node-b", md, upload(4), modSrc); err != nil || !r.Valid(false) || r.Source == nil || len(r.Source.Modules) != 1 {
		t.Fatalf("source with module %+v %v", r, err)
	}
}
