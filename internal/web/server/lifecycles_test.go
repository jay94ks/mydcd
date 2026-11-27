// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

const testCheckSource = `package checker

import (
	"context"

	lifecycle "github.com/jay94ks/seafield/lifecycle/v1"
)

func Check(ctx context.Context, in lifecycle.Request, probe lifecycle.Probe) (lifecycle.Result, error) {
	return lifecycle.Result{Schema: 1, Status: lifecycle.Pass, Reason: "ok"}, nil
}
`

func TestLifecycleScripts(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	n := 0
	op := func() string { n++; return fmt.Sprintf("d7b2c3d4-0000-4000-8000-%012d", n) }
	base := "/api/v1/t/shop/lifecycles/"
	get := func(path string) map[string]any {
		t.Helper()
		code, out := f.do("GET", path, nil)
		if code != 200 {
			t.Fatalf("GET %s: %d %v", path, code, out)
		}
		return out
	}
	step := func(method, path string, body map[string]any, want string) map[string]any {
		t.Helper()
		code, out := f.do(method, path, body)
		if s := opState(t, code, out); s != want {
			t.Fatalf("%s %s %v: %s %d %v", method, path, body, s, code, out)
		}
		return out
	}
	refuse := func(method, path string, body map[string]any, status int, code string) {
		t.Helper()
		c, out := f.do(method, path, body)
		if c != status || errCode(out) != code {
			t.Fatalf("%s %s: want %d %s, got %d %v", method, path, status, code, c, out)
		}
	}

	list := get("/api/v1/t/shop/lifecycle-scripts")
	items := list["items"].([]any)
	if len(items) != 1 || list["policy"].(map[string]any)["configured"] != true {
		t.Fatalf("list: %v", list)
	}
	s := items[0].(map[string]any)
	if s["name"] != "http-ready" || s["recordRevision"] != 3.0 || s["activeRevision"] != 2.0 || len(s["versions"].([]any)) != 2 {
		t.Fatalf("script: %v", s)
	}
	d := get(base + "http-ready")
	if d["revision"] != 2.0 || !strings.Contains(d["source"].(string), "/healthz") || len(d["usedBy"].([]any)) != 1 {
		t.Fatalf("detail: %v", d)
	}
	if d = get(base + "http-ready?revision=1"); !strings.Contains(d["source"].(string), "/ready") {
		t.Fatalf("old revision: %v", d)
	}
	refuse("GET", base+"http-ready?revision=9", nil, 404, "not-found")
	refuse("GET", base+"nope", nil, 404, "not-found")

	// a new script: compile errors come back with lines, then a clean put
	bad := strings.Replace(testCheckSource, "return lifecycle.Result", "return lifecycle.Result{", 1)
	c, out := f.do("PUT", base+"tcp-up", map[string]any{"opId": op(), "source": bad})
	diag, _ := out["error"].(map[string]any)["diagnostics"].([]any)
	if c != 422 || errCode(out) != "compile-error" || len(diag) == 0 || diag[0].(map[string]any)["line"] != 10.0 {
		t.Fatalf("compile error: %d %v", c, out)
	}
	refuse("PUT", base+"tcp-up", map[string]any{"opId": op(), "source": testCheckSource, "lock": []map[string]any{{"path": "example.com/x", "version": "v1.0.0"}}}, 422, "invalid")
	// a lock without its ZIP: the provider does not have the module
	refuse("PUT", base+"tcp-up", map[string]any{"opId": op(), "source": testCheckSource, "lock": []map[string]any{{"path": "golang.org/x/text", "version": "v0.21.0"}}}, 422, "module-missing")
	// diagnostics from the provider come back as 422 compile-error
	fake.FailNextLifecycleStage([]checker.SourceDiagnostic{{Line: 3, Column: 2, Message: "undefined: x"}})
	c, out = f.do("PUT", base+"tcp-up", map[string]any{"opId": op(), "source": testCheckSource})
	if diag, _ := out["error"].(map[string]any)["diagnostics"].([]any); c != 422 || len(diag) != 1 || diag[0].(map[string]any)["message"] != "undefined: x" {
		t.Fatalf("provider diagnostics: %d %v", c, out)
	}
	// a module whose ZIP the test has: the admin adds its pin to the policy
	zip := []byte("PK\x03\x04 module")
	pin := map[string]any{"path": "example.com/safe", "version": "v1.0.0", "digest": fmt.Sprintf("%x", sha256.Sum256(zip)), "length": len(zip)}
	fakeLogin(t, f, "admin")
	step("PUT", "/api/v1/t/shop/lifecycle-policy", map[string]any{"opId": op(), "resolver": map[string]any{"sourceCacheBytes": 16 << 20, "modules": []map[string]any{
		{"path": sfc.FixtureModulePin.Path, "version": sfc.FixtureModulePin.Version, "digest": fmt.Sprintf("%x", sfc.FixtureModulePin.Digest), "length": sfc.FixtureModulePin.Length}, pin}}}, "applied")
	fakeLogin(t, f, "alice")
	if c, out := f.do("PUT", base+"tcp-up", map[string]any{"opId": op(), "source": testCheckSource, "lock": []map[string]any{{"path": "example.com/safe", "version": "v1.0.0", "zip": zip[1:]}}}); c != 422 {
		t.Fatalf("wrong zip: %d %v", c, out)
	}
	o := op()
	step("PUT", base+"tcp-up", map[string]any{"opId": o, "source": testCheckSource, "lock": []map[string]any{{"path": "example.com/safe", "version": "v1.0.0", "zip": zip}}}, "applied")
	var put control.LifecycleScriptPut
	userPayload(t, f, "u-alice", o, &put)
	if put.Name != "tcp-up" || put.Source.Verify() != nil || len(put.Source.Modules) != 1 {
		t.Fatalf("put payload: %+v", put)
	}
	d = get(base + "tcp-up")
	if d["source"] != testCheckSource || d["script"].(map[string]any)["recordRevision"] != 1.0 {
		t.Fatalf("new script: %v", d)
	}
	// a new version with a stale expected is rejected by sfcd
	if c, out := f.do("PUT", base+"tcp-up", map[string]any{"opId": op(), "source": testCheckSource + "\n", "expected": 7}); opState(t, c, out) == "applied" {
		t.Fatalf("stale put applied: %v", out)
	}
	step("PUT", base+"tcp-up", map[string]any{"opId": op(), "source": testCheckSource + "\n"}, "applied")

	// retire then delete; active and pinned versions are refused first
	refuse("DELETE", base+"http-ready", map[string]any{"opId": op(), "revision": 2}, 409, "active")
	refuse("POST", base+"http-ready/retire", map[string]any{"opId": op(), "revision": 1}, 409, "not-active")
	step("POST", base+"http-ready/retire", map[string]any{"opId": op(), "revision": 2}, "applied")
	refuse("DELETE", base+"http-ready", map[string]any{"opId": op(), "revision": 2}, 409, "in-use")
	fake.SetLifecycleUses("shop", "http-ready", nil)
	od := op()
	step("DELETE", base+"http-ready", map[string]any{"opId": od, "revision": 2}, "applied")
	var sel control.LifecycleScriptSelection
	userPayload(t, f, "u-alice", od, &sel)
	if sel.Name != "http-ready" || sel.Revision != 2 {
		t.Fatalf("delete payload: %+v", sel)
	}
	refuse("DELETE", base+"http-ready", map[string]any{"opId": op(), "revision": 2}, 409, "deleted")
	if d = get(base + "http-ready?revision=2"); d["sourceAvailable"] != false {
		t.Fatalf("deleted source: %v", d)
	}

	// payments: alice is a viewer (no ManageServices) and it has no policy
	refuse("GET", "/api/v1/t/payments/lifecycle-scripts", nil, 403, "denied")
}

func TestLifecyclePolicy(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "admin")
	n := 0
	op := func() string { n++; return fmt.Sprintf("d8b2c3d4-0000-4000-8000-%012d", n) }
	code, out := f.do("GET", "/api/v1/t/payments/lifecycle-policy", nil)
	if code != 200 || out["configured"] != false || out["policy"].(map[string]any)["execution"].(map[string]any)["maxConcurrent"] != 4.0 {
		t.Fatalf("default: %d %v", code, out)
	}
	// no policy: a script put is refused before staging
	if code, out := f.do("PUT", "/api/v1/t/payments/lifecycles/x", map[string]any{"opId": op(), "source": testCheckSource}); code != 409 || errCode(out) != "policy-disabled" {
		t.Fatalf("no policy: %d %v", code, out)
	}
	if code, out := f.do("PUT", "/api/v1/t/payments/lifecycle-policy", map[string]any{"opId": op(), "execution": map[string]any{"maxConcurrent": 0}}); code != 422 || errCode(out) != "invalid-policy" {
		t.Fatalf("bad policy: %d %v", code, out)
	}
	o := op()
	code, out = f.do("PUT", "/api/v1/t/payments/lifecycle-policy", map[string]any{"opId": o, "resolver": map[string]any{
		"allowPackages": []string{"golang.org/x/text/language"}, "sourceCacheBytes": 32 << 20,
		"modules": []map[string]any{{"path": sfc.FixtureModulePin.Path, "version": sfc.FixtureModulePin.Version, "digest": fmt.Sprintf("%x", sfc.FixtureModulePin.Digest), "length": sfc.FixtureModulePin.Length}}}})
	if opState(t, code, out) != "applied" {
		t.Fatalf("set policy: %d %v", code, out)
	}
	var p checker.TenantPolicy
	userPayload(t, f, "u-admin", o, &p)
	if p.Revision != 0 || !p.Enabled || p.Execution.MaxConcurrent != 4 || len(p.Resolver.Modules) != 1 || p.Resolver.SourceCacheBytes != 32<<20 {
		t.Fatalf("policy payload: %+v", p)
	}
	code, out = f.do("GET", "/api/v1/t/payments/lifecycle-policy", nil)
	pol := out["policy"].(map[string]any)
	if code != 200 || out["configured"] != true || pol["revision"] != 1.0 || pol["resolver"].(map[string]any)["modules"].([]any)[0].(map[string]any)["digest"] != fmt.Sprintf("%x", sfc.FixtureModulePin.Digest) {
		t.Fatalf("read back: %d %v", code, out)
	}
	// disable keeps the rest; Expected = policy revision
	if code, out := f.do("PUT", "/api/v1/t/payments/lifecycle-policy", map[string]any{"opId": op(), "enabled": false}); opState(t, code, out) != "applied" {
		t.Fatalf("disable: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/t/payments/lifecycle-policy", nil)
	pol = out["policy"].(map[string]any)
	if pol["enabled"] != false || pol["revision"] != 2.0 || pol["resolver"].(map[string]any)["sourceCacheBytes"] != float64(32<<20) {
		t.Fatalf("disabled: %v", out)
	}
	if code, out := f.do("PUT", "/api/v1/t/payments/lifecycles/x", map[string]any{"opId": op(), "source": testCheckSource}); code != 409 || errCode(out) != "policy-disabled" {
		t.Fatalf("disabled put: %d %v", code, out)
	}
}
