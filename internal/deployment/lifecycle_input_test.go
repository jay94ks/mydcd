// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"gopkg.in/yaml.v3"
)

// A bounded parser fixture, not a compiler/runner or container success proof.
func lifecycleInputDocument() string {
	raw := strings.Replace(appInputDocument(), "x-sfc: {}", `x-sfc:
  lifecycle:
    optimizer: {compile: true}
    scripts:
      inline:
        source: |
          package checker
          const literal = "$UNEXPANDED"
      registered:
        ref: {name: ready-file, revision: 7}
        compile: false
    templates:
      image: {builtin: docker_health}
    checks:
      - {id: all-ready, phase: readiness, builtin: depends_on, parameters: {services: [web], condition: service_healthy}}`, 1)
	return strings.Replace(raw, "x-sfc: {node: node-a}", `x-sfc:
      node: node-a
      lifecycle:
        checks:
          - {id: native, phase: readiness, use: image}
          - {id: endpoint, phase: liveness, script: inline, parameters: {mode: test}}
          - {id: marker, phase: startup, script: registered, interval: 2s, timeout: 1s, retries: 4, start_period: 30s}
          - {id: file, phase: readiness, builtin: file, parameters: {path: /run/ready, kind: regular, mode: 256}}`, 1)
}

func TestServiceLifecycleActionsUseProductPolicy(t *testing.T) {
	raw := strings.Replace(lifecycleInputDocument(), "phase: liveness, script: inline", "phase: liveness, script: inline, actions: {on_alive: keep, on_dead: restart}", 1)
	c, err := ParseApp([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := c.LifecycleProgram()
	if err != nil || p.Services["web"][1].Actions == nil || p.Services["web"][1].Actions.OnDead != checker.RestartContainer {
		t.Fatal("app policy not mapped to product core", p, err)
	}
	for _, bad := range []string{
		strings.Replace(raw, "on_dead: restart", "on_dead: remove-volume", 1),
		strings.Replace(raw, "on_alive: keep", "on_alive: null", 1),
		strings.Replace(raw, "on_alive: keep", "unknown_action: keep", 1),
		strings.Replace(raw, "phase: liveness, script: inline", "phase: readiness, script: inline", 1),
	} {
		if _, err = ParseApp([]byte(bad)); err == nil {
			t.Fatal("invalid lifecycle action declaration accepted")
		}
	}
}

func TestAppLifecycleUsesProductProgramWithoutCatalogFacts(t *testing.T) {
	t.Setenv("UNEXPANDED", "must-not-appear")
	c, err := ParseApp([]byte(lifecycleInputDocument()))
	if err != nil {
		t.Fatal(err)
	}
	p, present, err := c.LifecycleProgram()
	if err != nil || !present || !p.Compile || len(p.Checks) != 1 || len(p.Services["web"]) != 4 || !strings.Contains(p.Scripts["inline"].Source, "$UNEXPANDED") {
		t.Fatal("declaration projection or literal source changed", err)
	}
	before, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	named := []checker.NamedSource{{Tenant: "tenant", Ref: checker.NamedReference{Name: "ready-file", Revision: 7}, Digest: strings.Repeat("a", 64), SDK: 1, Active: true}}
	r, err := checker.ResolveProgram("tenant", p, named, lifecycleTiming(), 3000)
	if err != nil || r.Scripts["registered"].Compile || !r.Scripts["inline"].Compile || r.Services["web"][2].Timing.TimeoutMS != 1000 || r.Services["web"][3].Builtin.File.Mode == nil || *r.Services["web"][3].Builtin.File.Mode != 256 {
		t.Fatal("core selection/timing/typed parameters", err)
	}
	// Mutation of every pointer/raw byte boundary must leave input unchanged.
	*p.Scripts["registered"].Compile = true
	p.Scripts["registered"].Ref.Revision++
	*p.Services["web"][2].Retries = 99
	p.Services["web"][1].Template.Parameters[0] = '['
	after, err := c.Canonical()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("returned Program aliases app declaration", err)
	}
	var restored Compose
	if json.Unmarshal(before, &restored) != nil {
		t.Fatal("canonical JSON not readable")
	}
	p1, _, _ := c.LifecycleProgram()
	p2, _, err := restored.LifecycleProgram()
	if err != nil || !reflect.DeepEqual(p1, p2) {
		t.Fatal("JSON persistence changed declaration", err)
	}
	yml, err := yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	round, err := ParseApp(yml)
	if err != nil {
		t.Fatal("YAML projection lost literal code/parameters", err)
	}
	p3, _, err := round.LifecycleProgram()
	if err != nil || !reflect.DeepEqual(p1, p3) {
		t.Fatal("YAML changed product program", err)
	}
	if _, err := checker.ResolveProgram("tenant", p1, nil, lifecycleTiming(), 3000); err == nil {
		t.Fatal("declaration check fabricated missing named revision")
	}
	named[0].Ref.Revision = 8
	if _, err := checker.ResolveProgram("tenant", p1, named, lifecycleTiming(), 3000); err == nil {
		t.Fatal("named latest fallback")
	}
	catalog, _ := checker.NewCatalog([32]byte{1})
	if _, err := c.ResolveLifecycle(catalog); err == nil {
		t.Fatal("policy-free resolution")
	}
}

func TestAppLifecycleRejectsAmbiguousMalformedOrUnboundedDeclaration(t *testing.T) {
	raw := lifecycleInputDocument()
	for label, mutate := range map[string]func(string) string{
		"null extension":    func(s string) string { return strings.Replace(s, "optimizer: {compile: true}", "optimizer: null", 1) },
		"unknown optimizer": func(s string) string { return strings.Replace(s, "compile: true", "compile: true, keep_warm: true", 1) },
		"source and ref": func(s string) string {
			return strings.Replace(s, "compile: false", "compile: false\n        source: package checker", 1)
		},
		"zero revision": func(s string) string { return strings.Replace(s, "revision: 7", "revision: 0", 1) },
		"unknown script field": func(s string) string {
			return strings.Replace(s, "compile: false", "compile: false\n        file: /unapproved.go", 1)
		},
		"unknown check":      func(s string) string { return strings.Replace(s, "use: image", "use: image, keep_ready: true", 1) },
		"unknown parameter":  func(s string) string { return strings.Replace(s, "mode: 256", "mode: 256, ignored: true", 1) },
		"null parameters":    func(s string) string { return strings.Replace(s, "parameters: {mode: test}", "parameters: null", 1) },
		"scalar parameters":  func(s string) string { return strings.Replace(s, "parameters: {mode: test}", "parameters: opaque", 1) },
		"typed script value": func(s string) string { return strings.Replace(s, "mode: test", "mode: true", 1) },
		"parameter budget": func(s string) string {
			return strings.Replace(s, "mode: test", "mode: '"+strings.Repeat("x", 33<<10)+"'", 1)
		},
		"fractional millisecond": func(s string) string { return strings.Replace(s, "timeout: 1s", "timeout: 1ns", 1) },
		"unknown phase":          func(s string) string { return strings.Replace(s, "phase: startup", "phase: restart", 1) },
		"missing template":       func(s string) string { return strings.Replace(s, "use: image", "use: missing", 1) },
		"missing alias":          func(s string) string { return strings.Replace(s, "script: registered", "script: missing", 1) },
		"foreign target": func(s string) string {
			return strings.Replace(s, "path: /run/ready", "service: foreign, path: /run/ready", 1)
		},
		"duplicate check": func(s string) string { return strings.Replace(s, "id: marker", "id: native", 1) },
		"service owns policy": func(s string) string {
			return strings.Replace(s, "      lifecycle:\n        checks:", "      lifecycle:\n        optimizer: {compile: false}\n        checks:", 1)
		},
		"source NUL":          func(s string) string { return strings.Replace(s, "$UNEXPANDED", "\x00", 1) },
		"ambient environment": func(s string) string { return strings.Replace(s, "MODE: app", "MODE: $UNEXPANDED", 1) },
		"internal metadata key": func(s string) string {
			return strings.Replace(s, "    command: []", "    '-': {PolicyRevision: 1}\n    command: []", 1)
		},
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := ParseApp([]byte(mutate(raw))); err == nil {
				t.Fatal("malformed lifecycle admitted")
			}
		})
	}
}

func TestAppLifecycleDependenciesShareOriginalDAGAndDoNotMutateInput(t *testing.T) {
	c, err := ParseApp([]byte(appInputDocument()))
	if err != nil {
		t.Fatal(err)
	}
	web := c.Services["web"]
	web.DependsOn = Dependencies{"db": {Condition: "service_started"}}
	c.Services["web"] = web
	db := c.Services["web"]
	db.DependsOn = nil
	db.Sfc.Lifecycle = &ServiceLifecycle{Checks: []LifecycleCheck{{ID: "wait-web", Phase: "startup", LifecycleTemplate: LifecycleTemplate{Builtin: "depends_on", Parameters: LifecycleParameters(`{"services":["web"],"condition":"service_started"}`)}}}}
	c.Services["db"] = db
	before, _ := json.Marshal(c)
	if _, _, err := c.LifecycleProgram(); err == nil || !strings.Contains(err.Error(), "DEPENDENCY_CYCLE") {
		t.Fatal("cross-kind cycle was not checked by the existing DAG", err)
	}
	after, _ := json.Marshal(c)
	if !bytes.Equal(before, after) {
		t.Fatal("DAG validation mutated app")
	}
	web.DependsOn = nil
	c.Services["web"] = web
	if _, _, err := c.LifecycleProgram(); err != nil {
		t.Fatal("acyclic lifecycle dependency", err)
	}
}

func TestAppLifecycleCannotDeployBeforePinsAndRunnerAreConnected(t *testing.T) {
	f, c, ctx, _ := externalFixture(t)
	before, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := before.Encode()
	if bytes.Contains(old, []byte(`"Lifecycle"`)) || bytes.Contains(old, []byte(`"LifecycleSources"`)) {
		t.Fatal("absent lifecycle changed schema1 artifact")
	}
	c.Sfc.Lifecycle = &LifecycleDeclaration{Templates: map[string]LifecycleTemplate{"image": {Builtin: "docker_health"}}}
	svc := c.Services["web"]
	svc.Sfc.Lifecycle = &ServiceLifecycle{Checks: []LifecycleCheck{{ID: "image", Use: "image", Phase: "readiness"}}}
	c.Services["web"] = svc
	if _, err := CompileApp(c, f.c, ctx); err == nil || !strings.Contains(err.Error(), "FEATURE_UNAVAILABLE: lifecycle") {
		t.Fatal("parsed declaration was accepted as an executable Task", err)
	}
	svc.LifecycleSources = &checker.Selection{PolicyRevision: 1, Scripts: []checker.NamedReference{{Name: "injected", Revision: 1}}}
	c.Services["web"] = svc
	if c.ValidateApp() == nil {
		t.Fatal("caller injected accepted Task source facts")
	}
}

func TestAppLifecyclePlanningUsesCurrentPolicyAndExactNamedMetadata(t *testing.T) {
	f := makeFixture(t)
	c, err := ParseApp([]byte(lifecycleInputDocument()))
	if err != nil {
		t.Fatal(err)
	}
	c.Sfc.Tenant = "tenant" // the server sets the tenant from the request scope
	c.Sfc.Lifecycle.Optimizer.Compile = false
	script := c.Sfc.Lifecycle.Scripts["registered"]
	script.Ref.Revision = 1
	c.Sfc.Lifecycle.Scripts["registered"] = script
	policy := checker.TenantPolicy{Tenant: "tenant", Enabled: true,
		Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}},
		Resolver:  checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/seafield/lifecycle/v1"}, SourceCacheBytes: 1 << 20}}
	book, err := checker.NewCatalog(f.cluster)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.SetPolicy(f.c, "alice", 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	const source = "package checker\n"
	fact := checker.SourceFact{Schema: 1, Cluster: f.cluster, Owner: public(f.na), Tenant: "tenant", SDK: 1, Digest: sha256.Sum256([]byte(source)), Length: uint64(len(source))}
	fact.Signature = ed25519.Sign(f.na, checker.SourceFactBytes(fact))
	book, err = book.PutScript(f.c, "alice", 0, "tenant", "ready-file", fact)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.ResolveLifecycle(book)
	if err != nil || r.Scripts["registered"].Ref.Revision != 1 || r.Scripts["registered"].Compile || r.Services["web"][0].Timing.IntervalMS != 10000 {
		t.Fatal("current metadata resolution", err)
	}
	c.Sfc.Lifecycle.Optimizer.Compile = true
	if _, err := c.ResolveLifecycle(book); err == nil || !strings.Contains(err.Error(), "LIFECYCLE_BUILDER_REQUIRED") {
		t.Fatal("compile=true invented a builder", err)
	}
	c.Sfc.Lifecycle.Optimizer.Compile = false
	short := policy
	short.Execution.TimeoutMS = 500
	shortBook, err := book.SetPolicy(f.c, "alice", 1, short)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveLifecycle(shortBook); err == nil {
		t.Fatal("planning retained old timeout permission")
	}
	policy.Enabled = false
	disabled, err := book.SetPolicy(f.c, "alice", 1, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveLifecycle(disabled); err == nil {
		t.Fatal("planning ignored disabled policy")
	}
	retired, err := book.RetireScript(f.c, "alice", 1, "tenant", checker.NamedReference{Name: "ready-file", Revision: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveLifecycle(retired); err == nil {
		t.Fatal("planning accepted retired source")
	}
	if _, err := c.ResolveLifecycle(book); err != nil {
		t.Fatal("pure planning mutated original catalog", err)
	}
	// This test signs source metadata only; it does not stage bytes, reserve a
	// Binding or prove that a native runner can execute this source.
}

func TestLifecycleParameterCodecRejectsAmbiguityAndPreservesIntegers(t *testing.T) {
	const raw = `{"large":9007199254740993,"nested":{"enabled":true}}`
	var value LifecycleParameters
	if json.Unmarshal([]byte(raw), &value) != nil {
		t.Fatal("valid bounded object")
	}
	yml, err := yaml.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var restored LifecycleParameters
	if yaml.Unmarshal(yml, &restored) != nil || !bytes.Equal(value, restored) {
		t.Fatal("YAML/JSON rounded integers or changed parameters")
	}
	for _, raw := range []string{`null`, `[]`, `1`, `{"a":1,"a":2}`, `{"nested":{"a":1,"a":2}}`, `{} {}`, `{"text":"` + strings.Repeat("x", 33<<10) + `"}`} {
		if json.Unmarshal([]byte(raw), new(LifecycleParameters)) == nil {
			t.Fatal("ambiguous/unbounded parameter object", len(raw))
		}
	}
}
