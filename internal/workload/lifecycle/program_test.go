// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/json"
	"reflect"
	"testing"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func programDefaults() Timing {
	return Timing{IntervalMS: 5000, TimeoutMS: 2000, FreshForMS: 7000, Retries: 3}
}

func TestCheckerDeclarationChecksDoNotInventNamedSourceAvailability(t *testing.T) {
	p := Program{Scripts: map[string]Script{"named": {Ref: &NamedReference{Name: "ready", Revision: 9}}},
		Services: map[string][]Check{"web": {{ID: "ready", Phase: contract.Readiness, Template: Template{Script: "named"}}}}}
	if _, err := CheckProgram(p, programDefaults(), 2000); err != nil {
		t.Fatal("valid unresolved declaration", err)
	}
	if _, err := ResolveProgram("tenant", p, nil, programDefaults(), 2000); err == nil {
		t.Fatal("declaration admitted missing named source")
	}
	p.Scripts["named"].Ref.Revision = 0
	if _, err := CheckProgram(p, programDefaults(), 2000); err == nil {
		t.Fatal("declaration accepted implicit latest revision")
	}
}

func TestCheckerProgramScopesTemplatesAndExistingDAGEdges(t *testing.T) {
	p := Program{Scripts: map[string]Script{"custom": {Source: "package checker\n"}}, Templates: map[string]Template{"image": {Builtin: "docker_health"}},
		Checks: []Check{{ID: "app-ready", Phase: contract.Readiness, Template: Template{Builtin: "depends_on", Parameters: json.RawMessage(`{"services":["web","db"],"condition":"service_healthy"}`)}}},
		Services: map[string][]Check{
			"db": {{ID: "native", Use: "image", Phase: contract.Readiness}},
			"web": {
				{ID: "http", Phase: contract.Readiness, Timeout: "1s", Template: Template{Builtin: "healthz", Parameters: json.RawMessage(`{"path":"/readyz","port":8080}`)}},
				{ID: "dependency", Phase: contract.Startup, Template: Template{Builtin: "depends_on", Parameters: json.RawMessage(`{"services":["db"],"condition":"service_healthy"}`)}},
				{ID: "custom", Phase: contract.Liveness, Template: Template{Script: "custom", Parameters: json.RawMessage(`{"key":"value"}`)}},
			},
		}}
	resolved, err := ResolveProgram("tenant", p, nil, programDefaults(), 2000)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Services["web"][0].Builtin.HTTP.Service != "web" || resolved.Services["web"][0].Timing.TimeoutMS != 1000 || resolved.Services["web"][0].Timing.FreshForMS != 6000 || !reflect.DeepEqual(resolved.Dependencies["web"], []string{"db"}) || len(resolved.Dependencies["db"]) != 0 {
		t.Fatal("scope/timing or app-wide checks became dependency edges", resolved)
	}
	if resolved.Services["db"][0].Builtin.Kind != "docker_health" || resolved.Services["web"][2].Parameters["key"] != "value" {
		t.Fatal("template/direct builtins or script parameters lost")
	}
	// The result deliberately exports edges; the real planner must merge them
	// into its existing DAG and reject cycles. Resolution is not an executor.
	if resolved.Checks[0].Builtin.Dependency.Services[0] != "db" {
		t.Fatal("dependency conditions were not canonicalized")
	}
}

func TestCheckerProgramRejectsAmbiguityForeignScopeAndMalformedProbe(t *testing.T) {
	for _, test := range []struct {
		name  string
		check Check
	}{
		{"foreign-service", Check{Template: Template{Builtin: "healthz", Parameters: json.RawMessage(`{"service":"db","port":80,"path":"/"}`)}}},
		{"external-host", Check{Template: Template{Builtin: "healthz", Parameters: json.RawMessage(`{"port":80,"path":"https://example.invalid/"}`)}}},
		{"case-alias", Check{Template: Template{Builtin: "healthz", Parameters: json.RawMessage(`{"Port":80,"path":"/"}`)}}},
		{"duplicate-key", Check{Template: Template{Builtin: "healthz", Parameters: json.RawMessage(`{"port":80,"path":"/","port":81}`)}}},
		{"scope-self-dependency", Check{Template: Template{Builtin: "depends_on", Parameters: json.RawMessage(`{"services":["web"],"condition":"service_started"}`)}}},
		{"missing-dependency", Check{Template: Template{Builtin: "depends_on", Parameters: json.RawMessage(`{"services":["missing"],"condition":"service_started"}`)}}},
		{"shell-option", Check{Template: Template{Builtin: "cmd", Parameters: json.RawMessage(`{"argv":["true"],"shell":true}`)}}},
		{"relative-file", Check{Template: Template{Builtin: "file", Parameters: json.RawMessage(`{"path":"../file"}`)}}},
		{"null-parameters", Check{Template: Template{Builtin: "file", Parameters: json.RawMessage(`null`)}}},
		{"ambiguous-selector", Check{Template: Template{Builtin: "docker_health", Script: "custom"}}},
		{"missing-template", Check{Use: "missing"}},
		{"policy-timeout", Check{Timeout: "3s", Template: Template{Builtin: "docker_health"}}},
		{"fractional-ms", Check{Timeout: "1ns", Template: Template{Builtin: "docker_health"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := test.check
			c.ID, c.Phase = "probe", contract.Readiness
			p := Program{Services: map[string][]Check{"web": {c}, "db": nil}}
			if _, err := ResolveProgram("tenant", p, nil, programDefaults(), 2000); err == nil {
				t.Fatal("invalid input admitted")
			}
		})
	}
	if _, err := ResolveProgram("tenant", Program{Templates: map[string]Template{"unused": {Builtin: "unknown"}}, Services: map[string][]Check{"web": nil}}, nil, programDefaults(), 2000); err == nil {
		t.Fatal("unknown unused template accepted")
	}
}
