// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func appProbeFixture(t *testing.T) (TaskProgram, Definition, Run, ProbeCall) {
	t.Helper()
	book, _, _, _ := frozenProgramFixture(t)
	p := Program{Services: map[string][]Check{"web": nil}, Checks: []Check{{ID: "inspect", Phase: contract.Liveness, Template: Template{Builtin: "file", Parameters: json.RawMessage(`{"service":"web","path":"/ready","kind":"regular"}`)}}}}
	frozen, err := FreezeProgram("tenant", p, book, nil, programDefaults())
	if err != nil {
		t.Fatal(err)
	}
	program, err := frozen.Task("web")
	if err != nil {
		t.Fatal(err)
	}
	check := program.AppChecks[0]
	source, err := program.CheckSourceDigest(check)
	if err != nil {
		t.Fatal(err)
	}
	request := testDefinition().Request
	request.Cluster = hex.EncodeToString(program.Cluster[:])
	request.Checker = check.ID
	request.SourceDigest = hex.EncodeToString(source[:])
	request.Phase = check.Phase
	request.Parameters = check.Parameters
	d := Definition{ProgramDigest: hex.EncodeToString(program.Program[:]), PolicyRevision: program.Policy.Revision, Timing: check.Timing, Request: request}
	m, err := New(d, 1000)
	if err != nil {
		t.Fatal(err)
	}
	m, run, err := m.Plan(1000)
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Dispatch(run.Request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	run = *m.Checkpoint().Active
	call := ProbeCall{Schema: 1, Binding: ProbeBinding(run.Request), Sequence: 1, Kind: "file", DeadlineUnixMilli: run.Request.DeadlineUnixMilli, File: &contract.FileProbe{Service: "web", Path: "/ready", Kind: "regular"}}
	return program, d, run, call
}

func TestRemoteAppRunReusesExactMachineAndDeclaredBuiltinPayload(t *testing.T) {
	p, d, run, call := appProbeFixture(t)
	def, check, err := p.AppProbeDefinition(run, nil)
	if err != nil || def.Digest() != d.Digest() || check.ID != "inspect" {
		t.Fatal("accepted Machine binding changed", def, err)
	}
	check.Builtin.File.Path = "/caller-mutated"
	if p.AppChecks[0].Builtin.File.Path != "/ready" {
		t.Fatal("returned check aliased accepted policy")
	}
	if _, err = p.ValidateAppProbeCall(run, nil, p.Policy, call); err != nil {
		t.Fatal("accepted file call denied", err)
	}
	for _, mutate := range []func(*Run){
		func(r *Run) { r.Phase = Prepared }, func(r *Run) { r.Sequence++ }, func(r *Run) { r.PreparedAt++ },
		func(r *Run) { r.RequestDigest[0]++ }, func(r *Run) { r.Request.Checker = "other" },
		func(r *Run) { r.Request.SourceDigest = hashText("foreign") },
		func(r *Run) { r.Request.Targets[0].Service = "foreign" },
	} {
		changed := ownRun(run)
		mutate(&changed)
		if _, _, err = p.AppProbeDefinition(changed, nil); err == nil {
			t.Fatal("changed run accepted", changed)
		}
	}
	changed := call
	query := *call.File
	query.Path = "/private"
	changed.File = &query
	if _, err = p.ValidateAppProbeCall(run, nil, p.Policy, changed); err == nil {
		t.Fatal("builtin widened its accepted path")
	}
	if _, _, err = p.AppProbeDefinition(run, &ShutdownScope{Operation: "invented-stop", Revision: 1}); err == nil {
		t.Fatal("normal run reused a stop grant")
	}
	other := p.Clone()
	other.Service = "foreign"
	if _, _, err = other.AppProbeDefinition(run, nil); err == nil {
		t.Fatal("non-coordinator delegated an app check")
	}
	query.Path = "/ready"
	query.Service = "foreign"
	if _, err = p.ValidateAppProbeCall(run, nil, p.Policy, changed); err == nil {
		t.Fatal("foreign service accepted")
	}
}
