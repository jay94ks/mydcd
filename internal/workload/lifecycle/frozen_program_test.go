// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func TestBuiltinOnlyTaskRetainsProgramWithoutAScriptPin(t *testing.T) {
	book, _, _, _ := frozenProgramFixture(t)
	for _, appScope := range []bool{false, true} {
		p := Program{Services: map[string][]Check{"web": nil}}
		if appScope {
			p.Checks = []Check{{ID: "all-ready", Phase: contract.Readiness, Template: Template{Builtin: "depends_on", Parameters: json.RawMessage(`{"services":["web"],"condition":"service_healthy"}`)}}}
		} else {
			p.Services["web"] = []Check{{ID: "native", Phase: contract.Readiness, Template: Template{Builtin: "docker_health"}}}
		}
		frozen, err := FreezeProgram("tenant", p, book, nil, programDefaults())
		if err != nil {
			t.Fatal(err)
		}
		task, err := frozen.Task("web")
		if err != nil || task.ValidateCatalog(book) != nil {
			t.Fatal(task, err)
		}
		selection, err := task.Selection()
		if err != nil || selection != nil || len(task.Checks)+len(task.AppChecks) != 1 {
			t.Fatal("nil source pin erased builtin program", task, selection, err)
		}
	}
}

// Metadata fixture only: signatures are real, while byte staging, current
// membership, user authority and runner readiness belong to adapter tests.
func frozenProgramFixture(t *testing.T) (Catalog, Program, map[string]SourceFact, FrozenProgram) {
	t.Helper()
	policy := sourcePolicy()
	policy.Resolver.Modules = []ModulePin{{Path: "example.invalid/safe", Version: "v1.0.0", Digest: [32]byte{2}, Length: 1024}}
	book, err := NewCatalog([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	book.d.Revision = 2
	book.d.Policies["tenant"] = []TenantPolicy{policy}
	named := signedSource(12, "package checker\nconst named = true\n", nil)
	book.d.Scripts["tenant/ready"] = ScriptRecord{Tenant: "tenant", Name: "ready", Revision: 1, Versions: []ScriptVersion{{Revision: 1, Source: named, Active: true}}}
	if err := book.Validate(); err != nil {
		t.Fatal(err)
	}
	p := Program{Scripts: map[string]Script{
		"inline": {Source: "package checker\n", Modules: slices.Clone(policy.Resolver.Modules)},
		"named":  {Ref: &NamedReference{Name: "ready", Revision: 1}},
	}, Checks: []Check{{ID: "app", Phase: contract.Readiness, Template: Template{Script: "named"}}},
		Services: map[string][]Check{
			"alpha": {{ID: "custom", Phase: contract.Readiness, Template: Template{Script: "inline"}}},
			"beta":  {{ID: "native", Phase: contract.Readiness, Template: Template{Builtin: "docker_health"}}},
		}}
	inline := map[string]SourceFact{"inline": signedSource(11, p.Scripts["inline"].Source, policy.Resolver.Modules)}
	frozen, err := FreezeProgram("tenant", p, book, inline, programDefaults())
	if err != nil {
		t.Fatal(err)
	}
	return book, p, inline, frozen
}

func TestCheckerFrozenProgramOwnsOriginalLockAndProjectsExactServiceSources(t *testing.T) {
	book, p, inline, frozen := frozenProgramFixture(t)
	if frozen.Validate(p, book.Cluster(), programDefaults()) != nil || frozen.ValidateCatalog(book) != nil {
		t.Fatal("original frozen program")
	}
	content := inline["inline"].ContentDigest()
	if frozen.Program.Scripts["inline"].Source != "" || frozen.Program.Scripts["inline"].Digest != hex.EncodeToString(content[:]) || content == inlineContentDigest(p.Scripts["inline"].Source) {
		t.Fatal("staged full lock was lost or raw source duplicated")
	}
	a, err := frozen.Task("alpha")
	if err != nil || a.Validate(book.Cluster()) != nil || a.ValidateCatalog(book) != nil || a.Coordinator != "alpha" || len(a.AppChecks) != 1 {
		t.Fatal("coordinator projection", err)
	}
	selection, err := a.Selection()
	if err != nil || selection == nil || len(selection.Scripts) != 1 || len(selection.Sources) != 1 {
		t.Fatal("exact used script pins", err)
	}
	b, err := frozen.Task("beta")
	if err != nil || b.Validate(book.Cluster()) != nil || len(b.Scripts) != 0 || len(b.Sources) != 0 || len(b.AppChecks) != 0 {
		t.Fatal("builtin-only Task inherited scripts/app checks", err)
	}
	if selection, err := b.Selection(); err != nil || selection != nil {
		t.Fatal("builtin invented source pin", err)
	}
	before, _ := json.Marshal(frozen)
	inline["inline"].Modules[0].Digest[0]++
	a.Sources["inline"].Signature[0] ^= 1
	a.Checks[0].Parameters["changed"] = "value"
	if frozen.Validate(p, book.Cluster(), programDefaults()) != nil {
		t.Fatal("projection/input changed original")
	}
	after, _ := json.Marshal(frozen)
	if !bytes.Equal(before, after) {
		t.Fatal("frozen source/check aliases caller")
	}
	if _, err := frozen.Task("foreign"); err == nil {
		t.Fatal("unknown Task projection")
	}
}

func TestCheckerFrozenProgramRejectsStagingAndNormalizationSubstitution(t *testing.T) {
	book, p, inline, frozen := frozenProgramFixture(t)
	if _, err := FreezeProgram("tenant", p, book, nil, programDefaults()); err == nil {
		t.Fatal("missing inline cache fact was synthesized")
	}
	wrong := map[string]SourceFact{"inline": signedSource(11, "package checker\nconst changed = true\n", nil)}
	if _, err := FreezeProgram("tenant", p, book, wrong, programDefaults()); err == nil {
		t.Fatal("different staged source accepted")
	}
	inline["extra"] = inline["inline"]
	if _, err := FreezeProgram("tenant", p, book, inline, programDefaults()); err == nil {
		t.Fatal("extra staged alias accepted")
	}
	for _, change := range []func(*FrozenProgram){
		func(f *FrozenProgram) { f.Policy.Execution.TimeoutMS++ },
		func(f *FrozenProgram) { f.Program.Services["alpha"][0].Timing.FreshForMS++ },
		func(f *FrozenProgram) {
			f.Program.Scripts["inline"] = ScriptSelection{Digest: f.Program.Scripts["inline"].Digest, Source: p.Scripts["inline"].Source}
		},
		func(f *FrozenProgram) { f.Sources["extra"] = f.Sources["inline"] },
		func(f *FrozenProgram) { f.Cluster[0]++ },
	} {
		changed := frozen.Clone()
		change(&changed)
		// A policy field is valid in isolation but must match the real history.
		if changed.Validate(p, book.Cluster(), programDefaults()) == nil && changed.ValidateCatalog(book) == nil {
			t.Fatal("substituted original provenance")
		}
	}
	for _, change := range []func(*TaskProgram){
		func(t *TaskProgram) { t.Service = "beta" },
		func(t *TaskProgram) { t.Coordinator = "beta" },
		func(t *TaskProgram) { t.Checks[0].Timing.FreshForMS++ },
		func(t *TaskProgram) { t.Sources["extra"] = t.Sources["inline"] },
		func(t *TaskProgram) { t.Program = [32]byte{} },
	} {
		task, err := frozen.Task("alpha")
		if err != nil {
			t.Fatal(err)
		}
		change(&task)
		if task.Validate(book.Cluster()) == nil {
			t.Fatal("invalid Task projection")
		}
	}
}

func TestCheckerFrozenHistoryDoesNotResurrectCurrentNamedOrPolicyPermission(t *testing.T) {
	book, p, inline, frozen := frozenProgramFixture(t)
	retired := book.clone()
	record := retired.d.Scripts["tenant/ready"]
	record.Revision++
	record.Versions[0].Active = false
	retired.d.Scripts["tenant/ready"] = record
	retired.d.Revision++
	if retired.Validate() != nil || frozen.ValidateCatalog(retired) != nil {
		t.Fatal("retirement destroyed immutable source provenance")
	}
	if _, err := FreezeProgram("tenant", p, retired, inline, programDefaults()); err == nil {
		t.Fatal("retired source accepted for new program")
	}
	disabled := book.clone()
	policy, _ := disabled.Policy("tenant", 0)
	policy.Enabled, policy.Revision = false, 2
	disabled.d.Policies["tenant"] = append(disabled.d.Policies["tenant"], policy)
	disabled.d.Revision++
	if disabled.Validate() != nil || frozen.ValidateCatalog(disabled) != nil {
		t.Fatal("disabled current policy erased historical contract")
	}
	if _, err := FreezeProgram("tenant", p, disabled, inline, programDefaults()); err == nil {
		t.Fatal("historical policy used as current permission")
	}
	forged := book.clone()
	record = forged.d.Scripts["tenant/ready"]
	record.Versions[0].Source = signedSource(12, "package checker\nconst substitute = true\n", nil)
	forged.d.Scripts["tenant/ready"] = record
	if frozen.ValidateCatalog(forged) == nil {
		t.Fatal("named revision silently remapped to another signed fact")
	}
}
