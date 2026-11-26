// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/storage"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Real source DB/SDK/recipe producer and frozen Task projection; metadata
// authority is simulated. No compiler process or native execution is claimed.
func TestCheckerTaskCompilationsBuildOnlyCompiledAliasesWithExactSelection(t *testing.T) {
	book, _, intent, batch, private := buildJobFixture(t)
	_, policy := compilationFixture(t)
	on, off := true, false
	declaration := Program{Scripts: map[string]Script{"compiled": {Source: compileTestSource, Compile: &on}, "interpreted": {Source: compileTestSource, Compile: &off}}, Services: map[string][]Check{"web": {{ID: "compiled-check", Phase: contract.Readiness, Template: Template{Script: "compiled"}}, {ID: "interpreted-check", Phase: contract.Readiness, Template: Template{Script: "interpreted"}}}}}
	fact := intent.Selection.Sources[0]
	frozen, err := FreezeProgram("tenant", declaration, book, map[string]SourceFact{"compiled": fact, "interpreted": fact}, programDefaults())
	if err != nil {
		t.Fatal(err)
	}
	program, err := frozen.Task("web")
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, intent.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Stage(context.Background(), fact.Descriptor(), []byte(compileTestSource), policy); err != nil {
		t.Fatal(err)
	}
	inputs, err := store.TaskCompilations(context.Background(), program, policy, ResolverTarget{GOOS: batch.GOOS, GOARCH: batch.GOARCH, Toolchain: batch.Toolchain})
	if err != nil || len(inputs) != 1 || inputs[0].Item().Key != batch.Items[0].Key {
		t.Fatal("compiled-only actual recipe", err)
	}
	plan := TaskCompilePlan{Recipes: []CompileRecipe{inputs[0].Item().Recipe}}
	if plan.ValidateProgram(program) != nil {
		t.Fatal("exact compiled coverage")
	}
	if (TaskCompilePlan{}).ValidateProgram(program) == nil {
		t.Fatal("missing compiled input authorized native activation")
	}
	duplicate := plan
	duplicate.Recipes = append(duplicate.Recipes, duplicate.Recipes[0])
	if duplicate.ValidateProgram(program) == nil {
		t.Fatal("duplicate recipe substituted for coverage")
	}
	wanted := []BuildInput{{Content: fact.ContentDigest(), Recipe: inputs[0].Item().Key}}
	selection, err := program.CompileSelection(wanted)
	if err != nil || len(selection.Sources) != 1 || len(selection.Scripts) != 0 || selection.Sources[0].ContentDigest() != fact.ContentDigest() {
		t.Fatal("exact compiled input selection", err)
	}
	changed := program.Clone()
	s := changed.Scripts["compiled"]
	s.Compile = false
	changed.Scripts["compiled"] = s
	if _, err := changed.CompileSelection(wanted); err == nil {
		t.Fatal("interpreted aliases widened to compiler")
	}
	if _, err := program.CompileSelection(append(wanted, wanted[0])); err == nil {
		t.Fatal("duplicate source request")
	}
	if _, err := program.CompileSelection([]BuildInput{{Content: [32]byte{99}, Recipe: inputs[0].Item().Key}}); err == nil {
		t.Fatal("foreign source selected")
	}
}
