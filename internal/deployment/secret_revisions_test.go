// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// A secret updated after a deploy changes the same app.yaml's plan for the
// services that read it, and only for them: their inputs and task are
// replaced (a new task generation binds the new value), the others stay.
func TestSecretRevisionChangeReplacesOnlyItsReaders(t *testing.T) {
	f := makeFixture(t)
	revisions := map[string]int{}
	pinned := func() PlanningContext {
		ctx := contextFor(t, f)
		ctx.SecretRevisions = func(sources []Source) string {
			out := ""
			for _, s := range sources {
				out += fmt.Sprintf("%s/%s@%d;", s.Realm, s.Object, revisions[s.Object])
			}
			return out
		}
		return ctx
	}
	ctx := pinned()
	b, err := Compile(smallCompose(t), f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewExecution(b, f.c, ctx, "operation", "submitter", 1)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := state.New("submitter")
	if err != nil {
		t.Fatal(err)
	}
	x := inventoryFor(t, &executionFixture{f, b, e, shared, 100}, ctx)
	x.all()
	actions := func() map[string]string {
		ctx := pinned()
		ctx.Current = x.shared.Objects("")
		next, err := Compile(smallCompose(t), f.c, ctx)
		if err != nil {
			t.Fatal(err)
		}
		changes, err := x.a.Changes(next, false)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, c := range changes {
			out[c.Key] = c.Action
		}
		return out
	}
	key := func(kind, id string) string { return ResourceKey(kind, "tenant", "php-mysql", id) }
	for k, action := range actions() {
		if action != "Keep" {
			t.Fatalf("unchanged secrets: %s is %s", k, action)
		}
	}
	// Only web reads "overrides". (db is web's dependency, so a db change
	// would replace web too; that is the existing dependency rule.)
	var webOnly string
	for _, s := range secretInputSources(smallCompose(t), "tenant", smallCompose(t).Services["web"]) {
		if !containsSource(secretInputSources(smallCompose(t), "tenant", smallCompose(t).Services["db"]), s) {
			webOnly = s.Object
		}
	}
	if webOnly == "" {
		t.Fatal("fixture: no source only web reads")
	}
	revisions[webOnly]++
	got := actions()
	for _, k := range []string{key("inputs", "web"), key("task", "web")} {
		if got[k] != "Replace" {
			t.Fatalf("%s after its secret changed: %s", k, got[k])
		}
	}
	for _, k := range []string{key("inputs", "db"), key("task", "db")} {
		if got[k] != "Keep" {
			t.Fatalf("%s reads no changed secret but is %s", k, got[k])
		}
	}
}

func containsSource(list []Source, s Source) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
