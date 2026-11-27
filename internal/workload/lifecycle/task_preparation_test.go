// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
)

// Actual private DB/owner and reusable plan store. The accepted parent/build
// metadata are simulated; this is not real Raft/Task/native/build readiness.
func TestCheckerTaskPreparationSealsOriginalJobAndRecoversWithoutDeadlineReset(t *testing.T) {
	ctx := context.Background()
	book, parent, b, batch, private := buildJobFixture(t)
	input, policy := compilationFixture(t)
	db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, b.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if store != nil {
			store.Close()
		}
	}()
	p := TaskPreparation{Schema: 1, Cluster: b.Cluster, Owner: b.Owner, Use: parent.Digest(), Program: [32]byte{4}, SDK: CompileSDKDigest(), Tenant: b.Tenant, UseID: parent.ID, Target: b.Target, DeadlineUnixMilli: b.DeadlineUnixMilli}
	if _, err := store.TaskPreparation(ctx, p.Tenant, p.ID(), false); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("new task not positively missing", err)
	}
	started, err := store.BeginTaskPreparation(ctx, p)
	if err != nil || started.Plan != nil || started.Digest() != p.Digest() {
		t.Fatal("original private scope", err)
	}
	later := p.Clone()
	later.DeadlineUnixMilli += 10000
	kept, err := store.BeginTaskPreparation(ctx, later)
	if err != nil || kept.DeadlineUnixMilli != p.DeadlineUnixMilli {
		t.Fatal("deadline reset on repeated prepare", err)
	}
	for label, change := range map[string]func(*TaskPreparation){
		"program": func(p *TaskPreparation) { p.Program[0]++ },
		"sdk":     func(p *TaskPreparation) { p.SDK[0]++ },
		"use-id":  func(p *TaskPreparation) { p.UseID = "other" },
		"target": func(p *TaskPreparation) {
			if p.Target == "linux/amd64" {
				p.Target = "linux/arm64"
			} else {
				p.Target = "linux/amd64"
			}
		},
	} {
		t.Run(label, func(t *testing.T) {
			changed := p.Clone()
			change(&changed)
			if _, err := store.BeginTaskPreparation(ctx, changed); err == nil {
				t.Fatal("same original scope replaced")
			}
		})
	}
	batch, err = NewCompileBatch(p.ID(), p.DeadlineUnixMilli, policy, []*Compilation{input})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := book.PlanBuild(parent, b.Node, b.Owner, b.Selection, batch)
	if err != nil {
		t.Fatal(err)
	}
	p.Plan = &TaskCompilePlan{Recipes: []CompileRecipe{input.Item().Recipe}, Build: &intent}
	sealed, err := store.SealTaskPreparation(ctx, p)
	if err != nil || sealed.Plan.Build.Digest() != intent.Digest() {
		t.Fatal("original sealed build", err)
	}
	replacement := p.Clone()
	replacement.Plan.Build.Manifest[0]++
	kept, err = store.SealTaskPreparation(ctx, replacement)
	if err != nil || kept.Digest() != sealed.Digest() {
		t.Fatal("concurrent/repeated seal changed original", err)
	}
	sealed.Plan.Recipes[0].Flags[0] = "changed"
	sealed.Plan.Build.Manifest[0]++
	actual, err := store.TaskPreparation(ctx, p.Tenant, p.ID(), false)
	if err != nil || actual.Digest() != p.Digest() {
		t.Fatal("public plan aliases DB", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSources(db, p.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	actual, err = store.TaskPreparation(ctx, p.Tenant, p.ID(), true)
	if err != nil || actual.Digest() != p.Digest() {
		t.Fatal("same DB lost original plan/deadline/job", err)
	}
	if err := db.Write(map[string][]byte{preparationPrefix + preparationKey(p): nil}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TaskPreparation(ctx, p.Tenant, p.ID(), false); !errors.Is(err, ErrPreparation) {
		t.Fatal("known plan loss became new task", err)
	}
	if _, err := store.BeginTaskPreparation(ctx, started); !errors.Is(err, ErrPreparation) {
		t.Fatal("known plan was recreated", err)
	}
	if _, err := store.TaskPreparation(ctx, p.Tenant, p.ID(), true); !errors.Is(err, ErrPreparation) {
		t.Fatal("sync/reload erased known original plan", err)
	}
}

func TestCheckerTaskPreparationRejectsMismatchedBuildAndPreservesCacheOnlyPlan(t *testing.T) {
	_, parent, b, batch, private := buildJobFixture(t)
	db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, b.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	p := TaskPreparation{Schema: 1, Cluster: b.Cluster, Owner: b.Owner, Use: parent.Digest(), Program: [32]byte{4}, SDK: CompileSDKDigest(), Tenant: b.Tenant, UseID: parent.ID, Target: b.Target, DeadlineUnixMilli: b.DeadlineUnixMilli}
	if _, err := store.BeginTaskPreparation(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p.Plan = &TaskCompilePlan{Recipes: []CompileRecipe{batch.Items[0].Recipe}}
	cacheOnly, err := store.SealTaskPreparation(context.Background(), p)
	if err != nil || cacheOnly.Plan.Build != nil {
		t.Fatal("cache hit invented build job", err)
	}
	for label, change := range map[string]func(*TaskPreparation){
		"recipe-source-order": func(p *TaskPreparation) { p.Plan.Recipes = append(p.Plan.Recipes, p.Plan.Recipes[0]) },
		"recipe-tenant":       func(p *TaskPreparation) { p.Plan.Recipes[0].Tenant = "foreign" },
		"recipe-sdk":          func(p *TaskPreparation) { p.Plan.Recipes[0].SDK[0]++ },
		"foreign-build":       func(p *TaskPreparation) { copy := b.Clone(); p.Plan.Build = &copy },
	} {
		t.Run(label, func(t *testing.T) {
			changed := p.Clone()
			change(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
}

func TestCheckerTaskPreparationUnknownSealRecoversOnlyOriginalOrPendingBytes(t *testing.T) {
	for _, mode := range []string{"uncommitted", "committed", "unrelated"} {
		t.Run(mode, func(t *testing.T) {
			_, parent, b, batch, private := buildJobFixture(t)
			db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			store, err := OpenSources(db, b.Cluster, private)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			p := TaskPreparation{Schema: 1, Cluster: b.Cluster, Owner: b.Owner, Use: parent.Digest(), Program: [32]byte{4}, SDK: CompileSDKDigest(), Tenant: b.Tenant, UseID: parent.ID, Target: b.Target, DeadlineUnixMilli: b.DeadlineUnixMilli}
			if _, err := store.BeginTaskPreparation(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			sealed := p.Clone()
			sealed.Plan = &TaskCompilePlan{Recipes: []CompileRecipe{batch.Items[0].Recipe}}
			// Simulate the same DB write returning unknown, not an actual OS
			// sync fault. The recovery Sync/DB decoder/owner are real.
			store.uncertain = true
			store.preparationWrites = map[string][32]byte{preparationKey(p): sealed.Digest()}
			if mode != "uncommitted" {
				value := sealed.Clone()
				if mode == "unrelated" {
					value.Program[0]++
				}
				raw, _ := json.Marshal(value)
				if err := db.Write(map[string][]byte{preparationPrefix + preparationKey(p): raw}); err != nil {
					t.Fatal(err)
				}
			}
			actual, err := store.TaskPreparation(context.Background(), p.Tenant, p.ID(), true)
			if mode == "unrelated" {
				if !errors.Is(err, ErrPreparation) {
					t.Fatal("unrelated valid scope adopted on recover", err)
				}
				return
			}
			if err != nil || store.uncertain {
				t.Fatal("original write not resolved", err)
			}
			expected := p
			if mode == "committed" {
				expected = sealed
			}
			if actual.Digest() != expected.Digest() {
				t.Fatal("recovery invented/replaced original plan")
			}
		})
	}
}
