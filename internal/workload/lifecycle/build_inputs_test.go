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

// Real local source DB and the same sealed source/SDK/batch producer. No
// current quorum, compiler process/container or successful binary is claimed.
func TestCheckerPrepareBuildReconstructsExactAcceptedManifestFromActualCache(t *testing.T) {
	ctx := context.Background()
	_, _, intent, expected, private := buildJobFixture(t)
	_, policy := compilationFixture(t)
	db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, intent.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if store != nil {
			store.Close()
		}
	}()
	facts := intent.Selection.Sources
	if _, _, err := store.PrepareBuild(ctx, intent, policy, facts); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("missing bytes inferred/fetched", err)
	}
	if _, err := store.Stage(ctx, expected.Items[0].Source, []byte(compileTestSource), policy); err != nil {
		t.Fatal(err)
	}
	batch, inputs, err := store.PrepareBuild(ctx, intent, policy, facts)
	if err != nil || len(inputs) != 1 || intent.ValidateCompilation(policy, batch) != nil {
		t.Fatal("same production preparation", err)
	}
	a, _ := json.Marshal(batch)
	b, _ := json.Marshal(expected)
	if string(a) != string(b) || inputs[0].Item().Key != intent.Inputs[0].Recipe {
		t.Fatal("rebuilt different manifest/recipe")
	}
	for label, mutate := range map[string]func(*BuildIntent, *TenantPolicy){
		"manifest": func(b *BuildIntent, _ *TenantPolicy) { b.Manifest[0]++ },
		"recipe":   func(b *BuildIntent, _ *TenantPolicy) { b.Inputs[0].Recipe[0]++ },
		"source":   func(b *BuildIntent, _ *TenantPolicy) { b.Inputs[0].Content[0]++ },
		"job":      func(b *BuildIntent, _ *TenantPolicy) { b.ID = hashText("other-original-job") },
		"deadline": func(b *BuildIntent, _ *TenantPolicy) { b.DeadlineUnixMilli++ },
		"policy":   func(_ *BuildIntent, p *TenantPolicy) { p.Revision++ },
		"target": func(b *BuildIntent, _ *TenantPolicy) {
			if b.Target == "linux/amd64" {
				b.Target = "linux/arm64"
			} else {
				b.Target = "linux/amd64"
			}
		},
	} {
		t.Run(label, func(t *testing.T) {
			b, p := intent.Clone(), policy.Clone()
			mutate(&b, &p)
			if _, _, err := store.PrepareBuild(ctx, b, p, facts); err == nil {
				t.Fatal("different original preparation accepted")
			}
		})
	}
	if _, _, err := store.PrepareBuild(ctx, intent, policy, append(facts, facts[0])); err == nil {
		t.Fatal("extra source widened batch")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSources(db, intent.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	again, _, err := store.PrepareBuild(ctx, intent, policy, facts)
	if err != nil || intent.ValidateCompilation(policy, again) != nil {
		t.Fatal("same DB did not preserve exact preparation", err)
	}
}
