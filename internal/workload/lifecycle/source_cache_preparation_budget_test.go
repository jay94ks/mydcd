// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestCheckerSourceCacheBudgetPreparationEntryCapPreservesOriginalSeal(t *testing.T) {
	ctx := context.Background()
	_, parent, intent, batch, _ := buildJobFixture(t)
	group := &SourceCacheBudget{}
	old, db, _ := groupedSourceStore(t, group, intent.Cluster, 61)
	current, _, _ := groupedSourceStore(t, group, intent.Cluster, 62)
	original := TaskPreparation{Schema: 1, Cluster: intent.Cluster, Owner: old.identity.Node, Use: parent.Digest(), Program: [32]byte{4}, SDK: CompileSDKDigest(), Tenant: intent.Tenant, UseID: parent.ID, Target: intent.Target, DeadlineUnixMilli: intent.DeadlineUnixMilli}
	// Existing persisted original preparations are finite explicit fixture input.
	// Actual reload, entry admission and later sealing all use SourceStore.
	rows := map[string][]byte{}
	for i := 0; i < maxSourceEntries-1; i++ {
		p := original
		p.Use = sha256.Sum256([]byte(fmt.Sprintf("original-preparation-%d", i)))
		raw, err := json.Marshal(p)
		if err != nil || p.Validate() != nil {
			t.Fatal("invalid preparation fixture", err)
		}
		rows[preparationPrefix+preparationKey(p)] = raw
	}
	if err := db.Write(rows); err != nil {
		t.Fatal(err)
	}
	first := original
	first.Use = sha256.Sum256([]byte("original-preparation-0"))
	if _, err := old.TaskPreparation(ctx, first.Tenant, first.ID(), true); err != nil {
		t.Fatal(err)
	}
	draft := original
	draft.Owner = current.identity.Node
	begun, err := current.BeginTaskPreparation(ctx, draft)
	if err != nil {
		t.Fatal("last shared preparation slot refused", err)
	}
	other := draft
	other.Use[0]++
	if _, err = current.BeginTaskPreparation(ctx, other); !errors.Is(err, ErrPreparation) {
		t.Fatal("new key reset preparation entry cap", err)
	}
	before := current.preparationBytes
	sealed := begun.Clone()
	sealed.Plan = &TaskCompilePlan{Recipes: []CompileRecipe{batch.Items[0].Recipe}}
	accepted, err := current.SealTaskPreparation(ctx, sealed)
	if err != nil || accepted.Digest() != sealed.Digest() {
		t.Fatal("existing original could not seal at full shared entry capacity", err)
	}
	raw, _ := json.Marshal(accepted)
	if current.preparationBytes != uint64(len(raw)) || current.preparationBytes < before || old.preparationBytes == 0 {
		t.Fatal("seal overwrote local preparation counter with global total")
	}
	recovered, err := current.TaskPreparation(ctx, sealed.Tenant, sealed.ID(), true)
	if err != nil || recovered.Digest() != sealed.Digest() || recovered.DeadlineUnixMilli != draft.DeadlineUnixMilli {
		t.Fatal("recovery replaced original preparation/deadline", err)
	}
	if _, err = current.BeginTaskPreparation(ctx, other); !errors.Is(err, ErrPreparation) {
		t.Fatal("recovery reset other namespace's preparation cap", err)
	}
}
