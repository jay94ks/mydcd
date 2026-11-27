// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

// Actual original ZIP/seal/file identity/DB. Current user authority and root
// leases are fixture inputs, not evidence of actual Raft/RootManager admission.
func TestGeneratedResultPreservesExactOriginalSignaturesAfterBodyReclaimWithoutWrites(t *testing.T) {
	for _, kind := range []string{"draft", "git"} {
		t.Run(kind, func(t *testing.T) {
			spool, g, _ := generatedRetirementFixture(t, kind, true)
			_, key := testScope(1, [32]byte{1})
			a := g.Artifact
			var frozen FrozenDraft
			var saved SavedGit
			var err error
			if a.Draft != nil {
				store, cause := OpenDraftStore(spool, a.Draft.Scope, false)
				if cause != nil {
					t.Fatal(cause)
				}
				frozen, err = store.AdoptFreeze(context.Background(), *a.Draft, key)
				err = errors.Join(err, store.Close())
			} else {
				saved, err = spool.AdoptGit(context.Background(), *a.Git, key)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := spool.ReclaimGenerated(context.Background(), g, reconcile.Lease{Generation: a.Scope.Root.Generation, Token: 7}); err != nil {
				t.Fatal(err)
			}
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			// Any Update would fail. Files are already deleted and no descriptor
			// or RootManager is available to reconstruct/initialize an archive.
			db := &draftGCFailureDB{Transactions: spool.db, failAt: 1}
			if a.Draft != nil {
				out, err := StoredDraftFreezeResult(db, *a.Draft, key)
				if err != nil || out.Code != "FROZEN" || !out.Reclaimed || out.Frozen == nil || !bytes.Equal(FrozenDraftBytes(*out.Frozen), FrozenDraftBytes(frozen)) || !bytes.Equal(out.Frozen.Signature, frozen.Signature) {
					t.Fatal("original freeze result/signature changed", out, err)
				}
			} else {
				out, err := StoredGitSaveResult(db, *a.Git, key)
				if err != nil || out.Code != "SAVED" || !out.Reclaimed || out.Saved == nil || !bytes.Equal(SavedGitBytes(*out.Saved), SavedGitBytes(saved)) || !bytes.Equal(out.Saved.Signature, saved.Signature) {
					t.Fatal("original Git result/signature changed", out, err)
				}
			}
		})
	}
}

func TestGeneratedResultNeverTurnsPreparedSealAbsenceIntoSuccess(t *testing.T) {
	for _, kind := range []string{"draft", "git"} {
		t.Run(kind, func(t *testing.T) {
			spool, g, _ := generatedRetirementFixture(t, kind, false)
			_, key := testScope(1, [32]byte{1})
			query := func(want string) {
				t.Helper()
				if g.Artifact.Draft != nil {
					out, err := StoredDraftFreezeResult(spool.db, *g.Artifact.Draft, key)
					if err != nil || out.Code != want || out.Frozen != nil || out.Reclaimed {
						t.Fatal("prepared freeze invented success", out, err)
					}
				} else {
					out, err := StoredGitSaveResult(spool.db, *g.Artifact.Git, key)
					if err != nil || out.Code != want || out.Saved != nil || out.Reclaimed {
						t.Fatal("prepared Git invented success", out, err)
					}
				}
			}
			query("PENDING")
			if err := spool.ReclaimGenerated(context.Background(), g, reconcile.Lease{}); err != nil {
				t.Fatal(err)
			}
			query("DISCARDED")
		})
	}
}

func TestGeneratedResultReadsMetadataWithUnavailableFilesAndDoesNotInferReclamation(t *testing.T) {
	for _, kind := range []string{"draft", "git"} {
		t.Run(kind, func(t *testing.T) {
			spool, g, _ := generatedRetirementFixture(t, kind, true)
			_, key := testScope(1, [32]byte{1})
			if err := spool.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(g.Artifact.Scope.Root.Path, ".sfc-imagebuild")
			if err := os.Rename(path, path+".offline"); err != nil {
				t.Fatal(err)
			}
			if g.Artifact.Draft != nil {
				out, err := StoredDraftFreezeResult(spool.db, *g.Artifact.Draft, key)
				if err != nil || out.Code != "FROZEN" || out.Reclaimed || out.Frozen == nil {
					t.Fatal(out, err)
				}
				changed := *g.Artifact.Draft
				changed.Draft[0] ^= 1
				if _, err := StoredDraftFreezeResult(spool.db, changed, key); !errors.Is(err, ErrConflict) {
					t.Fatal("same ID/different freeze plan accepted", err)
				}
			} else {
				out, err := StoredGitSaveResult(spool.db, *g.Artifact.Git, key)
				if err != nil || out.Code != "SAVED" || out.Reclaimed || out.Saved == nil {
					t.Fatal(out, err)
				}
				changed := *g.Artifact.Git
				changed.Tree[0] ^= 1
				if _, err := StoredGitSaveResult(spool.db, changed, key); !errors.Is(err, ErrConflict) {
					t.Fatal("same ID/different Git plan accepted", err)
				}
			}
			wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32))
			if g.Artifact.Draft != nil {
				if _, err := StoredDraftFreezeResult(spool.db, *g.Artifact.Draft, wrongKey); err == nil {
					t.Fatal("foreign key manufactured original freeze evidence")
				}
			} else if _, err := StoredGitSaveResult(spool.db, *g.Artifact.Git, wrongKey); err == nil {
				t.Fatal("foreign key manufactured original Git evidence")
			}
		})
	}
}

func TestGeneratedResultDistinguishesPartialMissingAndDiscardedOriginalIntents(t *testing.T) {
	spool, plan := failedGitStageFixture(t)
	_, key := testScope(1, [32]byte{1})
	if out, err := StoredGitSaveResult(spool.db, plan, key); err != nil || out.Code != "PENDING" || out.Saved != nil {
		t.Fatal(out, err)
	}
	g, lease := gitStageGrantFixture(plan)
	g.ContextRevision++
	if err := spool.RetireGitStage(context.Background(), g, lease); err != nil {
		t.Fatal(err)
	}
	if out, err := StoredGitSaveResult(spool.db, plan, key); err != nil || out.Code != "DISCARDED" || out.Saved != nil {
		t.Fatal(out, err)
	}
	missing := plan
	missing.ID = "missing"
	if out, err := StoredGitSaveResult(spool.db, missing, key); err != nil || out.Code != "NOT_INITIALIZED" {
		t.Fatal(out, err)
	}

	store, draftSpool, freeze := frozenDraftFixture(t)
	original := draftSpool.db
	draftSpool.db = &draftGCFailureDB{Transactions: original, failAt: 2}
	if _, err := store.PrepareFreeze(context.Background(), freeze); !errors.Is(err, errDraftGCCommit) {
		t.Fatal(err)
	}
	draftSpool.db = original
	if out, err := StoredDraftFreezeResult(original, freeze, key); err != nil || out.Code != "PENDING" || out.Frozen != nil {
		t.Fatal(out, err)
	}
	if _, err := store.CollectUnpreparedFreezes(context.Background(), func(DraftFreezePlan) (bool, error) { return true, nil }, 16); err != nil {
		t.Fatal(err)
	}
	if out, err := StoredDraftFreezeResult(original, freeze, key); err != nil || out.Code != "DISCARDED" || out.Frozen != nil {
		t.Fatal(out, err)
	}
	freeze.ID = "missing"
	if out, err := StoredDraftFreezeResult(original, freeze, key); err != nil || out.Code != "NOT_INITIALIZED" {
		t.Fatal(out, err)
	}
}
