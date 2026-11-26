// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Native bytes, original inode/ZIP and DB are real; current quorum authority
// and archive root leases are injected. Real FSM/RootManager tests are separate.
func generatedRetirementFixture(t *testing.T, kind string, adopted bool) (*Spool, GeneratedArchiveGrant, string) {
	t.Helper()
	ctx := context.Background()
	var spool *Spool
	var a GeneratedArtifact
	var source string
	_, key := testScope(1, [32]byte{1})
	if kind == "draft" {
		store, s, p := frozenDraftFixture(t)
		spool = s
		scope, err := store.PrepareFreeze(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		a = GeneratedArtifact{Scope: scope, Draft: &p}
		source = filepath.Join(scope.Root.Path, ".mydc-imagebuild", string(store.key), freezeName(p))
		if adopted {
			if _, err := store.AdoptFreeze(ctx, p, key); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		s, repo, p := gitSaveFixture(t)
		spool = s
		scope, err := spool.PrepareGit(ctx, p, func(w io.Writer) (Tree, error) {
			return WriteGitZIP(ctx, repo, p.Commit, ".", p.Dockerfile, w, p.ExpandedLimit)
		})
		if err != nil {
			t.Fatal(err)
		}
		a = GeneratedArtifact{Scope: scope, Git: &p}
		source = filepath.Join(scope.Root.Path, ".mydc-imagebuild", gitSaveName(p))
		if adopted {
			if _, err := spool.AdoptGit(ctx, p, key); err != nil {
				t.Fatal(err)
			}
		}
	}
	g := GeneratedArchiveGrant{Artifact: a, ContextRevision: a.Scope.ContextRevision, PolicyRevision: a.Scope.PolicyRevision + 1, Index: 20, Epoch: 1}
	return spool, g, source
}

func TestGeneratedRetirementReusesOriginalPlacementAndDeletionWithoutFabricatingSeal(t *testing.T) {
	for _, kind := range []string{"draft", "git"} {
		for _, mode := range []string{"prepared-unborrowed", "prepared-borrowed", "adopted"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				spool, g, source := generatedRetirementFixture(t, kind, mode == "adopted")
				a := g.Artifact
				original, _, err := spool.generatedSource(a)
				if err != nil {
					t.Fatal(err)
				}
				lease := reconcile.Lease{}
				if mode != "prepared-unborrowed" {
					lease = reconcile.Lease{Generation: a.Scope.Root.Generation, Token: 7}
				}
				if err := spool.ReclaimGenerated(context.Background(), g, lease); err != nil {
					t.Fatal(err)
				}
				h, err := spool.header(a.Scope)
				if err != nil || !h.Deleted || !generatedIdentity(h, original) || h.Unpublished == nil || !h.Unpublished.Returning || h.Unpublished.Borrowed != (lease.Token != 0) || (h.Seal != nil) != (mode == "adopted") {
					t.Fatal("original inode/evidence changed or cleanup fabricated a seal", h, err)
				}
				for _, name := range []string{source, filepath.Join(a.Scope.Root.Path, ".mydc-imagebuild", scopeName(a.Scope)+".zip")} {
					if _, err := os.Stat(name); !os.IsNotExist(err) {
						t.Fatal("original source/body retained", name, err)
					}
				}
				owners, err := StoredInputRootOwners(spool.db, a.Scope.Root)
				if owner := owners[ArtifactRootConsumer(a.Scope)]; err != nil || owner.Required || !owner.Pending {
					t.Fatal("unsettled artifact omitted", owner, err)
				}
				wrong := lease
				wrong.Token++
				if err := FinishGeneratedRetirement(spool.db, a, wrong); err == nil {
					t.Fatal("replacement lease settled original archive")
				}
				if err := FinishGeneratedRetirement(spool.db, a, lease); err != nil {
					t.Fatal(err)
				}
				owners, err = StoredInputRootOwners(spool.db, a.Scope.Root)
				if owner := owners[ArtifactRootConsumer(a.Scope)]; err != nil || owner.Required || owner.Pending {
					t.Fatal("returned artifact still pending", owner, err)
				}
				artifacts, _, err := StoredGeneratedArtifacts(spool.db, a.Scope.Root, a.Scope.Tenant, a.Scope.Context, "", func(GeneratedArtifact) (bool, error) { return true, nil }, 4)
				if err != nil || len(artifacts) != 0 {
					t.Fatal("returned archive rediscovered", artifacts, err)
				}
				if a.Draft != nil {
					anchor, found, err := DraftStoredScope(spool.db, a.Draft.Scope)
					if err != nil || !found {
						t.Fatal("original draft metadata removed", err)
					}
					dg := DraftRetirementGrant{Scope: anchor, ContextRevision: g.ContextRevision + 1, Generation: anchor.Data().Generation, Deleted: true, Index: 21, Epoch: 1}
					if err := spool.RetireDraft(context.Background(), dg, reconcile.Lease{Generation: anchor.Root.Generation, Token: 9}); err != nil {
						t.Fatal("native archive completion failed to release whole draft", err)
					}
				} else {
					sg := GitStageGrant{Plan: *a.Git, ContextRevision: g.ContextRevision, PolicyRevision: g.PolicyRevision, Index: 21, Epoch: 1}
					if err := spool.RetireGitStage(context.Background(), sg, reconcile.Lease{Generation: a.Scope.Root.Generation, Token: 9}); err != nil {
						t.Fatal("native archive completion failed to release Git stage", err)
					}
				}
			})
		}
	}
}

func TestGeneratedRetirementRecoversEveryOriginalCommitBoundary(t *testing.T) {
	for _, kind := range []string{"draft", "git"} {
		for _, failAt := range []int{1, 2, 3, 4, 5} {
			t.Run(kind+"/"+map[int]string{1: "intent", 2: "deleting", 3: "deleted", 4: "returning", 5: "returned"}[failAt], func(t *testing.T) {
				spool, g, source := generatedRetirementFixture(t, kind, false)
				original := spool.db
				failure := &draftGCFailureDB{Transactions: original, failAt: failAt}
				spool.db = failure
				err := spool.ReclaimGenerated(context.Background(), g, reconcile.Lease{})
				if failAt == 5 {
					if err != nil {
						t.Fatal(err)
					}
					err = FinishGeneratedRetirement(spool.db, g.Artifact, reconcile.Lease{})
				}
				expected := errDraftGCCommit
				if failAt == 2 {
					// Spool sanitizes the pre-unlink intent commit failure. The
					// injected transaction count still proves this exact boundary.
					expected = ErrStorage
				}
				if !errors.Is(err, expected) || failure.calls != failAt {
					t.Fatal("injected commit boundary missing", err)
				}
				_, sourceErr := os.Stat(source)
				_, bodyErr := os.Stat(filepath.Join(g.Artifact.Scope.Root.Path, ".mydc-imagebuild", scopeName(g.Artifact.Scope)+".zip"))
				if failAt == 1 && sourceErr != nil || failAt != 1 && !os.IsNotExist(sourceErr) || failAt == 2 && bodyErr != nil || failAt > 2 && !os.IsNotExist(bodyErr) {
					t.Fatal("wrong native mutation boundary", sourceErr, bodyErr)
				}
				spool.db = original
				if err := spool.ReclaimGenerated(context.Background(), g, reconcile.Lease{}); err != nil {
					t.Fatal("original intent could not resume", err)
				}
				if err := FinishGeneratedRetirement(spool.db, g.Artifact, reconcile.Lease{}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestGeneratedRetirementRejectsCurrentMissingOrReplacedSourceBeforeIntent(t *testing.T) {
	for _, kind := range []string{"draft", "git"} {
		for _, cause := range []string{"current", "missing", "replacement"} {
			t.Run(kind+"/"+cause, func(t *testing.T) {
				spool, g, source := generatedRetirementFixture(t, kind, false)
				switch cause {
				case "current":
					g.PolicyRevision--
				case "missing":
					if err := os.Remove(source); err != nil {
						t.Fatal(err)
					}
				case "replacement":
					if err := os.Rename(source, source+".original"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(source, []byte("replacement"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := spool.ReclaimGenerated(context.Background(), g, reconcile.Lease{}); err == nil {
					t.Fatal("unsafe native cleanup accepted")
				}
				if r, err := GeneratedArchiveState(spool.db, g.Artifact); err != nil || r != nil {
					t.Fatal("refusal created deletion intent", r, err)
				}
			})
		}
	}
}

func TestGeneratedRetirementProtectsOpenArchiveReaderAndNeedsOriginalBorrow(t *testing.T) {
	spool, g, _ := generatedRetirementFixture(t, "git", true)
	_, key := testScope(1, [32]byte{1})
	saved, err := spool.AdoptGit(context.Background(), *g.Artifact.Git, key)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := spool.Open(context.Background(), saved.Scope, saved.Fact)
	if err != nil {
		t.Fatal(err)
	}
	lease := reconcile.Lease{Generation: saved.Scope.Root.Generation, Token: 7}
	if err := spool.ReclaimGenerated(context.Background(), g, lease); !errors.Is(err, ErrUsed) {
		t.Fatal("live archive reader ignored", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.ReclaimGenerated(context.Background(), g, reconcile.Lease{}); !errors.Is(err, ErrStorage) {
		t.Fatal("missing required archive pin treated as never borrowed", err)
	}
	if err := spool.ReclaimGenerated(context.Background(), g, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.AdoptGit(context.Background(), *g.Artifact.Git, key); err == nil {
		t.Fatal("retired artifact resurrected by adoption")
	}
}

func TestGeneratedDiscoveryPagesOriginalPlansWithoutProtectedRowsConsumingBatch(t *testing.T) {
	spool, repo, original := gitSaveFixture(t)
	var plans []GitSavePlan
	for _, id := range []string{"one", "two", "protected"} {
		plan := original
		plan.ID = id
		if _, err := spool.PrepareGit(context.Background(), plan, func(w io.Writer) (Tree, error) {
			return WriteGitZIP(context.Background(), repo, plan.Commit, ".", plan.Dockerfile, w, plan.ExpandedLimit)
		}); err != nil {
			t.Fatal(err)
		}
		plans = append(plans, plan)
	}
	seen := map[string]bool{}
	after := ""
	for page := 0; page < 4; page++ {
		artifacts, next, err := StoredGeneratedArtifacts(spool.db, original.Root, original.Tenant, original.Context, after, func(a GeneratedArtifact) (bool, error) { return a.Git.ID != "protected", nil }, 1)
		if err != nil || len(artifacts) > 1 {
			t.Fatal(artifacts, err)
		}
		for _, a := range artifacts {
			if seen[a.Git.ID] || a.Git.ID == "protected" {
				t.Fatal("page repeated or selected a protected source", a)
			}
			seen[a.Git.ID] = true
		}
		after = next
		if next == "" {
			break
		}
	}
	if !seen[plans[0].ID] || !seen[plans[1].ID] || len(seen) != 2 || after != "" {
		t.Fatal("finite pages omitted an original eligible source", seen, after)
	}
	artifacts, _, err := StoredGeneratedArtifacts(spool.db, original.Root, "other", original.Context, "", func(GeneratedArtifact) (bool, error) { return true, nil }, 4)
	if err != nil || len(artifacts) != 0 {
		t.Fatal("other tenant included", artifacts, err)
	}
}
