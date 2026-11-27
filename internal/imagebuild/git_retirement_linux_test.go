// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

func gitStageGrantFixture(plan GitSavePlan) (GitStageGrant, reconcile.Lease) {
	return GitStageGrant{Plan: plan, ContextRevision: plan.ContextRevision, PolicyRevision: plan.PolicyRevision, Index: 20, Epoch: 1}, reconcile.Lease{Generation: plan.Root.Generation, Token: 7}
}

func failedGitStageFixture(t *testing.T) (*Spool, GitSavePlan) {
	t.Helper()
	spool, _, plan := gitSaveFixture(t)
	_, err := spool.PrepareGit(context.Background(), plan, func(w io.Writer) (Tree, error) {
		_, err := io.WriteString(w, "partial original archive")
		return Tree{}, errors.Join(ErrSourceFetch, err)
	})
	if !errors.Is(err, ErrSourceFetch) {
		t.Fatal(err)
	}
	return spool, plan
}

// Native files/DB are real; the shared monotonic fence/lease are fixture
// inputs. Real RootManager and shared FSM checks are separate adapter tests.
func TestGitStageRetirementPreservesAdoptedArchiveAndOriginalReplay(t *testing.T) {
	spool, repo, plan := gitSaveFixture(t)
	ctx := context.Background()
	scope, err := spool.PrepareGit(ctx, plan, func(w io.Writer) (Tree, error) {
		return WriteGitZIP(ctx, repo, plan.Commit, ".", plan.Dockerfile, w, plan.ExpandedLimit)
	})
	if err != nil {
		t.Fatal(err)
	}
	_, key := testScope(1, [32]byte{1})
	saved, err := spool.AdoptGit(ctx, plan, key)
	if err != nil {
		t.Fatal(err)
	}
	g, lease := gitStageGrantFixture(plan)
	plans, err := StoredGitStages(spool.db, plan.Root, plan.Tenant, plan.Context, func(GitSavePlan) (bool, error) { return false, nil }, 4)
	if err != nil || len(plans) != 1 || plans[0] != plan {
		t.Fatal("current transferred stage not discovered", plans, err)
	}
	if err := spool.RetireGitStage(ctx, g, lease); err != nil {
		t.Fatal(err)
	}
	owners, err := StoredInputRootOwners(spool.db, plan.Root)
	if owner := owners[GitRootConsumer(plan)]; err != nil || owner.Required || !owner.Pending || !owners[ArtifactRootConsumer(scope)].Required {
		t.Fatal("independent consumer accounting", owners, err)
	}
	wrong := lease
	wrong.Token++
	if err := FinishGitStageRetirement(spool.db, plan, wrong); err == nil {
		t.Fatal("wrong lease settled stage")
	}
	if err := FinishGitStageRetirement(spool.db, plan, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.PrepareGit(ctx, plan, func(io.Writer) (Tree, error) {
		t.Fatal("returned stage refetched/rebuilt")
		return Tree{}, ErrSourceFetch
	}); err != nil {
		t.Fatal(err)
	}
	again, err := spool.AdoptGit(ctx, plan, key)
	if err != nil || string(SavedGitBytes(again)) != string(SavedGitBytes(saved)) || string(again.Signature) != string(saved.Signature) {
		t.Fatal("original archive reply changed", err)
	}
	reader, err := spool.Open(ctx, scope, again.Fact)
	if err != nil {
		t.Fatal(err)
	}
	n, readErr := io.Copy(io.Discard, reader)
	if closeErr := reader.Close(); readErr != nil || closeErr != nil || n != scope.Length {
		t.Fatal(n, readErr, closeErr)
	}
	owners, err = StoredInputRootOwners(spool.db, plan.Root)
	if owner := owners[GitRootConsumer(plan)]; err != nil || owner.Required || owner.Pending || !owners[ArtifactRootConsumer(scope)].Required {
		t.Fatal("stage settlement removed archive", owners, err)
	}
	plans, err = StoredGitStages(spool.db, plan.Root, plan.Tenant, plan.Context, func(GitSavePlan) (bool, error) { return true, nil }, 4)
	if err != nil || len(plans) != 0 {
		t.Fatal("returned stage rediscovered", plans, err)
	}
}

func TestGitStagePartialRetirementRequiresCommittedFenceAndCannotRegenerate(t *testing.T) {
	spool, plan := failedGitStageFixture(t)
	g, lease := gitStageGrantFixture(plan)
	if err := spool.RetireGitStage(context.Background(), g, lease); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("current partial removed", err)
	}
	_, r, found, err := GitStageState(spool.db, plan)
	if err != nil || !found || r != nil {
		t.Fatal("refusal recorded a deletion intent", r, err)
	}
	plans, err := StoredGitStages(spool.db, plan.Root, plan.Tenant, plan.Context, func(GitSavePlan) (bool, error) { return false, nil }, 1)
	if err != nil || len(plans) != 0 {
		t.Fatal("protected partial consumed collection batch", plans, err)
	}
	g.PolicyRevision++
	if err := spool.RetireGitStage(context.Background(), g, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(plan.Root.Path, ".sfc-imagebuild", gitSaveName(plan))); !os.IsNotExist(err) {
		t.Fatal("partial source retained", err)
	}
	if err := FinishGitStageRetirement(spool.db, plan, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.PrepareGit(context.Background(), plan, func(io.Writer) (Tree, error) { t.Fatal("discarded plan regenerated"); return Tree{}, nil }); !errors.Is(err, ErrUsed) {
		t.Fatal(err)
	}
}

func TestGitStageRetirementResumesIntentUnlinkAndReturnCommitFailures(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(map[int]string{1: "intent", 2: "unlink", 3: "return"}[failAt], func(t *testing.T) {
			spool, plan := failedGitStageFixture(t)
			g, lease := gitStageGrantFixture(plan)
			g.ContextRevision++
			original := spool.db
			spool.db = &draftGCFailureDB{Transactions: original, failAt: failAt}
			err := spool.RetireGitStage(context.Background(), g, lease)
			if failAt == 3 {
				if err != nil {
					t.Fatal(err)
				}
				err = FinishGitStageRetirement(spool.db, plan, lease)
			}
			if !errors.Is(err, errDraftGCCommit) {
				t.Fatal("missing injected boundary", err)
			}
			_, pathErr := os.Stat(filepath.Join(plan.Root.Path, ".sfc-imagebuild", gitSaveName(plan)))
			if failAt == 1 && pathErr != nil || failAt != 1 && !os.IsNotExist(pathErr) {
				t.Fatal("incorrect unlink boundary", pathErr)
			}
			spool.db = original
			if err := spool.RetireGitStage(context.Background(), g, lease); err != nil {
				t.Fatal("original retirement did not resume", err)
			}
			if err := FinishGitStageRetirement(spool.db, plan, lease); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGitStageRetirementRejectsReplacedMissingAndUnrecordedNonemptySource(t *testing.T) {
	for _, cause := range []string{"replacement", "missing", "unrecorded-nonempty"} {
		t.Run(cause, func(t *testing.T) {
			spool, plan := failedGitStageFixture(t)
			g, lease := gitStageGrantFixture(plan)
			g.ContextRevision++
			name := filepath.Join(plan.Root.Path, ".sfc-imagebuild", gitSaveName(plan))
			switch cause {
			case "replacement":
				if err := os.Rename(name, name+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte("replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
			case "unrecorded-nonempty":
				h, _, err := spool.loadGitSave(plan)
				if err != nil {
					t.Fatal(err)
				}
				h.Device, h.Inode = 0, 0
				if err := spool.saveGit(h); err != nil {
					t.Fatal(err)
				}
			}
			if err := spool.RetireGitStage(context.Background(), g, lease); !errors.Is(err, ErrStorage) {
				t.Fatal("unsafe source accepted", err)
			}
			_, r, _, err := GitStageState(spool.db, plan)
			if err != nil || r != nil {
				t.Fatal("refusal mutated retirement", r, err)
			}
		})
	}
}

func TestGitStageRetirementClosesOnlyEmptyCreationIntentWithoutInode(t *testing.T) {
	for _, created := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-create", true: "empty-before-inode-commit"}[created], func(t *testing.T) {
			spool, _, plan := gitSaveFixture(t)
			if err := spool.saveGit(nativeGitSave{Plan: plan}); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(plan.Root.Path, ".sfc-imagebuild", gitSaveName(plan))
			if created {
				if err := os.WriteFile(name, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			g, lease := gitStageGrantFixture(plan)
			g.Deleted = true
			g.ContextRevision++
			if err := spool.RetireGitStage(context.Background(), g, lease); err != nil {
				t.Fatal(err)
			}
			if err := FinishGitStageRetirement(spool.db, plan, lease); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(name); !os.IsNotExist(err) {
				t.Fatal("original creation intent not closed", err)
			}
		})
	}
}
