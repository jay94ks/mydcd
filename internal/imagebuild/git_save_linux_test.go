// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func gitSaveFixture(t *testing.T) (*Spool, *git.Repository, GitSavePlan) {
	t.Helper()
	spool, upload, _, _ := openTestSpool(t, []byte{1})
	repo, commit := gitContextFixture(t, map[string]string{"Dockerfile": "FROM scratch\nCOPY source /source\n", "source": "original"})
	tree, err := WriteGitZIP(context.Background(), repo, commit, ".", "Dockerfile", io.Discard, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	plan := GitSavePlan{Schema: 1, Tenant: upload.Tenant, Context: upload.Context, ID: "git-save-one", Creator: upload.Creator, Root: upload.Root, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20, Commit: commit, Tree: tree.Digest(), CreatedAt: 100, ExpiresAt: 1000}
	return spool, repo, plan
}

func TestGitSaveKeepsCheckedCommitDespiteRefMovementAndUsesOneOriginalArchive(t *testing.T) {
	spool, repo, plan := gitSaveFixture(t)
	ctx := context.Background()
	work, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	file, err := work.Filesystem.Create("source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("new HEAD input")); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = work.Add("source"); err != nil {
		t.Fatal(err)
	}
	if hash, err := work.Commit("moved ref", &git.CommitOptions{Author: &object.Signature{Name: "fixture", Email: "fixture@mydc.test", When: time.Unix(2, 0)}}); err != nil || hash.String() == plan.Commit {
		t.Fatal("fixture ref did not move", err)
	}
	scope, err := spool.PrepareGit(ctx, plan, func(w io.Writer) (Tree, error) {
		return WriteGitZIP(ctx, repo, plan.Commit, ".", plan.Dockerfile, w, plan.ExpandedLimit)
	})
	if err != nil {
		t.Fatal(err)
	}
	original, found, err := spool.loadGitSave(plan)
	if err != nil || !found || original.Inode == 0 {
		t.Fatal("missing original journal", err)
	}
	_, key := testScope(1, [32]byte{1})
	saved, err := spool.AdoptGit(ctx, plan, key)
	if err != nil || !saved.Valid() || saved.Scope != scope || saved.Plan.Commit != plan.Commit {
		t.Fatal("saved original evidence", err)
	}
	h, err := spool.header(scope)
	if err != nil || !matchesGeneratedArchive(h, nativeGeneratedArchive{Scope: scope, Plan: plan.Digest(), Device: original.Device, Inode: original.Inode}) {
		t.Fatal("source was copied/replaced", err)
	}
	if got, err := spool.PrepareGit(ctx, plan, func(io.Writer) (Tree, error) { t.Fatal("resumed save reran generator"); return Tree{}, ErrStorage }); err != nil || got != scope {
		t.Fatal("same original not recovered after rename", got, err)
	}
	reader, err := spool.Open(ctx, scope, saved.Fact)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := InspectZIP(ctx, bytes.NewReader(raw), int64(len(raw)), plan.Dockerfile, plan.ExpandedLimit)
	if err != nil || tree.Digest() != plan.Tree {
		t.Fatal("latest ref replaced checked source", err)
	}
	u := Upload{Scope: scope, Revision: 1, Closed: true, Version: VersionID(saved.Fact)}
	if err := spool.Reclaim(u, false); !errors.Is(err, ErrUsed) {
		t.Fatal("open reader did not protect original archive", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.Reclaim(u, false); err != nil {
		t.Fatal("same generated archive GC not reused", err)
	}
}

func TestGitSaveRecoversCompletionFromTheSameArchiveAndRejectsChangedPlan(t *testing.T) {
	spool, repo, plan := gitSaveFixture(t)
	ctx := context.Background()
	if recorded, err := GitSaveRecorded(spool.db, plan); err != nil || recorded {
		t.Fatal("metadata-only probe created a new save", recorded, err)
	}
	scope, err := spool.PrepareGit(ctx, plan, func(w io.Writer) (Tree, error) {
		return WriteGitZIP(ctx, repo, plan.Commit, ".", plan.Dockerfile, w, plan.ExpandedLimit)
	})
	if err != nil {
		t.Fatal(err)
	}
	h, _, err := spool.loadGitSave(plan)
	if err != nil {
		t.Fatal(err)
	}
	inode := h.Inode
	if recorded, err := GitSaveRecorded(spool.db, plan); err != nil || !recorded {
		t.Fatal("retained original was not discoverable without new staging", recorded, err)
	}
	h.Scope = nil
	if err := spool.saveGit(h); err != nil {
		t.Fatal(err)
	}
	if got, err := spool.PrepareGit(ctx, plan, nil); err != nil || got != scope {
		t.Fatal("complete original not adopted after record loss", got, err)
	}
	h, _, err = spool.loadGitSave(plan)
	if err != nil || h.Inode != inode {
		t.Fatal("completion repair changed original inode", err)
	}
	other := plan
	other.PolicyRevision++
	if _, err := spool.PrepareGit(ctx, other, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("same ID retargeted to changed policy", err)
	}
}

func TestGitSaveRetainsPartialOriginalWithoutRegeneratingOrTruncating(t *testing.T) {
	spool, _, plan := gitSaveFixture(t)
	ctx := context.Background()
	_, err := spool.PrepareGit(ctx, plan, func(w io.Writer) (Tree, error) {
		_, err := w.Write([]byte("partial original"))
		if err != nil {
			return Tree{}, err
		}
		return Tree{}, ErrSourceFetch
	})
	if !errors.Is(err, ErrSourceFetch) {
		t.Fatal(err)
	}
	if _, err := spool.PrepareGit(ctx, plan, func(io.Writer) (Tree, error) { t.Fatal("partial original regenerated"); return Tree{}, nil }); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("partial source not preserved", err)
	}
	name := filepath.Join(plan.Root.Path, ".mydc-imagebuild", gitSaveName(plan))
	if raw, err := os.ReadFile(name); err != nil || string(raw) != "partial original" {
		t.Fatal("partial source truncated/replaced", err)
	}
}

func TestGitSaveRefusesForeignDestinationOrReplacedOriginalInode(t *testing.T) {
	for _, target := range []bool{false, true} {
		t.Run(map[bool]string{false: "source", true: "destination"}[target], func(t *testing.T) {
			spool, repo, plan := gitSaveFixture(t)
			ctx := context.Background()
			scope, err := spool.PrepareGit(ctx, plan, func(w io.Writer) (Tree, error) {
				return WriteGitZIP(ctx, repo, plan.Commit, ".", plan.Dockerfile, w, plan.ExpandedLimit)
			})
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(plan.Root.Path, ".mydc-imagebuild", gitSaveName(plan))
			if target {
				name = filepath.Join(plan.Root.Path, ".mydc-imagebuild", scopeName(scope)+".zip")
			} else {
				if err := os.Rename(name, name+"-original"); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(name, []byte("foreign source"), 0600); err != nil {
				t.Fatal(err)
			}
			_, key := testScope(1, [32]byte{1})
			if _, err := spool.AdoptGit(ctx, plan, key); err == nil {
				t.Fatal("foreign inode/destination accepted")
			}
			if raw, err := os.ReadFile(name); err != nil || string(raw) != "foreign source" {
				t.Fatal("foreign native content overwritten", err)
			}
		})
	}
}
