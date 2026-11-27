// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	bolt "go.etcd.io/bbolt"
)

func nativeTestRoot(t *testing.T, spec JobSpec) *os.File {
	t.Helper()
	f, err := os.Open(spec.Scope.Root.Path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// A second owner object represents another accepted job against the same
// original DB/root. The callbacks stand in for quorum, never for native files.
func anotherWorkspaceJob(t *testing.T, f *nativeFixture, id string) (*NativeJobs, JobSpec) {
	t.Helper()
	spec := f.spec.Own()
	spec.ID = id
	run, err := NewJob(spec)
	if err != nil {
		t.Fatal(err)
	}
	grant := NativeGrant{Run: run, Index: 1, Epoch: 1, Allowed: true}
	n, err := OpenNativeJobs(f.db, f.docker, func(context.Context, JobSpec, bool) (NativeGrant, error) { return grant, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Accept(grant); err != nil {
		t.Fatal(err)
	}
	for _, use := range []RootUse{JobRoot, CacheRoot} {
		if err := n.PlanRootHold(context.Background(), spec, use); err != nil {
			t.Fatal(err)
		}
		if err := n.BindRootHold(spec, use, reconcile.Lease{Generation: spec.Scope.Root.Generation, Token: uint64(use)}); err != nil {
			t.Fatal(err)
		}
	}
	return n, spec
}

func TestNativeWorkspaceReopenAndExclusiveCacheUntilOriginalClosure(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	root := nativeTestRoot(t, f.spec)
	before, err := f.jobs.Record(f.spec)
	if err != nil || before.Workspace == nil || !before.Workspace.Ready {
		t.Fatal(before, err)
	}
	paths := nativeWorkspacePaths(f.spec, f.plan)
	if err := os.WriteFile(filepath.Join(paths[2], "retained"), []byte("cache-data"), 0600); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if err := f.jobs.PrepareWorkspace(ctx, f.spec, int(root.Fd())); err != nil {
		t.Fatal(err)
	}
	after, err := f.jobs.Record(f.spec)
	if err != nil || *after.Workspace != *before.Workspace {
		t.Fatal("reopen changed original identities", after, err)
	}
	second, spec2 := anotherWorkspaceJob(t, f, "build-two")
	if err := second.PrepareWorkspace(ctx, spec2, int(root.Fd())); !errors.Is(err, ErrUsed) {
		t.Fatal("borrowed active cache", err)
	}
	if err := second.ObserveExit(ctx, spec2, true); err != nil {
		t.Fatal(err)
	}
	if _, err := second.FinishWorkspace(ctx, spec2); err != nil {
		t.Fatal("unclaimed empty allocation cannot settle", err)
	}
	if _, err := f.jobs.cacheBorrow(f.spec, f.plan, false); err != nil {
		t.Fatal("other job released original cache", err)
	}
	if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
		t.Fatal(err)
	}
	closure, err := f.jobs.FinishWorkspace(ctx, f.spec)
	if err != nil || closure == ([32]byte{}) {
		t.Fatal(closure, err)
	}
	f.reopen()
	if again, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil || again != closure {
		t.Fatal("closure changed after reopen", again, err)
	}
	if _, err := os.Stat(filepath.Dir(paths[0])); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("job directory retained", err)
	}
	if got, err := os.ReadFile(filepath.Join(paths[2], "retained")); err != nil || string(got) != "cache-data" {
		t.Fatal("shared cache removed", err)
	}
	third, spec3 := anotherWorkspaceJob(t, f, "build-three")
	if err := third.PrepareWorkspace(ctx, spec3, int(root.Fd())); err != nil {
		t.Fatal("closed original still borrows cache", err)
	}
	r, err := third.Record(spec3)
	if err != nil || r.Workspace.Cache != before.Workspace.Cache {
		t.Fatal("did not reuse original cache inode", r, err)
	}
}

func TestNativeWorkspaceRejectsChangedRootAndMissingOriginalSpool(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	other, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := f.jobs.PrepareWorkspace(ctx, f.spec, int(other.Fd())); !errors.Is(err, ErrStorage) {
		t.Fatal("wrong pinned root accepted", err)
	}
	// Remove only the test's original spool identity. It must not be silently
	// initialized by the native consumer of an already accepted source.
	if err := os.Rename(filepath.Join(f.spec.Scope.Root.Path, ".sfc-imagebuild"), filepath.Join(f.spec.Scope.Root.Path, "old-spool")); err != nil {
		t.Fatal(err)
	}
	root := nativeTestRoot(t, f.spec)
	if err := f.jobs.PrepareWorkspace(ctx, f.spec, int(root.Fd())); err == nil {
		t.Fatal("lost original spool initialized")
	}
	if _, err := os.Stat(filepath.Join(f.spec.Scope.Root.Path, ".sfc-imagebuild")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing spool recreated", err)
	}
}

func TestNativeWorkspaceReplacementAndPermissionChangesNeverRepairedOrRemoved(t *testing.T) {
	for _, which := range []string{"input", "output", "cache", "job", "root", "mode"} {
		t.Run(which, func(t *testing.T) {
			f := newNativeFixture(t, false)
			ctx := f.ctx()
			paths := nativeWorkspacePaths(f.spec, f.plan)
			name := paths[0]
			switch which {
			case "output":
				name = paths[1]
			case "cache":
				name = paths[2]
			case "job":
				name = filepath.Dir(paths[0])
			case "root":
				name = f.spec.Scope.Root.Path
			}
			if which == "mode" {
				if err := os.Chmod(name, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(name, name+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(name, "foreign"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := f.jobs.Record(f.spec)
			if err != nil {
				t.Fatal(err)
			}
			if files, err := f.jobs.openWorkspace(r); err == nil {
				_ = files.Close()
				t.Fatal("changed original opened")
			}
			if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
				t.Fatal(err)
			}
			if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err == nil {
				t.Fatal("changed original cleaned")
			}
			if which != "mode" {
				if got, err := os.ReadFile(filepath.Join(name, "foreign")); err != nil || string(got) != "keep" {
					t.Fatal("foreign directory removed", err)
				}
			}
		})
	}
}

func TestNativeWorkspaceMissingRecordedDirectoryIsNotADeletionIntent(t *testing.T) {
	for _, leaf := range []bool{false, true} {
		t.Run(map[bool]string{false: "job", true: "input"}[leaf], func(t *testing.T) {
			f := newNativeFixture(t, false)
			ctx := f.ctx()
			name := nativeWorkspacePaths(f.spec, f.plan)[0]
			if !leaf {
				name = filepath.Dir(name)
			}
			if err := os.RemoveAll(name); err != nil {
				t.Fatal(err)
			}
			if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
				t.Fatal(err)
			}
			if _, err := f.jobs.FinishWorkspace(ctx, f.spec); !errors.Is(err, ErrStorage) {
				t.Fatal("absence manufactured deletion", err)
			}
			r, err := f.jobs.Record(f.spec)
			if err != nil || r.Workspace.Removing || r.Workspace.Closed {
				t.Fatal("invalid deletion intent recorded", r, err)
			}
		})
	}
}

type nativeWorkspaceCommitFailure struct {
	Transactions
	calls int
}

var errNativeWorkspaceCommit = errors.New("injected workspace closure commit loss")

func (d *nativeWorkspaceCommitFailure) Update(fn func(*bolt.Tx) error) error {
	d.calls++
	return d.Transactions.Update(func(tx *bolt.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if d.calls == 2 {
			return errNativeWorkspaceCommit
		}
		return nil
	})
}

func TestNativeWorkspaceResumesOriginalRemovalAfterFinalCommitLoss(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
		t.Fatal(err)
	}
	f.jobs.db = &nativeWorkspaceCommitFailure{Transactions: f.db}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); !errors.Is(err, errNativeWorkspaceCommit) {
		t.Fatal("injected closure failure hidden", err)
	}
	if _, err := os.Stat(filepath.Dir(nativeWorkspacePaths(f.spec, f.plan)[0])); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failure not after unlink", err)
	}
	f.reopen()
	r, err := f.jobs.Record(f.spec)
	if err != nil || !r.Workspace.Removing || r.Workspace.Closed {
		t.Fatal("lost original deletion intent", r, err)
	}
	if _, err := f.jobs.cacheBorrow(f.spec, f.plan, false); err != nil {
		t.Fatal("cache released before commit", err)
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil {
		t.Fatal("could not settle original removal", err)
	}
}

func TestNativeWorkspaceOutputReaderMustJoinBeforeCleanup(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	f.prepare(ctx)
	if err := f.jobs.Start(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	f.edit(func() {
		f.state = container.State{Status: container.StateExited, ExitCode: 0, StartedAt: "2026-11-22T00:00:01Z", FinishedAt: "2026-11-22T00:00:02Z"}
	})
	if err := f.jobs.ObserveExit(ctx, f.spec, false); err != nil {
		t.Fatal(err)
	}
	if out, err := f.jobs.OpenOutput(f.spec); err == nil {
		_ = out.Close()
		t.Fatal("restartable native output opened before removal")
	}
	if err := f.jobs.Remove(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	out, err := f.jobs.OpenOutput(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); !errors.Is(err, ErrUsed) {
		t.Fatal("active output reader removed", err)
	}
	if _, err := out.Directory.Stat(); err != nil {
		t.Fatal("reader closed by cleanup", err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
}

func TestNativeWorkspaceDoesNotAdoptUnrecordedNonemptyAllocation(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	r, err := f.jobs.Record(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	r.Workspace.Ready = false
	r.Workspace.Input, r.Workspace.Output, r.Workspace.Cache = NativeDirectory{}, NativeDirectory{}, NativeDirectory{}
	if err := f.jobs.save(r); err != nil {
		t.Fatal(err)
	}
	name := nativeWorkspacePaths(f.spec, f.plan)[0]
	if err := os.WriteFile(filepath.Join(name, "unrecorded"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	root := nativeTestRoot(t, f.spec)
	if err := f.jobs.PrepareWorkspace(ctx, f.spec, int(root.Fd())); !errors.Is(err, ErrStorage) {
		t.Fatal("nonempty allocation adopted", err)
	}
	if got, err := os.ReadFile(filepath.Join(name, "unrecorded")); err != nil || string(got) != "keep" {
		t.Fatal("unknown bytes altered", err)
	}
}
