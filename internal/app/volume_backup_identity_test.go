// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

func TestBackupPartialIntentUsesOriginalCheckpointAndNoCopy(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	for _, failure := range []string{"write", "sync"} {
		t.Run(failure, func(t *testing.T) {
			job, backend, path := artifactFixture(t)
			m, err := openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, backend)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Close() }()
			if failure == "write" {
				m.writeBytes = func(file *os.File, raw []byte) (int, error) {
					if filepath.Base(file.Name()) == "intent.json" {
						n, err := file.Write(raw[:len(raw)/2])
						return n, errors.Join(syscall.ENOSPC, err)
					}
					return file.Write(raw)
				}
			} else {
				m.syncFile = func(file *os.File) error {
					if filepath.Base(file.Name()) == "intent.json" {
						return syscall.EIO
					}
					return file.Sync()
				}
			}
			if _, err = m.Step(context.Background(), job); err == nil {
				t.Fatal("intent I/O failure published complete")
			}
			before, err := m.journal.Read(backupArtifactKey(job.Binding))
			if err != nil || before.Checkpoint == nil || before.Checkpoint.Operation != 1 || before.State.Pending == nil || before.State.Pending.Phase != reconcile.RecoveryRequired || backend.exports != 0 {
				t.Fatal("ownership not synced before metadata write", err)
			}
			raw := append([]byte(nil), before.Checkpoint.Data...)
			_ = m.Close()
			m, err = openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, backend)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = m.Step(context.Background(), job); err == nil || backend.exports != 0 {
				t.Fatal("original incomplete intent recopied", err)
			}
			job.Phase, job.Revision = "Cancelling", 2
			if _, err = m.Step(context.Background(), job); err != nil {
				t.Fatal("original metadata cancellation", err)
			}
			after, _ := m.journal.Read(backupArtifactKey(job.Binding))
			if after.Checkpoint != nil || after.State.Pending != nil || after.State.Applied.Present || after.State.LastID != 1 {
				t.Fatal("cancel lost original ID or retained proof")
			}
			if failure == "write" {
				if _, err = os.Lstat(filepath.Join(path, backupArtifactName(job.Binding))); !os.IsNotExist(err) {
					t.Fatal("partial owned metadata directory retained", err)
				}
			}
			if len(raw) == 0 {
				t.Fatal("empty ownership checkpoint")
			}
		})
	}
}
func TestBackupPartialIntentRejectsChangedInodeAndForeignContents(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	for _, scenario := range []string{"inode", "foreign-file", "symlink", "nonprefix", "missing-proof"} {
		t.Run(scenario, func(t *testing.T) {
			job, backend, path := artifactFixture(t)
			m, err := openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, backend)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			dir := filepath.Join(path, backupArtifactName(job.Binding))
			m.writeBytes = func(file *os.File, raw []byte) (int, error) {
				if filepath.Base(file.Name()) == "intent.json" {
					n, err := file.Write(raw[:8])
					return n, errors.Join(syscall.EIO, err)
				}
				return file.Write(raw)
			}
			if _, err = m.Step(context.Background(), job); err == nil {
				t.Fatal("expected partial intent")
			}
			switch scenario {
			case "inode":
				if err = os.Rename(dir, dir+"-original"); err != nil {
					t.Fatal(err)
				}
				if err = os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			case "foreign-file":
				if err = os.WriteFile(filepath.Join(dir, "foreign"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				_ = os.Remove(filepath.Join(dir, "intent.json"))
				if err = os.Symlink(filepath.Join(path, "owner.json"), filepath.Join(dir, "intent.json")); err != nil {
					t.Fatal(err)
				}
			case "nonprefix":
				if err = os.WriteFile(filepath.Join(dir, "intent.json"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-proof":
				// Exercise the legacy missing-proof boundary directly. Existing records
				// never acquire a new identity checkpoint during recovery/retirement.
				if err = m.remove(context.Background(), job.Binding, nil); err == nil {
					t.Fatal("partial metadata adopted without original checkpoint")
				}
				return
			}
			job.Phase, job.Revision = "Cancelling", 2
			if _, err = m.Step(context.Background(), job); err == nil {
				t.Fatal("foreign directory/contents removed", scenario)
			}
			if _, err = os.Lstat(dir); err != nil {
				t.Fatal("foreign directory changed", err)
			}
			row, _ := m.journal.Read(backupArtifactKey(job.Binding))
			if row.Checkpoint == nil || row.State.Pending == nil || row.State.LastID != 1 {
				t.Fatal("foreign denial discarded original checkpoint")
			}
		})
	}
}
