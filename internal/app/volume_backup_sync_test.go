// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestBackupArtifactSyncFailureKeepsOriginalUntilDurableRecoveryOrCancel(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	for _, stage := range []string{"archive-file", "completion-file", "job-directory", "root-directory"} {
		t.Run(stage, func(t *testing.T) {
			job, backend, path := artifactFixture(t)
			m, err := openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, backend)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Close() }()
			active, hits := true, 0
			install := func() {
				m.syncFile = func(f *os.File) error {
					info, err := f.Stat()
					if err != nil {
						return err
					}
					marker := filepath.Join(path, backupArtifactName(job.Binding), "complete.json")
					_, completeErr := os.Lstat(marker)
					fail := stage == "archive-file" && filepath.Base(f.Name()) == "archive.tar" || stage == "completion-file" && filepath.Base(f.Name()) == "complete.tmp"
					if info.IsDir() && completeErr == nil {
						name := path
						if stage == "job-directory" {
							name = filepath.Dir(marker)
						}
						expected, err := os.Stat(name)
						if err != nil {
							return err
						}
						fail = (stage == "job-directory" || stage == "root-directory") && os.SameFile(info, expected)
					}
					if active && fail {
						hits++
						return syscall.EIO
					}
					return f.Sync()
				}
			}
			install()
			if c, err := m.Step(context.Background(), job); !errors.Is(err, syscall.EIO) || c != nil {
				t.Fatal("sync error published complete", c, err)
			}
			original, _ := m.journal.Read(backupArtifactKey(job.Binding))
			if original.State.LastID != 1 || original.State.Pending == nil || original.State.Pending.Phase != reconcile.RecoveryRequired || backend.exports != 1 {
				t.Fatal("original Apply1 lost", original.State, backend.exports)
			}
			_ = m.Close()
			m, err = openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, backend)
			if err != nil {
				t.Fatal(err)
			}
			install()
			if c, err := m.Step(context.Background(), job); err == nil || c != nil || backend.exports != 1 {
				t.Fatal("restart ignored failed sync or recopied", c, err, backend.exports)
			}
			if (stage == "job-directory" || stage == "root-directory") && hits < 2 {
				t.Fatal("recovery failed to retry original directory sync")
			}
			active = false
			if stage == "job-directory" || stage == "root-directory" {
				c, err := m.Step(context.Background(), job)
				if err != nil || c == nil || backend.exports != 1 {
					t.Fatal("same original durable recovery", c, err)
				}
				row, _ := m.journal.Read(backupArtifactKey(job.Binding))
				if row.State.LastID != 1 || row.State.Pending != nil || !row.State.Applied.Present {
					t.Fatal("recovery replaced original operation")
				}
				job.Phase, job.Revision, job.Receipt = "Deleting", 3, &c.Receipt
			} else {
				if c, err := m.Step(context.Background(), job); err == nil || c != nil || backend.exports != 1 {
					t.Fatal("no completion automatically recopied", c, err)
				}
				job.Phase, job.Revision = "Cancelling", 2
			}
			if _, err = m.Step(context.Background(), job); err != nil {
				t.Fatal("original cleanup", err)
			}
			if _, err = os.Stat(filepath.Join(path, backupArtifactName(job.Binding), "archive.tar")); !os.IsNotExist(err) {
				t.Fatal("original artifact retained", err)
			}
		})
	}
}
