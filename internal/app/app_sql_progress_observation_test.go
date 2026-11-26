// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/mydcp"
)

func TestSQLReceiveProgressObservationPublicationAndReplacement(t *testing.T) {
	for _, name := range []string{"unpublished", "published", "replacement", "stable-read-error", "empty", "wrong-binding", "wrong-mode", "permission-error"} {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir()
			dir, err := os.OpenRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			intent := moveReceiveIntent{Schema: 1}
			p := moveReceiveProgress{Schema: 1, Binding: intent.digest(), Inode: 1, Offset: mydcp.VolumeChunkSize}
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if name == "wrong-binding" {
				p.Binding[0]++
				raw, _ = json.Marshal(p)
			}
			if name == "empty" {
				raw = nil
			}
			if name != "unpublished" {
				if err = os.WriteFile(filepath.Join(path, "progress.json"), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if name == "wrong-mode" {
				if err = os.Chmod(filepath.Join(path, "progress.json"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			read := backupRead
			switch name {
			case "replacement":
				read = func(root *os.Root, _ string, _ int64) ([]byte, error) {
					// Reproduce the legitimate tmp->rename between identity reads,
					// with two actual different inodes, not a fabricated stat.
					if err := os.WriteFile(filepath.Join(path, "progress.tmp"), raw, 0600); err != nil {
						t.Fatal(err)
					}
					if err := root.Rename("progress.tmp", "progress.json"); err != nil {
						t.Fatal(err)
					}
					return nil, errBackupArtifact
				}
			case "stable-read-error":
				read = func(*os.Root, string, int64) ([]byte, error) { return nil, errBackupArtifact }
			case "permission-error":
				read = func(*os.Root, string, int64) ([]byte, error) { return nil, os.ErrPermission }
			}
			got, published, err := observeSQLReceiveProgress(dir, intent, read)
			switch name {
			case "unpublished", "replacement":
				if err != nil || published {
					t.Fatal("normal publication race was treated as corruption", published, err)
				}
				if name == "replacement" {
					got, published, err = observeSQLReceiveProgress(dir, intent, backupRead)
					if err != nil || !published || got != p {
						t.Fatal("stable replaced record was not observed", err)
					}
				}
			case "published":
				if err != nil || !published || got != p {
					t.Fatal("exact published progress missing", got, published, err)
				}
			default:
				if err == nil || published {
					t.Fatal("stable corrupt/unknown record accepted", published, err)
				}
				if name == "permission-error" && !errors.Is(err, os.ErrPermission) {
					t.Fatal("permission error hidden", err)
				}
			}
		})
	}
}
