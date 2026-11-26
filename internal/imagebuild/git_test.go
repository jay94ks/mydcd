// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

func gitContextFixture(t *testing.T, files map[string]string) (*git.Repository, string) {
	t.Helper()
	fs := memfs.New()
	repo, err := git.Init(memory.NewStorage(), fs)
	if err != nil {
		t.Fatal(err)
	}
	work, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		file, err := fs.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := work.Add(name); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := work.Commit("context", &git.CommitOptions{Author: &object.Signature{Name: "fixture", Email: "fixture@mydc.test", When: time.Unix(1, 0)}})
	if err != nil {
		t.Fatal(err)
	}
	return repo, hash.String()
}
func TestGitContextArchiveSharesZIPTreeAndDockerfileValidation(t *testing.T) {
	repo, commit := gitContextFixture(t, map[string]string{"Dockerfile": "FROM scratch\nCOPY source /source\n", "source": "original", "README": "fixture"})
	var output bytes.Buffer
	tree, err := WriteGitZIP(context.Background(), repo, commit, ".", "Dockerfile", &output, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := InspectZIP(context.Background(), bytes.NewReader(output.Bytes()), int64(output.Len()), "Dockerfile", 1<<20)
	if err != nil || tree.Digest() != actual.Digest() || !bytes.Equal(tree.Dockerfile, actual.Dockerfile) {
		t.Fatal("Git and ZIP use different context interpretation", err)
	}
	var repeated bytes.Buffer
	if _, err := WriteGitZIP(context.Background(), repo, commit, ".", "Dockerfile", &repeated, 1<<20); err != nil || !bytes.Equal(output.Bytes(), repeated.Bytes()) {
		t.Fatal("same commit is not deterministic", err)
	}
	if _, err := WriteGitZIP(context.Background(), repo, commit, ".", "Dockerfile", &bytes.Buffer{}, tree.Bytes-1); err == nil {
		t.Fatal("expanded budget ignored")
	}
}
func TestGitContextRejectsLFSAndMissingDockerfile(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"lfs":     {"Dockerfile": "FROM scratch\n", "source": "version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 10\n"},
		"missing": {"source": "original"},
	} {
		t.Run(name, func(t *testing.T) {
			repo, commit := gitContextFixture(t, files)
			if _, err := WriteGitZIP(context.Background(), repo, commit, ".", "Dockerfile", &bytes.Buffer{}, 1<<20); err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
	repo, commit := gitContextFixture(t, map[string]string{"Dockerfile": "FROM scratch\n"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteGitZIP(ctx, repo, commit, ".", "Dockerfile", &bytes.Buffer{}, 1<<20); err == nil {
		t.Fatal("cancel ignored")
	}
}
