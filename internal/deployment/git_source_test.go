// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

func TestGitLibraryReadsOnePinnedRegularComposeBlob(t *testing.T) {
	fs := memfs.New()
	repo, err := git.Init(memory.NewStorage(), fs)
	if err != nil {
		t.Fatal(err)
	}
	f, err := fs.Create("app.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte(appInputDocument()))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	w, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Add("app.yaml"); err != nil {
		t.Fatal(err)
	}
	h, err := w.Commit("input", &git.CommitOptions{Author: &object.Signature{Name: "fixture", Email: "fixture@mydc.test", When: time.Unix(1, 0)}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := ReadGitCompose(repo, h.String(), "app.yaml", 4<<20)
	if err != nil || a.Commit != h.String() || a.Input.Name != "php-mysql" {
		t.Fatal(err)
	}
	original := []byte(appInputDocument())
	if !bytes.Equal(a.Bytes(), original) {
		t.Fatal("pinned source bytes changed")
	}
	copy := a.Bytes()
	copy[0] = '!'
	if !bytes.Equal(a.Bytes(), original) {
		t.Fatal("caller changed pinned source bytes")
	}
	for _, item := range []struct {
		commit, name string
		limit        int64
	}{{"HEAD", "app.yaml", 4 << 20}, {h.String(), "../app.yaml", 4 << 20}, {h.String(), "missing.yaml", 4 << 20}, {h.String(), "app.yaml", 16}} {
		if _, err = ReadGitCompose(repo, item.commit, item.name, item.limit); err == nil {
			t.Fatal("invalid source accepted")
		}
	}
	bad, err := fs.Create("management.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bad.Write([]byte(strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64)))); err != nil {
		t.Fatal(err)
	}
	if err = bad.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Add("management.yaml"); err != nil {
		t.Fatal(err)
	}
	badCommit, err := w.Commit("management input is not an app", &git.CommitOptions{Author: &object.Signature{Name: "fixture", Email: "fixture@mydc.test", When: time.Unix(2, 0)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReadGitCompose(repo, badCommit.String(), "management.yaml", 4<<20); err == nil {
		t.Fatal("Git source bypassed app scope")
	}
	if err = fs.Symlink("app.yaml", "link.yaml"); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Add("link.yaml"); err != nil {
		t.Fatal(err)
	}
	h, err = w.Commit("link", &git.CommitOptions{Author: &object.Signature{Name: "fixture", Email: "fixture@mydc.test", When: time.Unix(2, 0)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReadGitCompose(repo, h.String(), "link.yaml", 4<<20); err == nil {
		t.Fatal("symlink accepted")
	}
}
