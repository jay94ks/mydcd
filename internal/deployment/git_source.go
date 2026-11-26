// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
)

var ErrSource = errors.New("invalid or unavailable pinned application source")

type GitArtifact struct {
	Commit, Path string
	Digest       [32]byte
	Input        Compose
	raw          []byte
}

// Bytes returns the original pinned blob, independently owned by the caller.
// Durable CD handoff retains these bytes rather than fetching a mutable ref.
func (a GitArtifact) Bytes() []byte { return bytes.Clone(a.raw) }

// ReadGitCompose consumes a fetched repository, not a working tree or mutable
// ref. It reads a regular blob at one exact commit; no checkout/hooks, symlink
// traversal, submodule/LFS fetch or local file fallback is performed. The E6
// fetch adapter supplies the authorized repository and transport/byte budget.
func ReadGitCompose(repo *git.Repository, commit, name string, limit int64) (GitArtifact, error) {
	if repo == nil || len(commit) != 40 || plumbing.NewHash(commit).String() != commit || !relativeFile(name) || strings.Count(name, "/") > 16 || limit < 1 || limit > 4<<20 {
		return GitArtifact{}, ErrSource
	}
	c, err := repo.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		return GitArtifact{}, ErrSource
	}
	f, err := c.File(name)
	if err != nil || f.Mode != filemode.Regular && f.Mode != filemode.Executable || f.Size < 1 || f.Size > limit {
		return GitArtifact{}, ErrSource
	}
	r, err := f.Reader()
	if err != nil {
		return GitArtifact{}, ErrSource
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return GitArtifact{}, ErrSource
	}
	input, err := ParseApp(raw)
	if err != nil {
		return GitArtifact{}, ErrSource
	}
	return GitArtifact{Commit: commit, Path: name, Digest: sha256.Sum256(raw), Input: input, raw: raw}, nil
}
