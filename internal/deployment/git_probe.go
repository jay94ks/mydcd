// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

const GitProbeMaxBytes = 4 << 20

type GitProbeRequest struct{ App, Repository, Branch, Path, Credential string }

func (q GitProbeRequest) Valid() bool {
	return identifier(q.App) && relativeFile(q.Path) && strings.Count(q.Path, "/") <= 16 && !strings.HasPrefix(q.Branch, "refs/") && plumbing.ReferenceName("refs/heads/"+q.Branch).Validate() == nil && q.Branch != "" && len(q.Branch) <= 256 && (GitRepositoryRequest{Repository: q.Repository, Ref: "refs/heads/" + q.Branch, Credential: q.Credential, Seconds: 30}).Validate() == nil
}

type GitProbeResult struct {
	Code, Commit, Node string
	Size               int64
}

func (r GitProbeResult) Valid() bool {
	if !identifier(r.Node) {
		return false
	}
	if r.Code == "" {
		return gitCommit(r.Commit) && r.Size >= 0 && r.Size <= GitProbeMaxBytes
	}
	switch r.Code {
	case "auth-failed", "no-repository", "no-branch", "no-file", "no-credential", "timeout", "rate-limited", "too-large", "source-error":
		return r.Commit == "" && r.Size == 0
	}
	return false
}

var errGitNoBranch = errors.New("Git branch not found")

// gitProbeCode retains only public categories. Existing CD wrappers continue
// flattening failures to ErrSource; no provider text or credentials escape.
func gitProbeCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	if errors.Is(err, transport.ErrAuthenticationRequired) || errors.Is(err, transport.ErrAuthorizationFailed) {
		return "auth-failed"
	}
	if errors.Is(err, transport.ErrRepositoryNotFound) {
		return "no-repository"
	}
	if errors.Is(err, errGitNoBranch) {
		return "no-branch"
	}
	return "source-error"
}

type gitProbeFailure struct{ code string }

func (e gitProbeFailure) Error() string { return "Git source probe: " + e.code }

// Probe reads one pinned regular object using CD's transport/pack decoder. It
// neither populates the CD source cache nor creates candidates/checkouts/files.
func (f *GitFetcher) Probe(ctx context.Context, tenant string, q GitProbeRequest, access GitAccess) (result GitProbeResult) {
	if f == nil || f.slot == nil || !identifier(tenant) || !q.Valid() || !access.valid(q.Credential != "") {
		result.Code = "source-error"
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	select {
	case f.slot <- struct{}{}:
		defer func() { <-f.slot }()
	case <-ctx.Done():
		result.Code = "timeout"
		return
	}
	repo, commit, err := fetchGitRepository(ctx, GitRepositoryRequest{Repository: q.Repository, Ref: "refs/heads/" + q.Branch, Credential: q.Credential, Seconds: 30}, access, nil)
	if err != nil {
		var classified gitProbeFailure
		if errors.As(err, &classified) {
			result.Code = classified.code
		} else {
			result.Code = gitProbeCode(err)
		}
		if ctx.Err() != nil {
			result.Code = "timeout"
		}
		return
	}
	object, err := repo.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		result.Code = "source-error"
		return
	}
	file, err := object.File(q.Path)
	if err != nil || file.Mode != filemode.Regular && file.Mode != filemode.Executable {
		result.Code = "no-file"
		return
	}
	if file.Size < 0 || file.Size > GitProbeMaxBytes {
		result.Code = "too-large"
		return
	}
	body, err := file.Reader()
	if err != nil {
		result.Code = "source-error"
		return
	}
	n, err := io.Copy(io.Discard, io.LimitReader(contextGitProbeReader{ctx, body}, GitProbeMaxBytes+1))
	closeErr := body.Close()
	if ctx.Err() != nil {
		result.Code = "timeout"
		return
	}
	if err != nil || closeErr != nil || n != file.Size {
		result.Code = "source-error"
		return
	}
	result.Commit, result.Size = commit, n
	return
}

type contextGitProbeReader struct {
	ctx context.Context
	io.Reader
}

func (r contextGitProbeReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}
