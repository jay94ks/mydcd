// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"testing"

	"github.com/go-git/go-git/v5"
)

func TestGitRepositoryVisitorUsesExistingPrivateHTTPSAndPinnedPack(t *testing.T) {
	x := newGitFetchFixture(t)
	f := NewGitFetcher()
	q := GitRepositoryRequest{Repository: x.policy.Source.Repository, Ref: x.policy.Source.Ref, Credential: x.policy.Source.Credential, Seconds: x.policy.Limits.Fetch}
	visits := 0
	commit, err := f.VisitRepository(context.Background(), "tenant", q, x.access, func(ctx context.Context, repo *git.Repository, commit string) error {
		visits++
		_, err := ReadGitCompose(repo, commit, x.policy.Source.Path, 4<<20)
		return err
	})
	if err != nil || visits != 1 || commit != x.old.String() {
		t.Fatal("actual SDK repository visitor", commit, visits, err)
	}
	q.Commit = commit
	if _, err := f.VisitRepository(context.Background(), "tenant", q, x.access, func(context.Context, *git.Repository, string) error { return ErrSource }); err == nil {
		t.Fatal("visitor failure accepted as fetch success")
	}
}
