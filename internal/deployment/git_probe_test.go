// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"testing"
)

func TestGitProbePublicRepositoryWithoutCredentialAndMissingRepository(t *testing.T) {
	x := newGitFetchFixture(t)
	x.setMode("public")
	fetcher := NewGitFetcher()
	q := GitProbeRequest{App: "shop", Repository: x.policy.Source.Repository, Branch: "main", Path: "app.yaml"}
	result := fetcher.Probe(context.Background(), "tenant", q, GitAccess{Roots: x.access.Roots})
	if result.Code != "" || result.Commit != x.old.String() || result.Size != int64(len(x.oldBody)) || len(fetcher.cache) != 0 {
		t.Fatal("public source read needed a credential or changed CD cache", result)
	}
	x.setMode("no-repository")
	result = fetcher.Probe(context.Background(), "tenant", q, GitAccess{Roots: x.access.Roots})
	if result.Code != "no-repository" || result.Commit != "" || result.Size != 0 || len(fetcher.cache) != 0 {
		t.Fatal("missing repository classification", result)
	}
}

func TestGitProbeUsesExistingActualHTTPSAndPinnedFileWithoutCDState(t *testing.T) {
	x := newGitFetchFixture(t)
	fetcher := NewGitFetcher()
	q := GitProbeRequest{App: "shop", Repository: x.policy.Source.Repository, Branch: "main", Path: "app.yaml", Credential: x.policy.Source.Credential}
	before := len(fetcher.cache)
	result := fetcher.Probe(context.Background(), "tenant", q, x.access)
	if result.Code != "" || result.Commit != x.old.String() || result.Size != int64(len(x.oldBody)) || len(fetcher.cache) != before {
		t.Fatal(result)
	}
	x.mu.Lock()
	pinned := len(x.wants) == 1 && x.wants[0].String() == result.Commit
	x.mu.Unlock()
	if !pinned {
		t.Fatal("probe fetched mutable head instead of original discovered commit")
	}
	q.Path = "missing.yaml"
	if result := fetcher.Probe(context.Background(), "tenant", q, x.access); result.Code != "no-file" || result.Commit != "" || result.Size != 0 {
		t.Fatal(result)
	}
	q.Path = "app.yaml"
	q.Branch = "missing"
	if result := fetcher.Probe(context.Background(), "tenant", q, x.access); result.Code != "no-branch" {
		t.Fatal(result)
	}
	q.Branch = "main"
	q.Credential = ""
	if result := fetcher.Probe(context.Background(), "tenant", q, GitAccess{Roots: x.access.Roots}); result.Code != "auth-failed" {
		t.Fatal(result)
	}
	q.Credential = x.policy.Source.Credential
	x.setMode("redirect")
	if result := fetcher.Probe(context.Background(), "tenant", q, x.access); result.Code == "" {
		t.Fatal("followed Git redirect")
	}
	x.setMode("")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result := fetcher.Probe(ctx, "tenant", q, x.access); result.Code != "timeout" {
		t.Fatal(result)
	}
	if len(fetcher.cache) != before {
		t.Fatal("probe changed CD source cache")
	}
}
func TestGitProbeRejectsSecretInputsAndUnsafeRefs(t *testing.T) {
	q := GitProbeRequest{App: "shop", Repository: "https://git.example/team/repo.git", Branch: "main", Path: "app.yaml"}
	if !q.Valid() {
		t.Fatal("valid probe")
	}
	for _, change := range []func(*GitProbeRequest){func(q *GitProbeRequest) { q.Repository = "http://git.example/repo" }, func(q *GitProbeRequest) { q.Repository = "https://user:password@git.example/repo" }, func(q *GitProbeRequest) { q.Repository += "?token=private" }, func(q *GitProbeRequest) { q.Path = "../private" }, func(q *GitProbeRequest) { q.Branch = "refs/heads/main" }, func(q *GitProbeRequest) { q.Branch = "main^{commit}" }, func(q *GitProbeRequest) { q.Credential = "/private/token" }} {
		bad := q
		change(&bad)
		if bad.Valid() {
			t.Fatal("unsafe Git probe")
		}
	}
}
