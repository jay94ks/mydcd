// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/storage/memory"
)

// This fixture serves real smart HTTPS bytes. Only the remote Git server and
// faults are test implementations; Fetch, TLS/auth, pinning, limits, cache and
// the regular app object reader are the same product implementation.
type gitFetchFixture struct {
	t           *testing.T
	mu          sync.Mutex
	server      *httptest.Server
	store       *memory.Storage
	old, next   plumbing.Hash
	oldBody     []byte
	policy      DeliveryDeclaration
	access      GitAccess
	mode        string
	gets, posts int
	wants       []plumbing.Hash
}

func newGitFetchFixture(t *testing.T) *gitFetchFixture {
	t.Helper()
	x := &gitFetchFixture{t: t, store: memory.NewStorage(), oldBody: []byte(appInputDocument())}
	fs := memfs.New()
	repo, err := git.Init(x.store, fs)
	if err != nil {
		t.Fatal(err)
	}
	w, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	commit := func(body []byte, when int64) plumbing.Hash {
		f, err := fs.Create("app.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(body); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = w.Add("app.yaml"); err != nil {
			t.Fatal(err)
		}
		h, err := w.Commit("app", &git.CommitOptions{Author: &object.Signature{Name: "fixture", Email: "fixture@mydc.test", When: time.Unix(when, 0)}})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	x.old = commit(x.oldBody, 1)
	x.next = commit(append(bytes.Clone(x.oldBody), []byte("\n# next commit\n")...), 2)
	x.server = httptest.NewTLSServer(http.HandlerFunc(x.serve))
	roots := x509.NewCertPool()
	roots.AddCert(x.server.Certificate())
	x.access = GitAccess{Roots: roots, Username: []byte("git-reader"), Password: []byte("private-fixture-token")}
	t.Cleanup(func() { x.server.Close(); clear(x.access.Username); clear(x.access.Password) })
	x.policy.Enabled = true
	x.policy.Source.Kind, x.policy.Source.Repository, x.policy.Source.Ref, x.policy.Source.Path, x.policy.Source.Credential = "git", x.server.URL+"/repo.git", "refs/heads/main", "app.yaml", "git-read"
	x.policy.Limits.Fetch, x.policy.Limits.Bytes = 2, 4<<20
	return x
}

func (x *gitFetchFixture) serve(w http.ResponseWriter, r *http.Request) {
	x.mu.Lock()
	defer x.mu.Unlock()
	user, password, ok := r.BasicAuth()
	if x.mode != "public" && x.mode != "no-repository" && (!ok || user != string(x.access.Username) || password != string(x.access.Password) || x.mode == "unauthorized") {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "private-provider-detail-do-not-replicate")
		return
	}
	if x.mode == "public" && r.Header.Get("Authorization") != "" {
		x.t.Error("public probe supplied private credentials")
	}
	if x.mode == "no-repository" {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/repo.git/info/refs" {
		x.gets++
		switch x.mode {
		case "failure":
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		case "redirect":
			w.Header().Set("Location", "https://other.invalid/repo.git/info/refs?service=git-upload-pack")
			w.WriteHeader(http.StatusFound)
			return
		case "oversize":
			w.Header().Set("Content-Length", fmt.Sprint(gitTransferBytes+1))
			w.WriteHeader(http.StatusOK)
			return
		case "wait":
			<-r.Context().Done()
			return
		}
		h := x.old
		if x.mode == "next" {
			h = x.next
		}
		a := packp.NewAdvRefs()
		a.Head = &h
		a.References["refs/heads/main"] = h
		a.Prefix = [][]byte{[]byte("# service=git-upload-pack\n"), nil}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		if err := a.Encode(w); err != nil {
			x.t.Error(err)
		}
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/repo.git/git-upload-pack" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	x.posts++
	request := packp.NewUploadPackRequest()
	if err := request.Decode(r.Body); err != nil {
		x.t.Error(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	x.wants = append(x.wants, request.Wants...)
	// The current remote branch is deliberately already x.next. Serve every
	// object but honor the client's frozen want; fetching must not re-resolve.
	var hashes []plumbing.Hash
	iter, err := x.store.IterEncodedObjects(plumbing.AnyObject)
	if err != nil {
		x.t.Error(err)
		return
	}
	err = iter.ForEach(func(o plumbing.EncodedObject) error { hashes = append(hashes, o.Hash()); return nil })
	if err != nil {
		x.t.Error(err)
		return
	}
	var pack bytes.Buffer
	if _, err = packfile.NewEncoder(&pack, x.store, false).Encode(hashes, 0); err != nil {
		x.t.Error(err)
		return
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	_, _ = io.WriteString(w, "0008NAK\n")
	_, _ = w.Write(pack.Bytes())
}

func (x *gitFetchFixture) ticket(sequence uint64) DeliveryFetch {
	return DeliveryFetch{Sequence: sequence, PolicyRevision: 1, Source: deliverySourceID(x.policy)}
}
func (x *gitFetchFixture) setMode(mode string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.mode = mode
}
func (x *gitFetchFixture) counts() (int, int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.gets, x.posts
}

func TestGitHTTPSFetchPinsCommitAndCacheNeverReplacesFreshAuthentication(t *testing.T) {
	x := newGitFetchFixture(t)
	fetcher := NewGitFetcher()
	first, err := fetcher.Fetch(context.Background(), "tenant", x.policy, x.ticket(1), x.access)
	if err != nil || first.artifact.Commit != x.old.String() || !bytes.Equal(first.artifact.Body, x.oldBody) || first.artifact.Digest != sha256.Sum256(x.oldBody) {
		t.Fatal("actual authenticated HTTPS did not preserve the advertised original commit/blob", err)
	}
	first.artifact.Body[0] = '!'
	cached, err := fetcher.Fetch(context.Background(), "tenant", x.policy, x.ticket(2), x.access)
	if err != nil || !bytes.Equal(cached.artifact.Body, x.oldBody) || cached.fetch.Sequence != 2 {
		t.Fatal("cache alias or old ticket", err)
	}
	if gets, posts := x.counts(); gets != 2 || posts != 1 {
		t.Fatal("cache must rediscover/authenticate but reuse the immutable pack", gets, posts)
	}
	for _, mode := range []string{"failure", "unauthorized", "redirect", "oversize"} {
		x.setMode(mode)
		_, err = fetcher.Fetch(context.Background(), "tenant", x.policy, x.ticket(3), x.access)
		if err != ErrSource || strings.Contains(err.Error(), "private") {
			t.Fatal("source fault was hidden by cache or leaked private transport detail", mode, err)
		}
	}
	x.setMode("next")
	next, err := fetcher.Fetch(context.Background(), "tenant", x.policy, x.ticket(4), x.access)
	if err != nil || next.artifact.Commit != x.next.String() || bytes.Equal(next.artifact.Body, x.oldBody) {
		t.Fatal("new remote commit not selected", err)
	}
	x.mu.Lock()
	if len(x.wants) != 2 || x.wants[0] != x.old || x.wants[1] != x.next {
		t.Error("mutable branch substituted for original commit", x.wants)
	}
	x.mu.Unlock()
	// Another tenant uses the same source/profile strings but cannot acquire
	// this tenant's cached artifact without its own successful exact fetch.
	before, _ := x.counts()
	if _, err = fetcher.Fetch(context.Background(), "other", x.policy, x.ticket(5), x.access); err != nil {
		t.Fatal(err)
	}
	if gets, posts := x.counts(); gets != before+1 || posts != 3 {
		t.Fatal("cross-tenant source cache reused", gets, posts)
	}
}

func TestGitHTTPSFetchRejectsTLSCredentialsScopeMissingBlobAndExpiredContext(t *testing.T) {
	x := newGitFetchFixture(t)
	fetcher := NewGitFetcher()
	badTLS := x.access
	badTLS.Roots = x509.NewCertPool()
	if _, err := fetcher.Fetch(context.Background(), "tenant", x.policy, x.ticket(1), badTLS); err != ErrSource {
		t.Fatal("untrusted TLS accepted", err)
	}
	badAuth := x.access
	badAuth.Password = []byte("wrong")
	if _, err := fetcher.Fetch(context.Background(), "tenant", x.policy, x.ticket(2), badAuth); err != ErrSource {
		t.Fatal("bad credential accepted", err)
	}
	badTicket := x.ticket(3)
	badTicket.Source[0] ^= 1
	if _, err := fetcher.Fetch(context.Background(), "tenant", x.policy, badTicket, x.access); err != ErrSource {
		t.Fatal("different source ticket accepted", err)
	}
	policy := x.policy
	policy.Source.Path = "missing.yaml"
	ticket := DeliveryFetch{Sequence: 4, PolicyRevision: 1, Source: deliverySourceID(policy)}
	if _, err := fetcher.Fetch(context.Background(), "tenant", policy, ticket, x.access); err != ErrSource {
		t.Fatal("missing blob accepted", err)
	}
	policy = x.policy
	policy.Limits.Bytes = 1
	if _, err := fetcher.Fetch(context.Background(), "tenant", policy, x.ticket(5), x.access); err != ErrSource {
		t.Fatal("oversize app accepted", err)
	}
	x.setMode("wait")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := fetcher.Fetch(ctx, "tenant", x.policy, x.ticket(6), x.access); err != ErrSource {
		t.Fatal("caller cancellation ignored", err)
	}
	if _, err := json.Marshal(x.access); err == nil {
		t.Fatal("Git private access serialized")
	}
	if text := fmt.Sprintf("%+v", x.access); strings.Contains(text, "private-fixture-token") || strings.Contains(text, "git-reader") {
		t.Fatal("private access formatted", text)
	}
}

func TestGitFetchRefAmbiguityAndPackAllocationBounds(t *testing.T) {
	a := packp.NewAdvRefs()
	h := plumbing.NewHash(strings.Repeat("1", 40))
	a.References["refs/heads/same"], a.References["refs/tags/same"] = h, h
	if _, err := resolveGitCommit(a, "same"); err == nil {
		t.Fatal("ambiguous branch/tag silently selected")
	}
	if got, err := resolveGitCommit(a, "refs/heads/same"); err != nil || got != h {
		t.Fatal(got, err)
	}
	// Declared object count is rejected before decoding/allocation, even when
	// the malicious response contains only its 12-byte pack header.
	count := []byte{'P', 'A', 'C', 'K', 0, 0, 0, 2, 0, 1, 0, 0}
	if err := boundedGitPack(context.Background(), count); err == nil {
		t.Fatal("unbounded object count accepted")
	}
	if err := boundedGitPack(context.Background(), []byte("not a pack")); err == nil {
		t.Fatal("malformed pack accepted")
	}
}

func TestGitHTTPSPartialTransferResumeKeepsOriginalCommitAfterBranchMoves(t *testing.T) {
	x := newGitFetchFixture(t)
	x.setMode("next")
	fetcher := NewGitFetcher()
	input, err := fetcher.FetchCommit(context.Background(), "tenant", x.policy, x.ticket(1), x.access, x.old.String())
	if err != nil || input.artifact.Commit != x.old.String() || !bytes.Equal(input.artifact.Body, x.oldBody) {
		t.Fatal("partial upload resumed from a different branch revision", err)
	}
	current, err := fetcher.Fetch(context.Background(), "tenant", x.policy, x.ticket(2), x.access)
	if err != nil || current.artifact.Commit != x.next.String() {
		t.Fatal("original commit recovery changed registered branch observation", err)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.wants) != 2 || x.wants[0] != x.old || x.wants[1] != x.next {
		t.Fatal("HTTPS upload-pack did not receive the exact original/new wants", x.wants)
	}
}
