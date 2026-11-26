// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
)

const (
	gitTransferBytes = 64 << 20
	gitExpandedBytes = 128 << 20
	gitObjectCount   = 16384
	gitCacheBytes    = 16 << 20
)

// GitAccess is installed node-local material for one already-authorized fetch.
// A caller must resolve the exact tenant/profile/repository before calling
// Fetch. Neither a manifest nor an HTTPS redirect can supply these values.
type GitAccess struct {
	Roots              *x509.CertPool
	Username, Password []byte
}

func (GitAccess) MarshalJSON() ([]byte, error) { return nil, ErrSource }
func (GitAccess) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted Git access]")
}
func (a GitAccess) valid(required bool) bool {
	if !required {
		return len(a.Username) == 0 && len(a.Password) == 0
	}
	return len(a.Username) > 0 && len(a.Username) <= 256 && len(a.Password) > 0 && len(a.Password) <= 16384 && !bytes.ContainsAny(a.Username, ":\x00\r\n") && !bytes.ContainsAny(a.Password, "\x00\r\n")
}

type gitAuth struct{ access GitAccess }

func (gitAuth) Name() string   { return "mydc-git-basic" }
func (gitAuth) String() string { return "[redacted Git authentication]" }
func (a gitAuth) SetAuth(r *http.Request) {
	r.SetBasicAuth(string(a.access.Username), string(a.access.Password))
}

type gitCachedInput struct {
	tenant string
	source [32]byte
	input  GitArtifact
}

// GitFetcher owns only a bounded, disposable source cache. The authoritative
// artifact and original operation belong to Delivery/Inventory, never here.
// One slot bounds memory and joins an in-progress fetch through its caller's
// context. No global go-git protocol registry, checkout or external git runs.
type GitFetcher struct {
	slot  chan struct{}
	cache []gitCachedInput // oldest first; used only while holding slot
}

func NewGitFetcher() *GitFetcher { return &GitFetcher{slot: make(chan struct{}, 1)} }

// Fetch always authenticates/discovers the current source, including a cache
// hit. An outage/auth failure never returns cached input as a fresh fetch.
// Mutable refs are resolved once; the upload and object reader use that exact
// commit even if the branch changes while the response is in flight.
func (f *GitFetcher) Fetch(ctx context.Context, tenant string, policy DeliveryDeclaration, ticket DeliveryFetch, access GitAccess) (input DeliveryInput, err error) {
	return f.fetch(ctx, tenant, policy, ticket, access, "")
}

// FetchCommit resumes a partially transferred original source. It still
// authenticates the registered repository, but never follows a newer branch.
func (f *GitFetcher) FetchCommit(ctx context.Context, tenant string, policy DeliveryDeclaration, ticket DeliveryFetch, access GitAccess, commit string) (DeliveryInput, error) {
	if !gitCommit(commit) {
		return DeliveryInput{}, ErrSource
	}
	return f.fetch(ctx, tenant, policy, ticket, access, commit)
}

func (f *GitFetcher) fetch(ctx context.Context, tenant string, policy DeliveryDeclaration, ticket DeliveryFetch, access GitAccess, pinned string) (input DeliveryInput, err error) {
	if f == nil || f.slot == nil || !identifier(tenant) || validateGitFetch(policy, ticket) != nil || !access.valid(policy.Source.Credential != "") {
		return input, ErrSource
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(policy.Limits.Fetch)*time.Second)
	defer cancel()
	select {
	case f.slot <- struct{}{}:
		defer func() { <-f.slot }()
	case <-ctx.Done():
		return input, ErrSource
	}
	defer func() {
		if err != nil {
			input, err = DeliveryInput{}, ErrSource
		}
	}()
	request := GitRepositoryRequest{Repository: policy.Source.Repository, Ref: policy.Source.Ref, Credential: policy.Source.Credential, Commit: pinned, Seconds: policy.Limits.Fetch}
	hit := false
	cached := func(commit string) (bool, error) {
		for i, entry := range f.cache {
			if entry.tenant != tenant || entry.source != ticket.Source || entry.input.Commit != commit {
				continue
			}
			artifact := entry.input
			if uint64(len(artifact.raw)) > policy.Limits.Bytes || ctx.Err() != nil {
				return false, ErrSource
			}
			f.cache = append(append(f.cache[:i:i], f.cache[i+1:]...), entry)
			input = DeliveryInput{ticket, deliveryArtifact{Kind: "git", Commit: artifact.Commit, Path: artifact.Path, Digest: artifact.Digest, Body: artifact.Bytes()}}
			hit = true
			return true, nil
		}
		return false, nil
	}
	repository, commit, err := fetchGitRepository(ctx, request, access, cached)
	if err != nil {
		return input, err
	}
	if hit {
		if ctx.Err() != nil {
			return DeliveryInput{}, ErrSource
		}
		return input, nil
	}
	input, err = ReadDeliveryInput(repository, ticket, commit, policy.Source.Path, int64(policy.Limits.Bytes))
	if err != nil || ctx.Err() != nil {
		return DeliveryInput{}, ErrSource
	}
	f.remember(tenant, ticket.Source, GitArtifact{Commit: commit, Path: policy.Source.Path, Digest: input.artifact.Digest, raw: bytes.Clone(input.artifact.Body)})
	return input, nil
}

func validateGitFetch(p DeliveryDeclaration, t DeliveryFetch) error {
	u, err := url.Parse(p.Source.Repository)
	if err != nil || !p.Enabled || p.Source.Kind != "git" || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(p.Source.Repository, "\x00\r\n") || !relativeFile(p.Source.Path) || strings.Count(p.Source.Path, "/") > 16 || p.Source.Ref == "" || len(p.Source.Ref) > 256 || p.Limits.Fetch < 1 || p.Limits.Fetch > 300 || p.Limits.Bytes < 1 || p.Limits.Bytes > 4<<20 || p.Source.Credential != "" && !identifier(p.Source.Credential) || t.Sequence == 0 || t.PolicyRevision == 0 || t.Source != deliverySourceID(p) {
		return ErrSource
	}
	return nil
}

func resolveGitCommit(a *packp.AdvRefs, name string) (plumbing.Hash, error) {
	if a == nil {
		return plumbing.ZeroHash, ErrSource
	}
	if gitCommit(name) {
		return plumbing.NewHash(name), nil
	}
	if name == "HEAD" && a.Head != nil && !a.Head.IsZero() {
		return *a.Head, nil
	}
	names := []string{name}
	if !strings.HasPrefix(name, "refs/") {
		names = []string{"refs/heads/" + name, "refs/tags/" + name}
	}
	var selected plumbing.Hash
	for _, ref := range names {
		if plumbing.ReferenceName(ref).Validate() != nil {
			return plumbing.ZeroHash, ErrSource
		}
		h, ok := a.References[ref]
		if !ok {
			continue
		}
		if peeled, ok := a.Peeled[ref]; ok {
			h = peeled
		}
		if h.IsZero() || !selected.IsZero() {
			return plumbing.ZeroHash, ErrSource // ambiguous short branch/tag
		}
		selected = h
	}
	if selected.IsZero() {
		return selected, ErrSource
	}
	return selected, nil
}

func (f *GitFetcher) remember(tenant string, source [32]byte, a GitArtifact) {
	var keep []gitCachedInput
	total := len(a.raw)
	for _, old := range f.cache {
		if old.tenant != tenant || old.source != source {
			keep = append(keep, old)
			total += len(old.input.raw)
		}
	}
	for len(keep) >= 64 || total > gitCacheBytes {
		total -= len(keep[0].input.raw)
		keep = keep[1:]
	}
	f.cache = append(keep, gitCachedInput{tenant, source, a})
}

type gitHTTPBudget struct {
	native    http.RoundTripper
	remaining int64
}

func (b *gitHTTPBudget) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.Method != http.MethodGet && r.Method != http.MethodPost || b.remaining <= 0 {
		return nil, ErrSource
	}
	response, err := b.native.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > b.remaining {
		response.Body.Close()
		return nil, ErrSource
	}
	response.Body = &gitBudgetBody{ReadCloser: response.Body, budget: b}
	return response, nil
}

type gitBudgetBody struct {
	io.ReadCloser
	budget *gitHTTPBudget
}

func (b *gitBudgetBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.budget.remaining < 0 {
		return 0, ErrSource
	}
	if b.budget.remaining == 0 {
		// Exactly the budget is valid if this is EOF. Consume at most one
		// overflow byte to distinguish it; never turn truncation into EOF.
		var one [1]byte
		n, err := b.ReadCloser.Read(one[:])
		if n != 0 {
			b.budget.remaining = -1
			return 0, ErrSource
		}
		return 0, err
	}
	if int64(len(p)) > b.budget.remaining {
		p = p[:b.budget.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.budget.remaining -= int64(n)
	return n, err
}

// Preflight uses go-git's scanner before its in-memory object decoder. Bound
// count, inflated bodies and delta result sizes before any corresponding large
// allocation. This is a resource limit, not another Git object implementation.
func boundedGitPack(ctx context.Context, raw []byte) error {
	scanner := packfile.NewScanner(bytes.NewReader(raw))
	_, count, err := scanner.Header()
	if err != nil || count == 0 || count > gitObjectCount {
		return ErrSource
	}
	var expanded uint64
	for i := uint32(0); i < count; i++ {
		h, err := scanner.NextObjectHeader()
		if err != nil || ctx.Err() != nil || h.Length < 0 || h.Length > gitExpandedBytes || expanded+uint64(h.Length) > gitExpandedBytes {
			return ErrSource
		}
		body := gitPackBody{ctx: ctx, remaining: h.Length}
		if _, _, err = scanner.NextObject(&body); err != nil || body.remaining != 0 {
			return ErrSource
		}
		expanded += uint64(h.Length)
		if h.Type == plumbing.OFSDeltaObject || h.Type == plumbing.REFDeltaObject {
			_, n := binary.Uvarint(body.prefix)
			if n <= 0 {
				return ErrSource
			}
			result, n := binary.Uvarint(body.prefix[n:])
			if n <= 0 || result > gitExpandedBytes || expanded+result > gitExpandedBytes {
				return ErrSource
			}
			expanded += result
		}
	}
	_, err = scanner.Checksum()
	return err
}

type gitPackBody struct {
	ctx       context.Context
	remaining int64
	prefix    []byte
}

func (b *gitPackBody) Write(p []byte) (int, error) {
	if b.ctx.Err() != nil || int64(len(p)) > b.remaining {
		return 0, ErrSource
	}
	if len(b.prefix) < 20 {
		b.prefix = append(b.prefix, p[:min(len(p), 20-len(b.prefix))]...)
	}
	b.remaining -= int64(len(p))
	return len(p), nil
}
