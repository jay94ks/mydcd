// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
)

// GitRepositoryRequest is public source metadata. A node must select the exact
// installed tenant/profile/repository before supplying transient GitAccess.
type GitRepositoryRequest struct {
	Repository, Ref, Credential, Commit string
	Seconds                             uint64
}

func (q GitRepositoryRequest) Validate() error {
	u, err := url.Parse(q.Repository)
	if err != nil || len(q.Repository) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || strings.ContainsAny(q.Repository, "\x00\r\n") || q.Ref == "" || len(q.Ref) > 256 || q.Seconds < 1 || q.Seconds > 300 || q.Credential != "" && !identifier(q.Credential) || q.Commit != "" && !gitCommit(q.Commit) {
		return ErrSource
	}
	return nil
}

// VisitRepository authenticates and pins one commit through the SAME bounded
// transport/pack decoder as CD. Repository/objects remain inside the callback;
// no checkout, external git or global protocol registration is introduced.
func (f *GitFetcher) VisitRepository(ctx context.Context, tenant string, q GitRepositoryRequest, access GitAccess, visit func(context.Context, *git.Repository, string) error) (commit string, err error) {
	if f == nil || f.slot == nil || !identifier(tenant) || visit == nil || q.Validate() != nil || !access.valid(q.Credential != "") {
		return "", ErrSource
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(q.Seconds)*time.Second)
	defer cancel()
	select {
	case f.slot <- struct{}{}:
		defer func() { <-f.slot }()
	case <-ctx.Done():
		return "", ErrSource
	}
	defer func() {
		if err != nil {
			commit, err = "", ErrSource
		}
	}()
	repo, commit, err := fetchGitRepository(ctx, q, access, nil)
	if err != nil {
		return "", err
	}
	if err = visit(ctx, repo, commit); err != nil || ctx.Err() != nil {
		return "", ErrSource
	}
	return commit, nil
}

// cached is consulted only AFTER authenticated reference discovery. It can
// reuse CD's immutable original bytes without turning stale/offline cache into
// a successful fresh fetch. All callers share this transport implementation.
func fetchGitRepository(ctx context.Context, q GitRepositoryRequest, access GitAccess, cached func(string) (bool, error)) (repository *git.Repository, commit string, err error) {
	if q.Validate() != nil || !access.valid(q.Credential != "") {
		return nil, "", ErrSource
	}
	defer func() {
		if err != nil {
			repository, commit, err = nil, "", errors.Join(ErrSource, gitProbeFailure{gitProbeCode(err)})
		}
	}()
	deadline := time.Duration(q.Seconds) * time.Second
	native := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: deadline}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: access.Roots}, TLSHandshakeTimeout: deadline, ResponseHeaderTimeout: deadline, MaxResponseHeaderBytes: 64 << 10, DisableCompression: true}
	defer native.CloseIdleConnections()
	budget := &gitHTTPBudget{native: native, remaining: gitTransferBytes}
	client := &http.Client{Transport: budget, Timeout: deadline, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrSource }}
	backend := githttp.NewClientWithOptions(client, &githttp.ClientOptions{RedirectPolicy: githttp.NoFollowRedirects})
	endpoint, err := transport.NewEndpoint(q.Repository)
	if err != nil {
		return nil, "", err
	}
	var auth transport.AuthMethod
	if q.Credential != "" {
		auth = gitAuth{access}
	}
	session, err := backend.NewUploadPackSession(endpoint, auth)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if closeErr := session.Close(); err == nil && closeErr != nil {
			repository, commit, err = nil, "", ErrSource
		}
	}()
	refs, err := session.AdvertisedReferencesContext(ctx)
	if err != nil {
		return nil, "", err
	}
	name := q.Ref
	if q.Commit != "" {
		name = q.Commit
	}
	hash, err := resolveGitCommit(refs, name)
	if err != nil {
		return nil, "", errors.Join(errGitNoBranch, err)
	}
	commit = hash.String()
	if cached != nil {
		hit, err := cached(commit)
		if err != nil {
			return nil, "", err
		}
		if hit {
			return nil, commit, nil
		}
	}
	req := packp.NewUploadPackRequestFromCapabilities(refs.Capabilities)
	for _, c := range []capability.Capability{capability.Sideband, capability.Sideband64k, capability.ThinPack} {
		req.Capabilities.Delete(c)
	}
	if refs.Capabilities.Supports(capability.Shallow) {
		_ = req.Capabilities.Set(capability.Shallow)
		req.Depth = packp.DepthCommits(1)
	}
	req.Wants = []plumbing.Hash{hash}
	response, err := session.UploadPack(ctx, req)
	if err != nil {
		return nil, "", err
	}
	pack, readErr := io.ReadAll(io.LimitReader(response, gitTransferBytes+1))
	closeErr := response.Close()
	if readErr != nil || closeErr != nil || len(pack) > gitTransferBytes || boundedGitPack(ctx, pack) != nil {
		return nil, "", ErrSource
	}
	store := memory.NewStorage()
	if err = packfile.UpdateObjectStorage(store, bytes.NewReader(pack)); err != nil {
		return nil, "", err
	}
	if err = store.SetReference(plumbing.NewHashReference(plumbing.HEAD, hash)); err != nil {
		return nil, "", err
	}
	repository, err = git.Open(store, nil)
	return repository, commit, err
}
