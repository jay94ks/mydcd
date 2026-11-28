// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// The web as a registry client of a built-in registry (UI-88 upload, UI-89
// layers, tag add). sfcd decides who may pull or push by issuing — or not
// — a short-lived credential scoped to one repository (registry-credential,
// the same `docker login` the CLI uses); the web then speaks the standard
// distribution API (token flow, blobs, manifests) with it. The credential
// never leaves the daemon: it is not sent to the browser, stored, logged or
// journaled. When the registry token runs out the client asks sfcd for a
// new credential, so a long push survives it while the login lasts.

// Manifest media types the client accepts.
var manifestAccept = strings.Join([]string{
	"application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json", "application/vnd.docker.distribution.manifest.list.v2+json",
}, ", ")

const maxManifestBytes = 4 << 20

// regClient talks to one repository of one built-in registry.
type regClient struct {
	base  string // scheme://authority
	repo  string
	scope string
	hc    *http.Client
	// login asks sfcd for a credential: username and secret (cleared by
	// the caller after use).
	login func(ctx context.Context) (string, []byte, error)

	mu    sync.Mutex
	token string // registry bearer token (memory only)
}

// registryClient asks sfcd for a credential (actions "pull" and/or "push")
// and returns a client for repository.
func (s *Server) registryClient(ctx context.Context, ws *webSession, tenant, id, repository string, actions ...string) (*regClient, error) {
	actions = slices.Sorted(slices.Values(actions))
	repo, got, err := registry.RequestedScope("repository:" + repository + ":" + strings.Join(actions, ","))
	if err != nil || repo != repository || !slices.Equal(got, actions) {
		return nil, invalid("repository: an image path such as shop/web")
	}
	var authority string
	login := func(ctx context.Context) (string, []byte, error) {
		var cred userauth.RegistryCredential
		err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
			var err error
			cred, err = c.RegistryCredential(ctx, tenant, sfc.RegistryCredentialRequest{ID: id, Repository: repo, Actions: actions})
			return err
		})
		if err != nil {
			return "", nil, err
		}
		if authority == "" {
			authority = cred.Authority
		} else if authority != cred.Authority {
			clear(cred.Credential)
			return "", nil, &httpErr{http.StatusConflict, "registry-changed", "the registry address changed"}
		}
		return ws.user.Username, cred.Credential, nil
	}
	// The first credential also tells the address.
	user, secret, err := login(ctx)
	if err != nil {
		return nil, err
	}
	scheme := "https"
	if s.opt.RegistryPlainHTTP {
		scheme = "http"
	}
	rt := s.opt.RegistryTransport
	if rt == nil {
		rt = http.DefaultTransport
	}
	c := &regClient{base: scheme + "://" + authority, repo: repo, scope: "repository:" + repo + ":" + strings.Join(actions, ","),
		hc: &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, login: login}
	err = c.authenticate(ctx, user, secret)
	clear(secret)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// authenticate runs the token flow (GET /v2/ → Bearer challenge → token
// endpoint with Basic username:secret). A registry without a challenge
// needs no token.
func (c *regClient) authenticate(ctx context.Context, user string, secret []byte) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/v2/", nil)
	res, err := c.hc.Do(req)
	if err != nil {
		return registryUnreachable(err)
	}
	res.Body.Close()
	if res.StatusCode == http.StatusOK {
		return nil
	}
	ch := parseBearer(res.Header.Get("WWW-Authenticate"))
	if res.StatusCode != http.StatusUnauthorized || ch["realm"] == "" {
		return &httpErr{http.StatusBadGateway, "registry", "the registry answered " + res.Status}
	}
	u, err := url.Parse(ch["realm"])
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return &httpErr{http.StatusBadGateway, "registry", "the registry token address is not usable"}
	}
	// The token endpoint must be on the same registry.
	base, _ := url.Parse(c.base)
	u.Scheme, u.Host = base.Scheme, base.Host
	q := u.Query()
	if ch["service"] != "" {
		q.Set("service", ch["service"])
	}
	q.Set("scope", c.scope)
	u.RawQuery = q.Encode()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.SetBasicAuth(user, string(secret))
	res, err = c.hc.Do(req)
	if err != nil {
		return registryUnreachable(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return &httpErr{http.StatusForbidden, "denied", "the registry refused the credential"}
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&tok) != nil || tok.Token == "" && tok.AccessToken == "" {
		return &httpErr{http.StatusBadGateway, "registry", "the registry token answer is not usable"}
	}
	c.mu.Lock()
	c.token = tok.Token
	if c.token == "" {
		c.token = tok.AccessToken
	}
	c.mu.Unlock()
	return nil
}

func parseBearer(h string) map[string]string {
	out := map[string]string{}
	rest, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return out
	}
	for rest != "" {
		k, v, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		k = strings.TrimSpace(k)
		if strings.HasPrefix(v, `"`) {
			end := strings.Index(v[1:], `"`)
			if end < 0 {
				break
			}
			out[k], rest = v[1:end+1], strings.TrimPrefix(v[end+2:], ",")
		} else {
			val, r, _ := strings.Cut(v, ",")
			out[k], rest = val, r
		}
	}
	return out
}

// do sends one request; on 401 it logs in again once (when body can be
// rewound: newBody returns a fresh body each time, or nil for none).
func (c *regClient) do(ctx context.Context, method, rawURL string, hdr http.Header, newBody func() (io.Reader, int64)) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		var body io.Reader
		length := int64(0)
		if newBody != nil {
			body, length = newBody()
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
		if err != nil {
			return nil, err
		}
		if body != nil {
			req.ContentLength = length
		}
		for k, v := range hdr {
			req.Header[k] = v
		}
		c.mu.Lock()
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		c.mu.Unlock()
		res, err := c.hc.Do(req)
		if err != nil {
			return nil, registryUnreachable(err)
		}
		if res.StatusCode != http.StatusUnauthorized || attempt > 0 {
			return res, nil
		}
		res.Body.Close()
		user, secret, err := c.login(ctx)
		if err != nil {
			return nil, err
		}
		err = c.authenticate(ctx, user, secret)
		clear(secret)
		if err != nil {
			return nil, err
		}
	}
}

func (c *regClient) url(kind, ref string) string {
	return c.base + "/v2/" + c.repo + "/" + kind + "/" + ref
}

func statusError(res *http.Response, what string) error {
	switch res.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return &httpErr{http.StatusForbidden, "denied", "the registry refused the credential"}
	case http.StatusNotFound:
		return &httpErr{http.StatusNotFound, "not-found", "no such " + what}
	}
	return &httpErr{http.StatusBadGateway, "registry", what + ": the registry answered " + res.Status}
}

func registryUnreachable(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &httpErr{http.StatusBadGateway, "registry-unreachable", "the registry is not reachable"}
}

// manifest reads a manifest by tag or digest: body, media type, digest.
func (c *regClient) manifest(ctx context.Context, ref string) ([]byte, string, string, error) {
	res, err := c.do(ctx, http.MethodGet, c.url("manifests", ref), http.Header{"Accept": {manifestAccept}}, nil)
	if err != nil {
		return nil, "", "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, "", "", statusError(res, "image")
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxManifestBytes+1))
	if err != nil || len(body) > maxManifestBytes {
		return nil, "", "", &httpErr{http.StatusBadGateway, "registry", "the manifest is not readable"}
	}
	sum := sha256.Sum256(body)
	dg := "sha256:" + hex.EncodeToString(sum[:])
	if strings.HasPrefix(ref, "sha256:") && ref != dg {
		return nil, "", "", &httpErr{http.StatusBadGateway, "registry", "the manifest does not match its digest"}
	}
	mt, _, _ := strings.Cut(res.Header.Get("Content-Type"), ";")
	return body, strings.TrimSpace(mt), dg, nil
}

// headManifest returns the digest a tag points at ("" when there is none).
func (c *regClient) headManifest(ctx context.Context, ref string) (string, error) {
	res, err := c.do(ctx, http.MethodHead, c.url("manifests", ref), http.Header{"Accept": {manifestAccept}}, nil)
	if err != nil {
		return "", err
	}
	res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		if d := res.Header.Get("Docker-Content-Digest"); d != "" {
			return d, nil
		}
		_, _, d, err := c.manifest(ctx, ref)
		return d, err
	case http.StatusNotFound:
		return "", nil
	}
	return "", statusError(res, "image")
}

func (c *regClient) putManifest(ctx context.Context, ref, mediaType string, body []byte) error {
	res, err := c.do(ctx, http.MethodPut, c.url("manifests", ref), http.Header{"Content-Type": {mediaType}},
		func() (io.Reader, int64) { return strings.NewReader(string(body)), int64(len(body)) })
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		return statusError(res, "manifest")
	}
	return nil
}

func (c *regClient) blobExists(ctx context.Context, digest string) (bool, error) {
	res, err := c.do(ctx, http.MethodHead, c.url("blobs", digest), nil, nil)
	if err != nil {
		return false, err
	}
	res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, statusError(res, "blob")
}

// blob opens a blob for reading (the caller closes it).
func (c *regClient) blob(ctx context.Context, digest string) (io.ReadCloser, int64, error) {
	res, err := c.do(ctx, http.MethodGet, c.url("blobs", digest), nil, nil)
	if err != nil {
		return nil, 0, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, 0, statusError(res, "layer")
	}
	return res.Body, res.ContentLength, nil
}

// pushBlob uploads one blob (POST, PATCH with the content, PUT ?digest=).
// open returns a fresh reader of the content each time.
func (c *regClient) pushBlob(ctx context.Context, digest string, size int64, open func() (io.Reader, error)) error {
	res, err := c.do(ctx, http.MethodPost, c.base+"/v2/"+c.repo+"/blobs/uploads/", nil, nil)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusAccepted {
		return statusError(res, "upload")
	}
	loc, err := c.location(res)
	if err != nil {
		return err
	}
	var openErr error
	res, err = c.do(ctx, http.MethodPatch, loc, http.Header{"Content-Type": {"application/octet-stream"}}, func() (io.Reader, int64) {
		r, err := open()
		if err != nil {
			openErr = err
			return strings.NewReader(""), 0
		}
		return r, size
	})
	if openErr != nil {
		return openErr
	}
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusAccepted && res.StatusCode != http.StatusNoContent {
		return statusError(res, "upload")
	}
	if loc, err = c.location(res); err != nil {
		return err
	}
	u, _ := url.Parse(loc)
	q := u.Query()
	q.Set("digest", digest)
	u.RawQuery = q.Encode()
	res, err = c.do(ctx, http.MethodPut, u.String(), nil, nil)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return statusError(res, "upload")
	}
	return nil
}

func (c *regClient) location(res *http.Response) (string, error) {
	loc := res.Header.Get("Location")
	if loc == "" {
		return "", &httpErr{http.StatusBadGateway, "registry", "the registry gave no upload location"}
	}
	base, _ := url.Parse(c.base)
	u, err := base.Parse(loc)
	if err != nil || u.Host != base.Host {
		return "", &httpErr{http.StatusBadGateway, "registry", "the upload location is on another host"}
	}
	return u.String(), nil
}

// readBlobJSON reads a small blob (config) and checks its digest.
func (c *regClient) readBlobJSON(ctx context.Context, digest string, v any) ([]byte, error) {
	rc, _, err := c.blob(ctx, digest)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, maxManifestBytes+1))
	if err != nil || len(body) > maxManifestBytes {
		return nil, fmt.Errorf("blob %s: too large", digest)
	}
	sum := sha256.Sum256(body)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, &httpErr{http.StatusBadGateway, "registry", "the blob does not match its digest"}
	}
	if v != nil {
		if err := json.Unmarshal(body, v); err != nil {
			return nil, &httpErr{http.StatusBadGateway, "registry", "the blob is not JSON"}
		}
	}
	return body, nil
}

func itoa64(v int64) string { return strconv.FormatInt(v, 10) }
