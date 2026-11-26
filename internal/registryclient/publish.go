// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	registrytransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// PublishOutcome separates dependency uploads from the root manifest PUT.
// A sent root with a lost/ambiguous response is UNKNOWN, never absence. It
// contains no private auth, foreign error body or remote upload location.
type PublishOutcome struct {
	Code               string
	Digest             string
	At                 uint64
	Started, Attempted bool
}

func (o PublishOutcome) Valid() bool {
	if o.At == 0 || o.Attempted && !o.Started {
		return false
	}
	if !pruneDigest(o.Digest) && (o.Digest != "" || o.Started || o.Attempted || o.Code == "OK" || o.Code == "UNKNOWN") {
		return false
	}
	if o.Code == "UNKNOWN" || o.Code == "OK" {
		return o.Attempted
	}
	return ValidResultCode(o.Code) && o.Code != "OK"
}

type publishOnceTransport struct {
	mu                             sync.Mutex
	inner                          http.RoundTripper
	host, repository, path, digest string
	before                         func(context.Context, bool) error
	started, attempted             bool
	beforeCode                     string
	status                         int
	responseDigest                 string
}

func (p *publishOnceTransport) RoundTrip(q *http.Request) (*http.Response, error) {
	if q.URL == nil || q.URL.Scheme != "https" || q.URL.Host != p.host {
		return nil, &Error{Code: "AUTH_SCOPE"}
	}
	if q.Method == http.MethodGet || q.Method == http.MethodHead {
		return p.inner.RoundTrip(q)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	root := q.Method == http.MethodPut && q.URL.Path == p.path
	// Child manifests are immutable content digests; only the original root
	// may name a mutable tag. Blob upload URLs stay on this one repository.
	prefix := "/v2/" + p.repository + "/"
	child := strings.TrimPrefix(q.URL.Path, prefix+"manifests/")
	upload := (q.Method == http.MethodPost || q.Method == http.MethodPatch || q.Method == http.MethodPut) && strings.HasPrefix(q.URL.Path, prefix+"blobs/uploads/")
	if p.attempted || !strings.HasPrefix(q.URL.Path, prefix) || !root && !upload && !(q.Method == http.MethodPut && pruneDigest(child)) {
		return nil, &Error{Code: "AUTH_SCOPE"}
	}
	if root {
		if q.URL.RawQuery != "" || q.Body == nil || q.ContentLength > MaxMetadataBytes {
			return nil, &Error{Code: "AUTH_SCOPE"}
		}
		raw, err := io.ReadAll(io.LimitReader(q.Body, MaxMetadataBytes+1))
		closeErr := q.Body.Close()
		if err != nil || closeErr != nil || int64(len(raw)) > MaxMetadataBytes || fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) != p.digest {
			return nil, &Error{Code: "INVALID_IMAGE"}
		}
		q = q.Clone(q.Context())
		q.Body = io.NopCloser(bytes.NewReader(raw))
		q.GetBody = nil // no Go HTTP replay of this mutating root request
	}
	// The owner durably records Started/Sent and rechecks current permission at
	// the actual write boundary, after authentication and before network I/O.
	if err := p.before(q.Context(), root); err != nil {
		p.beforeCode = ResultCode(err)
		return nil, err
	}
	p.started = true
	if root {
		p.attempted = true
	}
	response, err := p.inner.RoundTrip(q)
	if root && response != nil && err == nil {
		p.status = response.StatusCode
		p.responseDigest = response.Header.Get("Docker-Content-Digest")
	}
	return response, err
}

// PublishImage uploads one validated local Image OR ImageIndex to one exact
// reference. The caller owns output lifetime, current authority and a durable
// before callback. This call joins the SDK's writes and never retries a failed
// layer/manifest attempt; subsequent recovery must observe the original tag.
func (a *Access) PublishImage(ctx context.Context, target string, image v1.Image, index v1.ImageIndex, before func(context.Context, bool) error) PublishOutcome {
	out := PublishOutcome{Code: "INVALID_IMAGE", At: uint64(time.Now().UnixMilli())}
	if ctx == nil || before == nil || (image == nil) == (index == nil) {
		return out
	}
	a.auth.mu.Lock()
	closed := a.auth.closed
	a.auth.mu.Unlock()
	normalized, authority, repository, err := Normalize(target)
	if closed || err != nil || normalized != target || authority != a.authority {
		out.Code = "DENIED"
		return out
	}
	ref, err := name.ParseReference(target, name.StrictValidation)
	if err != nil {
		return out
	}
	var taggable interface {
		remote.Taggable
		MediaType() (types.MediaType, error)
	}
	if image != nil {
		taggable = image
	} else {
		taggable = index
	}
	raw, err := taggable.RawManifest()
	if err != nil {
		return out
	}
	media, err := taggable.MediaType()
	if err != nil {
		return out
	}
	resolved, err := ResolveManifest(target, string(media), raw)
	if err != nil {
		return out
	}
	out.Digest = resolved.Digest
	if digest, ok := ref.(name.Digest); ok && digest.DigestStr() != out.Digest {
		return out
	}
	gate := &publishOnceTransport{inner: a.bound, host: authority, repository: repository, path: "/v2/" + repository + "/manifests/" + ref.Identifier(), digest: out.Digest, before: before}
	// Use the same public authenticated-wrapper mechanism as DeleteManifest.
	// It avoids outer HTTP log/retry wrappers; disable the SDK writer's own
	// whole-upload/manifest retries as well. There is no ambient keychain.
	transport, err := registrytransport.NewWithContext(ctx, ref.Context().Registry, a.auth, gate, []string{ref.Context().Scope(registrytransport.PushScope)})
	if err == nil {
		options := []remote.Option{remote.WithContext(ctx), remote.WithAuth(a.auth), remote.WithTransport(transport), remote.WithJobs(1), remote.WithRetryPredicate(func(error) bool { return false })}
		if image != nil {
			err = remote.Write(ref, image, options...)
		} else {
			err = remote.WriteIndex(ref, index, options...)
		}
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	out.Started, out.Attempted, out.At = gate.started, gate.attempted, uint64(time.Now().UnixMilli())
	switch gate.status {
	case http.StatusOK, http.StatusCreated:
		if err == nil && (gate.responseDigest == "" || gate.responseDigest == out.Digest) {
			out.Code = "OK"
		} else {
			out.Code = "UNKNOWN"
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		out.Code = "DENIED"
	case http.StatusMethodNotAllowed, http.StatusNotImplemented:
		out.Code = "UNSUPPORTED"
	default:
		if gate.attempted {
			out.Code = "UNKNOWN"
		} else if gate.beforeCode != "" {
			out.Code = gate.beforeCode
		} else {
			out.Code = ResultCode(err)
			if out.Code == "OK" {
				out.Code = "UNAVAILABLE"
			}
		}
	}
	return out
}
