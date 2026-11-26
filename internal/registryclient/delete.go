// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	registrytransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// DeleteOutcome records only the original HTTP attempt, never credentials,
// raw remote errors or an absence inferred by a later GET. UNKNOWN means the
// request may have executed; it must not be automatically sent again.
type DeleteOutcome struct {
	Code      string
	At        uint64
	Attempted bool
}

func (r DeleteOutcome) Valid() bool {
	if r.At == 0 {
		return false
	}
	switch r.Code {
	case "OK", "ALREADY_ABSENT", "UNKNOWN":
		return r.Attempted
	case "DENIED", "UNSUPPORTED", "UNAVAILABLE":
		return true
	}
	return false
}

type deleteOnceTransport struct {
	mu         sync.Mutex
	inner      http.RoundTripper
	host, path string
	before     func(context.Context) error
	attempted  bool
	status     int
}

func (d *deleteOnceTransport) RoundTrip(q *http.Request) (*http.Response, error) {
	if q.Method != http.MethodDelete {
		return d.inner.RoundTrip(q) // the pinned SDK's challenge/token handshake
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.attempted || q.URL == nil || q.URL.Scheme != "https" || q.URL.Host != d.host || q.URL.Path != d.path || q.URL.RawQuery != "" || q.Body != nil {
		return nil, &Error{Code: "AUTH_SCOPE"}
	}
	// The owner checks current permission and references and persists Sent at
	// this last boundary, after authentication but before the actual DELETE.
	if err := d.before(q.Context()); err != nil {
		return nil, err
	}
	d.attempted = true
	response, err := d.inner.RoundTrip(q)
	if response != nil && err == nil {
		d.status = response.StatusCode
	}
	return response, err
}

// DeleteManifest deletes only an immutable digest. Mutable-tag deletion has no
// portable atomic expected-digest precondition; callers must not silently turn
// a tag-only request into digest deletion (which could remove other tags).
// before must durably record the original intent before allowing network I/O.
func (a *Access) DeleteManifest(ctx context.Context, raw string, before func(context.Context) error) DeleteOutcome {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out := DeleteOutcome{Code: "UNAVAILABLE"}
	ref, err := a.imageReference(raw)
	if err != nil || before == nil {
		out.Code, out.At = "DENIED", uint64(time.Now().UnixMilli())
		return out
	}
	gate := &deleteOnceTransport{inner: a.bound, host: ref.Context().RegistryStr(), path: "/v2/" + ref.Context().RepositoryStr() + "/manifests/" + ref.Identifier(), before: before}
	// NewWithContext supplies the SDK's authenticated Wrapper, which opts out
	// of the outer retry/log wrappers. The guard still rejects auth replays or
	// redirected DELETEs. No private/unsupported Wrapper fields are constructed.
	transport, err := registrytransport.NewWithContext(ctx, ref.Context().Registry, a.auth, gate, []string{ref.Context().Scope(registrytransport.DeleteScope)})
	if err == nil {
		err = remote.Delete(ref, remote.WithContext(ctx), remote.WithAuth(a.auth), remote.WithTransport(transport))
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	out.Attempted, out.At = gate.attempted, uint64(time.Now().UnixMilli())
	switch gate.status {
	case http.StatusOK, http.StatusAccepted:
		out.Code = "OK"
	case http.StatusNotFound:
		out.Code = "ALREADY_ABSENT"
	case http.StatusUnauthorized, http.StatusForbidden:
		out.Code = "DENIED"
	case http.StatusMethodNotAllowed, http.StatusNotImplemented:
		out.Code = "UNSUPPORTED"
	default:
		if gate.attempted {
			out.Code = "UNKNOWN"
		} else {
			switch ResultCode(err) {
			case "UNAUTHORIZED", "DENIED", "AUTH_SCOPE", "AUTHORITY_MISMATCH", "CLOSED":
				out.Code = "DENIED"
			case "UNSUPPORTED":
				out.Code = "UNSUPPORTED"
			}
		}
	}
	return out
}
