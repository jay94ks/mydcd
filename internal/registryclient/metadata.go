// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	registrytransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

type PlatformDigest struct {
	Digest   string
	Platform *v1.Platform `json:",omitempty"`
}
type Resolution struct {
	Normalized, Registry, Repository, Pinned, Digest, MediaType string
	ManifestBytes                                               int64
	Platforms                                                   []PlatformDigest `json:",omitempty"`
}

// Normalize permits a tag for a read-only resolution, never a local image ID,
// URL or implicit registry credential. Runtime trust still checks Pinned.
func Normalize(raw string) (normalized, authority, repository string, err error) {
	if raw == "" || strings.HasPrefix(raw, "sha256:") || len(raw) > 1024 || strings.ContainsAny(raw, "\x00\r\n \t") {
		return "", "", "", &Error{Code: "INVALID_IMAGE"}
	}
	named, e := reference.ParseNormalizedNamed(raw)
	if e != nil {
		return "", "", "", &Error{Code: "INVALID_IMAGE"}
	}
	named = reference.TagNameOnly(named)
	if _, err := access.CanonicalTrust([]access.TrustRule{{Registry: reference.Domain(named), Repository: "**"}}); err != nil {
		return "", "", "", &Error{Code: "INVALID_IMAGE"}
	}
	if digested, ok := named.(reference.Digested); ok && (digested.Digest().Algorithm() != "sha256" || digested.Digest().Validate() != nil) {
		return "", "", "", &Error{Code: "INVALID_IMAGE"}
	}
	return named.String(), reference.Domain(named), reference.Path(named), nil
}

// Resolve returns only public image coordinates and platform descriptors. It
// grants no deployment/image-source trust and returns no manifest/config body.
func (a *Access) Resolve(ctx context.Context, raw string) (Resolution, error) {
	result, _, err := a.manifest(ctx, raw)
	return result, err
}

func (a *Access) manifest(ctx context.Context, raw string) (Resolution, []byte, error) {
	a.auth.mu.Lock()
	closed := a.auth.closed
	a.auth.mu.Unlock()
	if closed {
		return Resolution{}, nil, &Error{Code: "CLOSED"}
	}
	normalized, authority, _, err := Normalize(raw)
	if err != nil {
		return Resolution{}, nil, err
	}
	if authority != a.authority {
		return Resolution{}, nil, &Error{Code: "AUTHORITY_MISMATCH"}
	}
	ref, err := name.ParseReference(normalized, name.StrictValidation)
	if err != nil {
		return Resolution{}, nil, &Error{Code: "INVALID_IMAGE"}
	}
	descriptor, err := remote.Get(ref, a.options(ctx, v1.Platform{})...)
	if err != nil {
		return Resolution{}, nil, Sanitize(err)
	}
	if descriptor.Digest.Algorithm != "sha256" || descriptor.Size < 0 || descriptor.Size > MaxMetadataBytes {
		return Resolution{}, nil, &Error{Code: "METADATA_BUDGET"}
	}
	result, err := ResolveManifest(normalized, string(descriptor.MediaType), descriptor.Manifest)
	if err != nil {
		return Resolution{}, nil, err
	}
	if result.Digest != descriptor.Digest.String() || result.ManifestBytes != descriptor.Size {
		return Resolution{}, nil, &Error{Code: "INVALID_IMAGE"}
	}
	return result, descriptor.Manifest, nil
}

// Login authenticates with the registry's own /v2/ challenge. No catalog
// privilege or image pull is silently substituted for the login-only probe.
func (a *Access) Login(ctx context.Context) error {
	a.auth.mu.Lock()
	closed := a.auth.closed
	a.auth.mu.Unlock()
	if closed {
		return &Error{Code: "CLOSED"}
	}
	registry, err := name.NewRegistry(a.authority, name.StrictValidation)
	if err != nil {
		return &Error{Code: "INVALID_SOURCE"}
	}
	transport, err := registrytransport.NewWithContext(ctx, registry, a.auth, a.bound, nil)
	if err != nil {
		return Sanitize(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+registry.RegistryStr()+"/v2/", nil)
	if err != nil {
		return &Error{Code: "INVALID_SOURCE"}
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return Sanitize(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Sanitize(&registrytransport.Error{StatusCode: response.StatusCode})
	}
	if _, err = io.Copy(io.Discard, response.Body); err != nil {
		return Sanitize(err)
	}
	return nil
}
