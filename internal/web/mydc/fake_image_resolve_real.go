// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/internal/registryclient"

	"github.com/distribution/reference"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// REQ-31 `image-resolve` in mydcd's real shape (docs/reference/
// image-resolution.md).
//
// The fake follows control.Policy.imageResolveTarget:
//   - Normalize fails → INVALID_IMAGE, Kind unknown, no Trust.
//   - Kind managed when a built-in registry of this tenant serves the
//     authority (another tenant's only → denied); deleted/stopped/draining
//     → UNAVAILABLE. The digest comes from the fake's built-in images
//     (tag or digest not there → NOT_FOUND).
//   - Kind external when imagesource.Lookup picks a source; deleted or
//     disabled → SOURCE_REVOKED, no reader or draining → SOURCE_NOT_READY.
//   - Trust is the tenant's set-trust rules; untrusted → UNTRUSTED and
//     nothing below is "asked" (no network I/O, as in mydcd).
//   - The fake registry: FakeImageAuthFailedHost → UNAUTHORIZED,
//     FakeImageUnreachableHost → UNAVAILABLE, tag FakeImageMissingTag →
//     NOT_FOUND; an external source also follows SetRegistryLoginResult and
//     its Vault credential (INVALID_CREDENTIAL). docker.io answers an index
//     with linux/amd64 and linux/arm64; the rest a single manifest.

const (
	fakeImageIndexType    = "application/vnd.oci.image.index.v1+json"
	fakeImageManifestType = "application/vnd.oci.image.manifest.v1+json"
)

func (c *fakeConn) ResolveImage(ctx context.Context, tenant string, q control.ImageResolveQuery) (control.ImageResolveResult, error) {
	const m = "image-resolve"
	if !q.Valid() {
		return control.ImageResolveResult{}, fail(m, CodeInvalid, "Ref")
	}
	// Read covers ManageRegistry in the fake (a manager also reads).
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.ImageResolveResult{}, err
	}
	defer c.unlock()
	r, ok := c.f.w.resolveImageReal(tenant, q.Ref, c.f.now().Unix())
	if !ok {
		return control.ImageResolveResult{}, fail(m, CodeDenied, "")
	}
	return r, nil
}

func (w *world) resolveImageReal(tenant, ref string, now int64) (control.ImageResolveResult, bool) {
	r := control.ImageResolveResult{Kind: "unknown"}
	normalized, authority, repository, err := registryclient.Normalize(ref)
	if err != nil {
		r.Code = "INVALID_IMAGE"
		return r, true
	}
	r.Normalized = normalized
	rules, _ := access.CanonicalTrust(w.trust[tenant])
	_, trusted := access.MatchImageTrust(rules, authority, repository)
	r.Trust = control.ImageTrustCheck{Trusted: trusted, Rules: rules}

	var managed *RegistryView
	other := false
	for i := range w.registries {
		reg := &w.registries[i]
		if registryAuthority(*reg) != authority {
			continue
		}
		if reg.Tenant != tenant {
			other = true
			continue
		}
		managed = reg
		break
	}
	var source *extSource
	switch {
	case managed != nil:
		r.Kind, r.Source = "managed", managed.ID
		if managed.Deleted || !managed.Active || managed.Draining {
			r.Code = "UNAVAILABLE"
		}
	case other:
		return control.ImageResolveResult{}, false
	default:
		e := w.extReal()
		e.settle(now)
		var defs []imagesource.Definition
		for _, k := range sortedKeys(e.rows) {
			if x := e.rows[k]; x.spec.Tenant == tenant {
				defs = append(defs, imagesource.Definition{Spec: imagesource.Own(x.spec), Deleted: x.deleted})
			}
		}
		d, err := imagesource.Lookup(defs, tenant, access.Image{Registry: authority, Repository: repository})
		if err != nil {
			return control.ImageResolveResult{}, false
		}
		if d != nil {
			source = e.rows[tenant+"/"+d.Spec.ID]
			r.Kind, r.Source = "external", d.Spec.ID
			switch {
			case d.Deleted || !d.Spec.Enabled:
				r.Code = "SOURCE_REVOKED"
			case source.reader == nil || source.reader.Draining:
				r.Code = "SOURCE_NOT_READY"
			}
		}
	}
	if !trusted {
		r.Code = "UNTRUSTED"
	}
	if r.Code != "" {
		return r, true
	}

	// The fake registry answers (mydcd would ask the owner / source reader
	// / anonymous HTTPS here).
	named, _ := reference.ParseNormalizedNamed(normalized)
	tagged, _ := named.(reference.Tagged)
	switch {
	case source != nil && w.loginResult[authority] != "" && w.loginResult[authority] != "ok":
		r.Code = realLoginCode(w.loginResult[authority])
	case authority == FakeImageAuthFailedHost:
		r.Code = "UNAUTHORIZED"
	case authority == FakeImageUnreachableHost || strings.Contains(authority, "unreachable"):
		r.Code = "UNAVAILABLE"
	case source != nil && source.spec.Credential != nil && !w.extCredentialOK(*source.spec.Credential):
		r.Code = "INVALID_CREDENTIAL"
	case tagged != nil && tagged.Tag() == FakeImageMissingTag:
		r.Code = "NOT_FOUND"
	}
	if r.Code != "" {
		return r, true
	}
	digest := "sha256:" + hex.EncodeToString(func() []byte { d := fakeDigest("manifest", normalized); return d[:] }())
	if d, ok := named.(reference.Digested); ok {
		digest = d.Digest().String()
	}
	if managed != nil {
		digest = ""
		for _, im := range w.img.images[tenant] {
			if im.Repository != repository {
				continue
			}
			if d, ok := named.(reference.Digested); ok && im.Digest == d.Digest().String() || tagged != nil && slices.Contains(im.Tags, tagged.Tag()) {
				digest = im.Digest
				break
			}
		}
		if digest == "" {
			r.Code = "NOT_FOUND"
			return r, true
		}
	}
	img := &registryclient.Resolution{Normalized: normalized, Registry: authority, Repository: repository, Pinned: authority + "/" + repository + "@" + digest,
		Digest: digest, MediaType: fakeImageManifestType, ManifestBytes: 1024}
	if authority == "docker.io" {
		img.MediaType, img.ManifestBytes = fakeImageIndexType, 512
		for _, p := range []v1.Platform{{OS: "linux", Architecture: "amd64"}, {OS: "linux", Architecture: "arm64", Variant: "v8"}} {
			child := fakeDigest(digest, p.String())
			img.Platforms = append(img.Platforms, registryclient.PlatformDigest{Digest: "sha256:" + hex.EncodeToString(child[:]), Platform: &p})
		}
	}
	r.Code, r.Image = "OK", img
	return r, true
}

// registryAuthority: the authority a built-in registry serves (Spec when the
// registry was put through put-registry, else the fixture Endpoint).
func registryAuthority(r RegistryView) string {
	if r.Spec.Authority != "" {
		return r.Spec.Authority
	}
	return r.Endpoint
}
