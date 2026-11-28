// SPDX-License-Identifier: Apache-2.0

package access

import (
	_ "crypto/sha256" // Register the only supported content digest algorithm.
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/distribution/reference"
)

type TrustRule struct{ Registry, Repository string }

// Image is a parsed image reference. Reference is the normalized form; Tag
// is set only for a tag reference and Digest only for a digest reference.
type Image struct{ Reference, Registry, Repository, Tag, Digest string }

// Pinned reports a digest reference.
func (i Image) Pinned() bool { return i.Digest != "" }

func registryName(s string) bool {
	if s == "" || len(s) > 253 || s != strings.ToLower(s) || strings.ContainsAny(s, "/@?#%\\ \t\r\n") || strings.HasSuffix(s, ".") {
		return false
	}
	u, err := url.Parse("https://" + s)
	if err != nil || u.Host != s || u.Hostname() == "" || u.User != nil || u.Path != "" {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
			return false
		}
	} else if strings.HasSuffix(s, ":") {
		return false
	}
	for _, b := range []byte(u.Hostname()) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '.' || b == ':') {
			return false
		}
	}
	return true
}
func CanonicalTrust(rules []TrustRule) ([]TrustRule, error) {
	if len(rules) > 256 {
		return nil, ErrInvalid
	}
	rules = slices.Clone(rules)
	for _, r := range rules {
		if !registryName(r.Registry) || r.Registry == "index.docker.io" {
			return nil, ErrInvalid
		}
		if r.Repository != "**" {
			n, err := reference.WithName(r.Registry + "/" + r.Repository)
			if err != nil || reference.Domain(n) != r.Registry || reference.Path(n) != r.Repository {
				return nil, ErrInvalid
			}
		}
	}
	slices.SortFunc(rules, func(a, b TrustRule) int {
		if a.Registry != b.Registry {
			return strings.Compare(a.Registry, b.Registry)
		}
		return strings.Compare(a.Repository, b.Repository)
	})
	for i := 1; i < len(rules); i++ {
		if rules[i] == rules[i-1] {
			return nil, ErrInvalid
		}
	}
	return rules, nil
}

// ParseImage accepts a tag or a digest reference and normalizes it:
// alpine is docker.io/library/alpine:latest, and a reference carrying both a
// tag and a digest keeps only the digest. A tag is never resolved or pinned
// here; only an instantiated container keeps the digest it was created from.
// A bare local image ID is refused.
func ParseImage(ref string) (Image, error) {
	if len(ref) > 1024 || strings.ContainsAny(ref, "\x00\r\n \t") || strings.HasPrefix(ref, "sha256:") {
		return Image{}, ErrInvalid
	}
	n, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return Image{}, ErrInvalid
	}
	i := Image{Registry: reference.Domain(n), Repository: reference.Path(n)}
	if d, ok := n.(reference.Digested); ok {
		if d.Digest().Algorithm() != "sha256" || d.Digest().Validate() != nil {
			return Image{}, ErrInvalid
		}
		i.Digest = d.Digest().String()
		i.Reference = n.Name() + "@" + i.Digest
	} else {
		t, ok := reference.TagNameOnly(n).(reference.Tagged)
		if !ok {
			return Image{}, ErrInvalid
		}
		i.Tag = t.Tag()
		i.Reference = n.Name() + ":" + i.Tag
	}
	if !registryName(i.Registry) {
		return Image{}, ErrInvalid
	}
	return i, nil
}

// NormalizeImage is ParseImage's normalized reference.
func NormalizeImage(ref string) (string, error) {
	i, err := ParseImage(ref)
	return i.Reference, err
}

// CheckImageRef is CheckImage for a tag or digest reference: Deploy on the
// node plus repository trust. Creating a container still needs CheckImage
// on the digest the tag resolved to at that moment.
func (c Catalog) CheckImageRef(actor, tenant, node, ref string) (Image, error) {
	if c.Authorize(actor, tenant, Deploy, node) != nil {
		return Image{}, ErrDenied
	}
	return c.CheckImageRefTrust(tenant, ref)
}

// CheckImageRefTrust is CheckImageTrust for a tag or digest reference.
func (c Catalog) CheckImageRefTrust(tenant, ref string) (Image, error) {
	i, err := ParseImage(ref)
	if err != nil {
		return Image{}, err
	}
	if err := c.CheckImageRepositoryTrust(tenant, i.Registry, i.Repository); err != nil {
		return Image{}, err
	}
	return i, nil
}

// PinImage normalizes Docker Hub aliases but never resolves mutable tags or
// accepts a bare local image ID as evidence of an authorized repository origin.
func PinImage(ref string) (Image, error) {
	if len(ref) > 1024 || strings.ContainsAny(ref, "\x00\r\n \t") {
		return Image{}, ErrInvalid
	}
	n, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return Image{}, ErrInvalid
	}
	d, ok := n.(reference.Digested)
	if !ok || d.Digest().Algorithm() != "sha256" || d.Digest().Validate() != nil {
		return Image{}, ErrInvalid
	}
	i := Image{Reference: n.String(), Registry: reference.Domain(n), Repository: reference.Path(n), Digest: d.Digest().String()}
	if !registryName(i.Registry) {
		return Image{}, ErrInvalid
	}
	return i, nil
}

// CheckImage is also required for cached images and immediately before create.
// A successful prior pull or a shared content-addressed cache grants no rights.
func (c Catalog) CheckImage(actor, tenant, node, ref string) (Image, error) {
	if c.Authorize(actor, tenant, Deploy, node) != nil {
		return Image{}, ErrDenied
	}
	return c.CheckImageTrust(tenant, ref)
}

// CheckImageTrust reports repository trust only; it grants no user, node or
// deployment authority. Diagnostics must not label a revoked role as a removed
// image source. Every actual pull/create still uses CheckImage above.
func (c Catalog) CheckImageTrust(tenant, ref string) (Image, error) {
	i, err := PinImage(ref)
	if err != nil {
		return Image{}, err
	}
	if err := c.CheckImageRepositoryTrust(tenant, i.Registry, i.Repository); err != nil {
		return Image{}, err
	}
	return i, nil
}

// CheckImageRepositoryTrust is the same repository rule used after digest
// resolution and by actual pull/create. It grants no operation permission.
func (c Catalog) CheckImageRepositoryTrust(tenant, authority, repository string) error {
	t := c.tenants[tenant]
	if _, ok := MatchImageTrust(t.ImageSources, authority, repository); ok {
		return nil
	}
	return ErrDenied
}

// MatchImageTrust reports the same exact-repository or ** rule used by create.
func MatchImageTrust(rules []TrustRule, authority, repository string) (TrustRule, bool) {
	for _, r := range rules {
		if r.Registry == authority && (r.Repository == "**" || r.Repository == repository) {
			return r, true
		}
	}
	return TrustRule{}, false
}
