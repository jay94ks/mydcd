// SPDX-License-Identifier: Apache-2.0

package imagesource

import (
	"errors"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
)

// Source contains public selectors only. Provider credentials are read
// at the native edge and must never be added to this replicated definition.
type Source struct {
	Tenant, ID, Authority, Repository string
	Enabled                           bool
	Auth                              string
	Credential                        *Credential           `json:",omitempty"`
	CA                                *CertificateAuthority `json:",omitempty"`
}

type Credential struct{ Realm, ID, UsernameKey, PasswordKey string }
type CertificateAuthority struct{ Realm, ID, Key string }

type Reference struct{ Realm, ID string }

// References is the ordered, deduplicated set approved for a Task or reader.
func (s Source) References() []Reference {
	var refs []Reference
	if c := s.Credential; c != nil {
		refs = append(refs, Reference{c.Realm, c.ID})
	}
	if c := s.CA; c != nil {
		r := Reference{c.Realm, c.ID}
		if len(refs) == 0 || refs[0] != r {
			refs = append(refs, r)
		}
	}
	return refs
}

// Definition includes retained revocation in the same source selection core
// used by management and the pure app planner. It contains no signed grants.
type Definition struct {
	Spec    Source
	Deleted bool
}

func Select(definitions []Definition, tenant string, image access.Image) (*Source, error) {
	e, err := Lookup(definitions, tenant, image)
	if err != nil || e == nil {
		return nil, err
	}
	if e.Deleted || !e.Spec.Enabled {
		return nil, ErrSource
	}
	spec := Own(e.Spec)
	return &spec, nil
}

// Lookup preserves the winning revoked definition for public classification.
// Select applies the deny policy; callers cannot treat a revoked match as an
// absent credential and silently choose anonymous access.
func Lookup(definitions []Definition, tenant string, image access.Image) (*Definition, error) {
	best, selected := 0, -1
	for i, e := range definitions {
		if e.Spec.Validate() != nil {
			return nil, ErrSource
		}
		if e.Spec.Tenant != tenant {
			continue
		}
		score, match := e.Spec.Match(image)
		if !match {
			continue
		}
		if score == best {
			return nil, ErrSource
		}
		if score > best {
			best, selected = score, i
		}
	}
	if selected < 0 {
		return nil, nil
	}
	e := definitions[selected]
	e.Spec = Own(e.Spec)
	return &e, nil
}

var ErrSource = errors.New("invalid external registry source")

func externalID(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func externalKey(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func (s Source) Key() string { return s.Tenant + "/" + s.ID }
func (s Source) Validate() error {
	if !externalID(s.Tenant) || !externalID(s.ID) {
		return ErrSource
	}
	repository := s.Repository
	if strings.HasSuffix(repository, "/**") {
		repository = strings.TrimSuffix(repository, "/**")
	}
	if _, err := access.CanonicalTrust([]access.TrustRule{{Registry: s.Authority, Repository: repository}}); err != nil {
		return ErrSource
	}
	validRealm := func(realm string) bool { return realm == "" || realm == s.Tenant }
	switch s.Auth {
	case "none":
		if s.Credential != nil {
			return ErrSource
		}
	case "password", "token":
		c := s.Credential
		if c == nil || !validRealm(c.Realm) || !externalID(c.ID) || !externalKey(c.UsernameKey) || !externalKey(c.PasswordKey) || c.UsernameKey == c.PasswordKey {
			return ErrSource
		}
	default:
		return ErrSource
	}
	if c := s.CA; c != nil && (!validRealm(c.Realm) || !externalID(c.ID) || !externalKey(c.Key)) {
		return ErrSource
	}
	return nil
}

// Match returns specificity; an exact repository beats a subtree and **. A
// disabled/deleted definition still participates so it cannot fall back to a
// broader credential or anonymous access. Authority aliases are not accepted.
func (s Source) Match(image access.Image) (int, bool) {
	if s.Validate() != nil || image.Registry != s.Authority {
		return 0, false
	}
	if s.Repository == image.Repository {
		return len(s.Repository)*2 + 2, true
	}
	if s.Repository == "**" {
		return 1, true
	}
	if strings.HasSuffix(s.Repository, "/**") {
		prefix := strings.TrimSuffix(s.Repository, "**")
		if strings.HasPrefix(image.Repository, prefix) {
			return len(prefix) * 2, true
		}
	}
	return 0, false
}

func Own(s Source) Source {
	if s.Credential != nil {
		c := *s.Credential
		s.Credential = &c
	}
	if s.CA != nil {
		c := *s.CA
		s.CA = &c
	}
	return s
}

func Equal(a, b Source) bool {
	if (a.Credential == nil) != (b.Credential == nil) || (a.CA == nil) != (b.CA == nil) {
		return false
	}
	if a.Credential != nil && *a.Credential != *b.Credential || a.CA != nil && *a.CA != *b.CA {
		return false
	}
	a.Credential, b.Credential, a.CA, b.CA = nil, nil, nil, nil
	return a == b
}
