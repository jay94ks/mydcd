// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/registryclient"
)

type ImageUsageQuery struct {
	Refs           []string `json:",omitempty"`
	ExternalSource string   `json:",omitempty"`
}

func (q ImageUsageQuery) Canonical() (ImageUsageQuery, error) {
	if len(q.Refs) > 32 || q.ExternalSource != "" && !validID(q.ExternalSource) {
		return ImageUsageQuery{}, access.ErrInvalid
	}
	q.Refs = slices.Clone(q.Refs)
	for i, ref := range q.Refs {
		if imagecache.ValidID(ref) {
			continue
		}
		name, _, _, err := registryclient.Normalize(ref)
		if err != nil {
			return ImageUsageQuery{}, err
		}
		q.Refs[i] = name
	}
	slices.Sort(q.Refs)
	for i := 1; i < len(q.Refs); i++ {
		if q.Refs[i] == q.Refs[i-1] {
			return ImageUsageQuery{}, access.ErrInvalid
		}
	}
	return q, nil
}
func (q ImageUsageQuery) Valid() bool { _, err := q.Canonical(); return err == nil }

func (q ImageUsageQuery) Match(row ImageReference) string {
	if row.Unknown {
		return "unknown"
	}
	if len(q.Refs) == 0 {
		return "scope"
	}
	match := ""
	for _, ref := range q.Refs {
		candidate := row.MatchImage(ref)
		if candidate == "exact" || candidate == "digest" {
			return candidate
		}
		if candidate == "" && row.sameRepositoryTag(ref) {
			candidate = "repository-unknown"
		}
		if candidate != "" {
			match = candidate
		}
	}
	return match
}

// sameRepositoryTag reports a tag and a digest (or another tag) of the same
// repository: usage reads show it as "repository-unknown", but a tag holds no
// digest, so it never protects one from deletion.
func (row ImageReference) sameRepositoryTag(ref string) bool {
	if row.Unknown || imagecache.ValidID(ref) {
		return false
	}
	_, ar, ap, err := registryclient.Normalize(row.Image)
	if err != nil {
		return false
	}
	_, br, bp, err := registryclient.Normalize(ref)
	if err != nil || ar != br || ap != bp {
		return false
	}
	_, rowErr := access.PinImage(row.Image)
	_, refErr := access.PinImage(ref)
	return rowErr != nil || refErr != nil
}

// MatchImage is also the registry deletion predicate. A tag row matches only
// the same tag: a tag is never pinned to a digest (devel/design/image-tags.md),
// so the digests a deploy resolved are their own rows (ImageReferences), and
// containers already made keep their image on their server.
func (row ImageReference) MatchImage(ref string) string {
	if row.Unknown {
		return "unknown"
	}
	if imagecache.ValidID(ref) {
		image, err := access.PinImage(row.Image)
		if err == nil && image.Digest == ref {
			return "digest"
		}
		return ""
	}
	a, ar, ap, err := registryclient.Normalize(row.Image)
	if err != nil {
		return ""
	}
	b, br, bp, err := registryclient.Normalize(ref)
	if err != nil || ar != br || ap != bp {
		return ""
	}
	if a == b {
		return "exact"
	}
	aPin, aErr := access.PinImage(a)
	bPin, bErr := access.PinImage(b)
	if aErr == nil && bErr == nil {
		if aPin.Digest == bPin.Digest {
			return "digest"
		}
	}
	return ""
}

type ImageUsage struct {
	ImageReference
	Match string
}
type ImageUsagesPage struct {
	Schema uint8
	Tenant string
	Root   [32]byte
	Index  uint64
	Rows   []ImageUsage
	Next   string
}
type imageUsageCursor struct {
	Root  [32]byte
	After string
}

func ImageUsagesCursor(raw string) ([32]byte, string, error) {
	if raw == "" {
		return [32]byte{}, "", nil
	}
	if len(raw) > 512 {
		return [32]byte{}, "", access.ErrInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(raw)
	var cursor imageUsageCursor
	if err != nil || canonical(body, &cursor) != nil || cursor.Root == ([32]byte{}) || len(cursor.After) != 64 || !lowerHex(cursor.After) {
		return [32]byte{}, "", access.ErrInvalid
	}
	return cursor.Root, cursor.After, nil
}

func (p Policy) ImageUsages(s state.State, session access.Session, at int64, tenant string, q ImageUsageQuery, after string) (ImageUsagesPage, error) {
	q, err := q.Canonical()
	if err != nil {
		return ImageUsagesPage{}, err
	}
	p, err = p.Current(s)
	if err != nil {
		return ImageUsagesPage{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageUsagesPage{}, err
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return ImageUsagesPage{}, access.ErrDenied
	}
	if _, ok := c.Tenant(tenant); !ok || !validID(tenant) {
		return ImageUsagesPage{}, access.ErrDenied
	}
	var definitions []imagesource.Definition
	if q.ExternalSource != "" {
		definitions, err = p.externalRegistryDefinitions(s, tenant)
		if err != nil {
			return ImageUsagesPage{}, err
		}
		if !slices.ContainsFunc(definitions, func(v imagesource.Definition) bool { return v.Spec.ID == q.ExternalSource }) {
			return ImageUsagesPage{}, access.ErrDenied
		}
	}
	references, err := p.ImageReferences(s, tenant, "")
	if err != nil {
		return ImageUsagesPage{}, err
	}
	var rows []ImageUsage
	for _, ref := range references {
		if ref.Tenant != tenant {
			continue
		} // unmapped legacy rows never become public
		if q.ExternalSource != "" && !ref.Unknown {
			image, err := access.PinImage(ref.Image)
			if err != nil {
				_, authority, repo, cause := registryclient.Normalize(ref.Image)
				if cause != nil {
					continue
				}
				image = access.Image{Registry: authority, Repository: repo}
			}
			selected, err := imagesource.Lookup(definitions, tenant, image)
			if err != nil {
				return ImageUsagesPage{}, err
			}
			if selected == nil || selected.Spec.ID != q.ExternalSource {
				continue
			}
		}
		match := q.Match(ref)
		if match == "" {
			continue
		}
		rows = append(rows, ImageUsage{ImageReference: ref, Match: match})
	}
	return pageImageUsages(p.Cluster, s.Index(), session, tenant, q, after, rows)
}

func pageImageUsages(cluster [32]byte, index uint64, session access.Session, tenant string, q ImageUsageQuery, after string, rows []ImageUsage) (ImageUsagesPage, error) {
	for i, row := range rows {
		if row.Tenant != tenant || !row.ImageReference.Valid() || row.Match != q.Match(row.ImageReference) || row.Match == "" || i > 0 && rows[i-1].ID >= row.ID {
			return ImageUsagesPage{}, access.ErrDenied
		}
	}
	// Only authorized matched rows enter the digest. An unrelated tenant/node
	// update cannot leak through or invalidate this user's page cursor.
	hash := sha256.New()
	_, _ = hash.Write([]byte("sfc-image-usages-view-1\x00"))
	encoder := json.NewEncoder(hash)
	_ = encoder.Encode(struct {
		Cluster      [32]byte
		Tenant, User string
		Scopes       []access.Scope
		Query        ImageUsageQuery
	}{cluster, tenant, session.User, session.Scopes, q})
	for _, row := range rows {
		_ = encoder.Encode(row)
	}
	var root [32]byte
	copy(root[:], hash.Sum(nil))
	previous, last, err := ImageUsagesCursor(after)
	if err != nil {
		return ImageUsagesPage{}, err
	}
	if after != "" && (previous != root || !slices.ContainsFunc(rows, func(r ImageUsage) bool { return r.ID == last })) {
		return ImageUsagesPage{}, access.ErrConflict
	}
	page := ImageUsagesPage{Schema: 1, Tenant: tenant, Root: root, Index: index}
	for _, row := range rows {
		if row.ID <= last {
			continue
		}
		if len(page.Rows) == 16 {
			body, _ := json.Marshal(imageUsageCursor{Root: root, After: page.Rows[len(page.Rows)-1].ID})
			page.Next = base64.RawURLEncoding.EncodeToString(body)
			break
		}
		page.Rows = append(page.Rows, row)
	}
	return page, nil
}
