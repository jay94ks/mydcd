// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

type ImageResolveQuery struct{ Ref string }

func (q ImageResolveQuery) Valid() bool { return len(q.Ref) > 0 && len(q.Ref) <= 1024 }

type ImageTrustCheck struct {
	Trusted bool
	Rules   []access.TrustRule
}

// ImageResolveTarget fixes only authority and current public policy. Actual
// bytes stay with the managed Store or the approved external source reader.
type ImageResolveTarget struct {
	Normalized, Kind, Source, Code string
	Owner                          [32]byte
	Trust                          ImageTrustCheck
	Managed                        *RegistryRunRef                `json:",omitempty"`
	External                       *ExternalRegistryReadSelection `json:",omitempty"`
	ExternalReadSet                [32]byte                       `json:",omitempty"`
}

func (t ImageResolveTarget) Same(other ImageResolveTarget) bool {
	a, _ := json.Marshal(t)
	b, _ := json.Marshal(other)
	return string(a) == string(b)
}

type ImageResolveRead struct {
	Session  access.Session
	Tenant   string
	Query    ImageResolveQuery
	Resolver [32]byte
	Target   ImageResolveTarget
}
type ImageResolveResult struct {
	Normalized, Kind, Source, Code string
	Trust                          ImageTrustCheck
	Image                          *registryclient.Resolution `json:",omitempty"`
}

func (t ImageResolveTarget) Result(code string, image *registryclient.Resolution) ImageResolveResult {
	return ImageResolveResult{Normalized: t.Normalized, Kind: t.Kind, Source: t.Source, Code: code, Trust: t.Trust, Image: image}
}
func (r ImageResolveResult) Valid(read ImageResolveRead) bool {
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded) > 224<<10 {
		return false
	}
	t := read.Target
	if r.Normalized != t.Normalized || r.Kind != t.Kind || r.Source != t.Source || r.Trust.Trusted != t.Trust.Trusted || !slices.Equal(r.Trust.Rules, t.Trust.Rules) {
		return false
	}
	if t.Code != "" {
		return r.Code == t.Code && r.Image == nil
	}
	if r.Code == "OK" {
		return r.Image != nil && r.Image.Valid(t.Normalized)
	}
	switch r.Code {
	case "CANCELLED", "TIMEOUT", "UNAUTHORIZED", "DENIED", "NOT_FOUND", "UNSUPPORTED", "UNAVAILABLE", "CLOSED", "INVALID_IMAGE", "IMAGE_BUDGET", "METADATA_BUDGET", "INVALID_CA", "INVALID_CREDENTIAL", "INVALID_SOURCE", "AUTHORITY_MISMATCH":
		return r.Image == nil
	}
	return false
}

func (r ImageResolveResult) ValidQuery(q ImageResolveQuery) bool {
	if !q.Valid() {
		return false
	}
	normalized, authority, repository, err := registryclient.Normalize(q.Ref)
	if err != nil {
		return r.Normalized == "" && r.Kind == "unknown" && r.Source == "" && r.Code == "INVALID_IMAGE" && !r.Trust.Trusted && len(r.Trust.Rules) == 0 && r.Image == nil
	}
	if r.Normalized != normalized {
		return false
	}
	switch r.Kind {
	case "unknown":
		if r.Source != "" {
			return false
		}
	case "managed", "external":
		if !validID(r.Source) {
			return false
		}
	default:
		return false
	}
	rules, err := access.CanonicalTrust(r.Trust.Rules)
	if err != nil || !slices.Equal(rules, r.Trust.Rules) {
		return false
	}
	_, trusted := access.MatchImageTrust(rules, authority, repository)
	if r.Trust.Trusted != trusted || !trusted && r.Code != "UNTRUSTED" || trusted && r.Code == "UNTRUSTED" {
		return false
	}
	t := ImageResolveTarget{Normalized: r.Normalized, Kind: r.Kind, Source: r.Source, Trust: r.Trust}
	if r.Code == "UNTRUSTED" {
		t.Code = r.Code
	}
	if r.Code == "SOURCE_REVOKED" || r.Code == "SOURCE_NOT_READY" {
		if r.Kind != "external" {
			return false
		}
		t.Code = r.Code
	}
	return r.Valid(ImageResolveRead{Query: q, Target: t})
}

func (p Policy) PlanImageResolve(s state.State, session access.Session, at int64, tenant string, q ImageResolveQuery, resolver [32]byte) (ImageResolveRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageResolveRead{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageResolveRead{}, err
	}
	if !q.Valid() || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return ImageResolveRead{}, access.ErrDenied
	}
	target, err := p.imageResolveTarget(s, c, at, tenant, q.Ref, resolver)
	if err != nil {
		return ImageResolveRead{}, err
	}
	return ImageResolveRead{Session: session, Tenant: tenant, Query: q, Resolver: resolver, Target: target}, nil
}

// User reads and accepted build jobs share selection, revocation, trust and
// source-reader ownership. Their authentication remains at their callers.
func (p Policy) imageResolveTarget(s state.State, c access.Catalog, at int64, tenant, ref string, resolver [32]byte) (ImageResolveTarget, error) {
	target := ImageResolveTarget{Kind: "unknown"}
	normalized, authority, repo, err := registryclient.Normalize(ref)
	if err != nil {
		target.Code = "INVALID_IMAGE"
		return target, nil
	}
	target.Normalized = normalized
	tenantRecord, ok := c.Tenant(tenant)
	if !ok {
		return ImageResolveTarget{}, access.ErrDenied
	}
	target.Trust = ImageTrustCheck{Trusted: c.CheckImageRepositoryTrust(tenant, authority, repo) == nil, Rules: slices.Clone(tenantRecord.ImageSources)}
	managed, err := p.Registries(s)
	if err != nil {
		return ImageResolveTarget{}, err
	}
	for _, entry := range managed.Entries() {
		if entry.Spec.Authority != authority && (entry.Active == nil || entry.Active.Spec.Authority != authority) {
			continue
		}
		if entry.Spec.Tenant != tenant {
			return ImageResolveTarget{}, access.ErrDenied
		}
		target.Kind, target.Source = "managed", entry.Spec.ID
		if entry.Deleted || !entry.Spec.Enabled || entry.Active == nil || entry.Active.Draining || entry.Active.Ready == nil || entry.Spec != entry.Active.Spec {
			target.Code = "UNAVAILABLE"
		} else {
			run := entry.Active.Reference()
			run.Ready = nil
			target.Managed = &run
			target.Owner = run.Owner
		}
		break
	}
	if target.Kind != "managed" {
		definitions, err := p.externalRegistryDefinitions(s, tenant)
		if err != nil {
			return ImageResolveTarget{}, err
		}
		definition, err := imagesource.Lookup(definitions, tenant, access.Image{Registry: authority, Repository: repo})
		if err != nil {
			return ImageResolveTarget{}, err
		}
		if definition != nil {
			target.Kind, target.Source = "external", definition.Spec.ID
			if definition.Deleted || !definition.Spec.Enabled {
				target.Code = "SOURCE_REVOKED"
			} else {
				entries, err := p.ExternalRegistries(s)
				if err != nil {
					return ImageResolveTarget{}, err
				}
				for _, entry := range entries {
					if entry.Spec.Key() != definition.Spec.Key() {
						continue
					}
					if entry.Reader == nil || entry.Reader.Draining {
						target.Code = "SOURCE_NOT_READY"
					} else {
						selection := ExternalRegistryReadSelection{Tenant: tenant, ID: entry.Spec.ID, Generation: entry.Reader.Generation}
						target.External = &selection
						target.Owner = entry.Reader.Owner
						work, cause := p.ExternalRegistryWork(s, entry.Reader.Owner, ExternalRegistryWorkRequest{Selection: selection, At: at})
						if cause != nil {
							target.Code = "DENIED"
						} else {
							target.ExternalReadSet = work.Inputs.ReadSet
						}
					}
				}
			}
		} else {
			target.Owner = resolver
		}
	}
	// Untrusted user-supplied hosts never cause network I/O. This is the same
	// repository test actual deployment uses before it resolves/pulls an image.
	if !target.Trust.Trusted {
		target.Code = "UNTRUSTED"
	}
	if target.Code == "" {
		members, err := p.Members(s)
		if err != nil {
			return ImageResolveTarget{}, err
		}
		if !members.WorkKey(target.Owner) {
			target.Code = "UNAVAILABLE"
		}
	}
	return target, nil
}

func (p Policy) CurrentImageResolve(s state.State, read ImageResolveRead, at int64) (ImageResolveRead, error) {
	current, err := p.PlanImageResolve(s, read.Session, at, read.Tenant, read.Query, read.Resolver)
	if err != nil || !current.Target.Same(read.Target) {
		return ImageResolveRead{}, access.ErrDenied
	}
	return current, nil
}
