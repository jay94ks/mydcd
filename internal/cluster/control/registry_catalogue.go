// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

type RegistryCatalogueQuery struct{ Kind, ID, Repository string }

func (q RegistryCatalogueQuery) Valid() bool {
	if (q.Kind != "managed" && q.Kind != "external") || !validID(q.ID) || len(q.Repository) > 255 {
		return false
	}
	if q.Repository == "" {
		return true
	}
	return registryclient.ValidRepository(q.Repository)
}

type RegistryCatalogueTarget struct {
	Kind, ID, Authority  string
	Owner                [32]byte
	Managed              *RegistryRunRef                `json:",omitempty"`
	External             *ExternalRegistryReadSelection `json:",omitempty"`
	ReadSet, Definitions [32]byte
}

func (t RegistryCatalogueTarget) Same(other RegistryCatalogueTarget) bool {
	a, _ := json.Marshal(t)
	b, _ := json.Marshal(other)
	return string(a) == string(b)
}

type RegistryCatalogueRead struct {
	Session access.Session
	Tenant  string
	Query   RegistryCatalogueQuery
	After   string
	Target  RegistryCatalogueTarget
}

func (r RegistryCatalogueRead) Basis() [32]byte {
	raw, _ := json.Marshal(struct {
		Tenant, User string
		Revision     uint64
		Scopes       []access.Scope
		Query        RegistryCatalogueQuery
		Target       RegistryCatalogueTarget
	}{r.Tenant, r.Session.User, r.Session.AccountRevision, r.Session.Scopes, r.Query, r.Target})
	return sha256.Sum256(append([]byte("mydc-registry-catalogue-permission-1\x00"), raw...))
}
func (p Policy) PlanRegistryCatalogue(s state.State, session access.Session, at int64, tenant string, q RegistryCatalogueQuery, after string) (RegistryCatalogueRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return RegistryCatalogueRead{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return RegistryCatalogueRead{}, err
	}
	if _, _, err := registryclient.CatalogueCursor(after); err != nil {
		return RegistryCatalogueRead{}, access.ErrInvalid
	}
	if _, ok := c.Tenant(tenant); !ok || !q.Valid() || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return RegistryCatalogueRead{}, access.ErrDenied
	}
	read := RegistryCatalogueRead{Session: session, Tenant: tenant, Query: q, After: after, Target: RegistryCatalogueTarget{Kind: q.Kind, ID: q.ID}}
	target := &read.Target
	if q.Kind == "managed" {
		book, err := p.Registries(s)
		if err != nil {
			return RegistryCatalogueRead{}, err
		}
		for _, entry := range book.Entries() {
			if entry.Spec.Tenant != tenant || entry.Spec.ID != q.ID {
				continue
			}
			if entry.Deleted || !entry.Spec.Enabled || entry.Active == nil || entry.Active.Draining || entry.Active.Ready == nil || entry.Spec != entry.Active.Spec {
				return RegistryCatalogueRead{}, access.ErrConflict
			}
			run := entry.Active.Reference()
			// Readiness must still exist above and the owner must have the real
			// live Store, but periodic observations are not a content generation.
			run.Ready = nil
			target.Authority = run.Spec.Authority
			target.Owner = run.Owner
			target.Managed = &run
		}
	} else {
		entries, err := p.ExternalRegistries(s)
		if err != nil {
			return RegistryCatalogueRead{}, err
		}
		for _, entry := range entries {
			if entry.Spec.Tenant != tenant || entry.Spec.ID != q.ID {
				continue
			}
			if entry.Deleted || !entry.Spec.Enabled || entry.Reader == nil || entry.Reader.Draining {
				return RegistryCatalogueRead{}, access.ErrConflict
			}
			selection := ExternalRegistryReadSelection{Tenant: tenant, ID: q.ID, Generation: entry.Reader.Generation}
			work, err := p.ExternalRegistryWork(s, entry.Reader.Owner, ExternalRegistryWorkRequest{Selection: selection, At: at})
			if err != nil {
				return RegistryCatalogueRead{}, access.ErrDenied
			}
			target.Authority = entry.Spec.Authority
			target.Owner = entry.Reader.Owner
			target.External = &selection
			target.ReadSet = work.Inputs.ReadSet
			// A newly narrower source must invalidate an earlier catalogue, even when
			// this broad reader's own generation and secret references did not change.
			definitions, err := p.externalRegistryDefinitions(s, tenant)
			if err != nil {
				return RegistryCatalogueRead{}, err
			}
			sameAuthority := []imagesource.Definition{}
			for _, definition := range definitions {
				if definition.Spec.Authority == target.Authority {
					sameAuthority = append(sameAuthority, definition)
				}
			}
			slices.SortFunc(sameAuthority, func(a, b imagesource.Definition) int {
				if a.Spec.ID < b.Spec.ID {
					return -1
				}
				if a.Spec.ID > b.Spec.ID {
					return 1
				}
				return 0
			})
			raw, _ := json.Marshal(sameAuthority)
			target.Definitions = sha256.Sum256(raw)
		}
	}
	if target.Owner == ([32]byte{}) || target.Authority == "" {
		return RegistryCatalogueRead{}, access.ErrDenied
	}
	members, err := p.Members(s)
	if err != nil {
		return RegistryCatalogueRead{}, err
	}
	if !members.WorkKey(target.Owner) {
		return RegistryCatalogueRead{}, access.ErrDenied
	}
	if q.Repository != "" && !p.RegistryCatalogueRepositoryAllowed(s, read, q.Repository) {
		return RegistryCatalogueRead{}, access.ErrDenied
	}
	return read, nil
}
func (p Policy) CurrentRegistryCatalogue(s state.State, read RegistryCatalogueRead, at int64) (RegistryCatalogueRead, error) {
	current, err := p.PlanRegistryCatalogue(s, read.Session, at, read.Tenant, read.Query, read.After)
	if err != nil || !current.Target.Same(read.Target) {
		return RegistryCatalogueRead{}, access.ErrDenied
	}
	return current, nil
}
func (p Policy) RegistryCatalogueRepositoryAllowed(s state.State, read RegistryCatalogueRead, repo string) bool {
	q := read.Query
	q.Repository = repo
	if !q.Valid() || repo == "" {
		return false
	}
	if read.Target.Managed != nil {
		return true
	}
	selected, err := p.ExternalRegistryForImage(s, read.Tenant, access.Image{Registry: read.Target.Authority, Repository: repo})
	return err == nil && selected != nil && selected.ID == read.Query.ID && selected.Authority == read.Target.Authority
}

type RegistryCatalogueResult struct {
	Kind, ID string
	Page     registryclient.CataloguePage
}

func (r RegistryCatalogueResult) ValidQuery(q RegistryCatalogueQuery, after string) bool {
	return q.Valid() && r.Kind == q.Kind && r.ID == q.ID && r.Page.Valid(r.Page.Authority, q.Repository, after) &&
		(r.Page.Code != "OK" || r.Page.Live == (q.Kind == "external") && r.Page.UntaggedComplete == (q.Kind == "managed"))
}
func (r RegistryCatalogueResult) Valid(read RegistryCatalogueRead) bool {
	return r.ValidQuery(read.Query, read.After) && r.Page.Authority == read.Target.Authority
}
