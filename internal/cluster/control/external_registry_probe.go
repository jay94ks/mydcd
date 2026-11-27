// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registryclient"
)

type ExternalRegistryProbeQuery struct{ ID, Image string }

func (q ExternalRegistryProbeQuery) Valid() bool {
	if !validID(q.ID) {
		return false
	}
	if q.Image == "" {
		return true
	}
	_, _, _, err := registryclient.Normalize(q.Image)
	return err == nil
}

type ExternalRegistryProbeRead struct {
	Session   access.Session
	Selection ExternalRegistryReadSelection
	Image     string
}

// Only bounded public observations cross the user API. Credentials and source
// grants remain inside the owner/provider path.
type ExternalRegistryProbeResult struct {
	Selection ExternalRegistryReadSelection
	Owner     [32]byte
	At        int64
	Code      string
	Image     *registryclient.Resolution `json:",omitempty"`
	Pull      *registryclient.PullCheck  `json:",omitempty"`
}

func (r ExternalRegistryProbeResult) Valid(read ExternalRegistryProbeRead) bool {
	if r.Selection != read.Selection || r.Owner == ([32]byte{}) || r.At <= 0 {
		return false
	}
	switch r.Code {
	case "OK":
		if read.Image == "" {
			return r.Image == nil && r.Pull == nil
		}
		return r.Image != nil && r.Image.Valid(read.Image) && r.Pull != nil && r.Pull.Valid(*r.Image)
	}
	// Every registry client failure code is a probe result, so the caller
	// learns why (AUTH_SCOPE, PLAIN_HTTP, ...) instead of a bare failure.
	return registryclient.ValidResultCode(r.Code) && r.Image == nil && r.Pull == nil
}
func (p Policy) PlanExternalRegistryProbe(s state.State, session access.Session, at int64, tenant string, q ExternalRegistryProbeQuery) (ExternalRegistryProbeRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return ExternalRegistryProbeRead{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ExternalRegistryProbeRead{}, err
	}
	if !q.Valid() || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return ExternalRegistryProbeRead{}, access.ErrDenied
	}
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return ExternalRegistryProbeRead{}, err
	}
	for _, entry := range entries {
		if entry.Spec.Tenant != tenant || entry.Spec.ID != q.ID {
			continue
		}
		if entry.Deleted || !entry.Spec.Enabled || entry.Reader == nil || entry.Reader.Draining {
			return ExternalRegistryProbeRead{}, access.ErrConflict
		}
		image := ""
		if q.Image != "" {
			normalized, authority, repository, err := registryclient.Normalize(q.Image)
			if err != nil {
				return ExternalRegistryProbeRead{}, err
			}
			if _, ok := entry.Spec.Match(access.Image{Registry: authority, Repository: repository}); !ok {
				return ExternalRegistryProbeRead{}, access.ErrDenied
			}
			image = normalized
		}
		return ExternalRegistryProbeRead{Session: session, Selection: ExternalRegistryReadSelection{tenant, q.ID, entry.Reader.Generation}, Image: image}, nil
	}
	return ExternalRegistryProbeRead{}, access.ErrDenied
}
func (p Policy) ExternalRegistryProbeOwner(s state.State, read ExternalRegistryProbeRead, at int64) ([32]byte, error) {
	current, err := p.PlanExternalRegistryProbe(s, read.Session, at, read.Selection.Tenant, ExternalRegistryProbeQuery{ID: read.Selection.ID, Image: read.Image})
	if err != nil || current.Selection != read.Selection || current.Image != read.Image {
		return [32]byte{}, access.ErrDenied
	}
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return [32]byte{}, err
	}
	for _, entry := range entries {
		if entry.Spec.Tenant == read.Selection.Tenant && entry.Spec.ID == read.Selection.ID && entry.Reader != nil {
			return entry.Reader.Owner, nil
		}
	}
	return [32]byte{}, access.ErrDenied
}
