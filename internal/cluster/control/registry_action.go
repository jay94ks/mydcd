// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registry"
)

type RegistryActionQuery struct{ Action, ID string }

func (q RegistryActionQuery) Valid() bool {
	return (q.Action == "start-registry" || q.Action == "stop-registry") && lifecycle.ValidID(q.ID)
}

type RegistryActionPlan struct {
	Schema                        uint8
	Cluster                       [32]byte
	Action, Tenant, ID            string
	Expected, RootRevision, Epoch uint64
	Current                       RegistryView
	WouldEnable, DataPreserved    bool
}

func registryPublicView(entry RegistryEntry) RegistryView {
	v := RegistryView{Spec: entry.Spec, Revision: entry.Revision, Generation: entry.Generation, Deleted: entry.Deleted}
	if entry.Active != nil {
		v.Active, v.Draining = true, entry.Active.Draining
		if entry.Active.Spec == entry.Spec && entry.Active.SpecRevision == entry.Revision && !v.Draining {
			v.Observation = entry.Active.Ready
		}
	}
	return v
}

func (p Policy) registryEnabledAllowed(s state.State, users access.Catalog, session access.Session, at int64, spec registry.Specification) error {
	if _, err := p.nodeOwner(s, spec.Node); err != nil {
		return access.ErrDenied
	}
	for _, action := range []access.Action{access.ManageRegistry, access.ManageVolumes} {
		if err := users.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, spec.Tenant, action, spec.Node); err != nil {
			return err
		}
	}
	return nil
}

// This is an authenticated read, never an executable unsigned/synthetic
// UserOperation. It shares the actual reducer's permission/native prerequisites.
func (p Policy) PlanRegistryAction(s state.State, session access.Session, at int64, tenant string, q RegistryActionQuery) (RegistryActionPlan, error) {
	var out RegistryActionPlan
	p, err := p.Current(s)
	if err != nil || tenant == "" || !q.Valid() {
		return out, access.ErrDenied
	}
	users, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	payload, _ := json.Marshal(RegistrySelection{Tenant: tenant, ID: q.ID})
	change := Change{Action: q.Action, Payload: payload}
	if err := p.authorizeRegistryChange(users, session, at, change); err != nil {
		return out, err
	}
	book, err := p.Registries(s)
	if err != nil {
		return out, err
	}
	entry, exists := book.Entry(tenant, q.ID)
	if !exists || entry.Deleted || entry.Revision == ^uint64(0) {
		return out, access.ErrConflict
	}
	volumeBook, err := p.Volumes(s)
	if err != nil {
		return out, err
	}
	if _, err := p.registryVolume(volumeBook, entry.Spec); err != nil {
		return out, access.ErrConflict
	}
	if q.Action == "start-registry" {
		if err := p.registryEnabledAllowed(s, users, session, at, entry.Spec); err != nil {
			return out, err
		}
	}
	return RegistryActionPlan{Schema: 1, Cluster: p.Cluster, Action: q.Action, Tenant: tenant, ID: q.ID, Expected: entry.Revision, RootRevision: s.Object(RegistriesKey).Revision, Epoch: s.ModuleEpoch(), Current: registryPublicView(entry), WouldEnable: q.Action == "start-registry", DataPreserved: true}, nil
}
