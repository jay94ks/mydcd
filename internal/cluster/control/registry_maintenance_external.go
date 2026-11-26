// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagesource"
)

// Public references only; source credentials/CA remain at the approved reader.
type ExternalRegistryMaintenanceTarget struct {
	Selection ExternalRegistryReadSelection
	Spec      imagesource.Source
	Node      string
	Owner     [32]byte
	Revision  uint64
	ReadSet   [32]byte
}

func (t ExternalRegistryMaintenanceTarget) Valid(tenant string) bool {
	return validID(tenant) && t.Selection.Tenant == tenant && t.Spec.Tenant == tenant && t.Spec.Validate() == nil && t.Spec.Enabled && t.Selection.ID == t.Spec.ID && t.Selection.Generation > 0 && t.Revision >= t.Selection.Generation && validID(t.Node) && t.Owner != ([32]byte{}) && t.ReadSet != ([32]byte{})
}
func (q RegistryMaintenanceChange) RegistryID() string {
	if q.External != nil {
		return q.External.Selection.ID
	}
	return q.Run.Spec.ID
}
func (q RegistryMaintenanceChange) Authority() string {
	if q.External != nil {
		return q.External.Spec.Authority
	}
	return q.Run.Spec.Authority
}
func (q RegistryMaintenanceChange) OwnerKey() [32]byte {
	if q.External != nil {
		return q.External.Owner
	}
	return q.Run.Owner
}
func (q RegistryMaintenanceChange) NodeID() string {
	if q.External != nil {
		return q.External.Node
	}
	return q.Run.Spec.Node
}
func (q RegistryMaintenanceChange) ExpectedRevision() uint64 {
	if q.External != nil {
		return q.External.Revision
	}
	return q.Run.SpecRevision
}
func (q RegistryMaintenanceChange) pendingKey() string {
	kind := "managed/"
	if q.External != nil {
		kind = "external/"
	}
	return kind + q.Tenant + "/" + q.RegistryID()
}

func (p Policy) externalMaintenanceTarget(s state.State, tenant, id, repo string, at int64) (ExternalRegistryMaintenanceTarget, error) {
	entries, err := p.ExternalRegistries(s)
	if err != nil {
		return ExternalRegistryMaintenanceTarget{}, err
	}
	for _, entry := range entries {
		if entry.Spec.Tenant != tenant || entry.Spec.ID != id {
			continue
		}
		if entry.Deleted || !entry.Spec.Enabled || entry.Reader == nil || entry.Reader.Draining {
			return ExternalRegistryMaintenanceTarget{}, access.ErrDenied
		}
		var selected *imagesource.Source
		var err error
		if repo != "" {
			selected, err = p.ExternalRegistryForImage(s, tenant, access.Image{Registry: entry.Spec.Authority, Repository: repo})
		}
		if repo != "" && (err != nil || selected == nil || selected.ID != id) {
			return ExternalRegistryMaintenanceTarget{}, access.ErrDenied
		}
		selection := ExternalRegistryReadSelection{Tenant: tenant, ID: id, Generation: entry.Reader.Generation}
		work, err := p.ExternalRegistryWork(s, entry.Reader.Owner, ExternalRegistryWorkRequest{Selection: selection, At: at})
		if err != nil {
			return ExternalRegistryMaintenanceTarget{}, err
		}
		return ExternalRegistryMaintenanceTarget{Selection: selection, Spec: imagesource.Own(entry.Spec), Node: work.Reader.Node, Owner: entry.Reader.Owner, Revision: entry.Revision, ReadSet: work.Inputs.ReadSet}, nil
	}
	return ExternalRegistryMaintenanceTarget{}, access.ErrDenied
}
func (p Policy) currentExternalMaintenance(s state.State, q RegistryMaintenanceChange, at int64) error {
	current, err := p.externalMaintenanceTarget(s, q.Tenant, q.RegistryID(), q.Repository, at)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(q.External)
	if string(a) != string(b) {
		return access.ErrDenied
	}
	return nil
}
func (p Policy) ExternalRegistryMaintenancePending(s state.State, tenant, id string) (bool, error) {
	return p.registryMaintenancePending(s, tenant, id, true)
}
