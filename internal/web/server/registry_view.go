// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/hex"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registry"
)

// registryView: one `registries` row (control.RegistryView) in screen form.
// Revision is the record revision: the Expected of put (0 for a new ID),
// start, stop and delete. Endpoint is Spec.Authority, Name the ID;
// Repositories is kept for the screen and sfcd does not count it (0).
type registryView struct {
	Tenant, ID, Name, Endpoint string
	Revision, Generation       uint64
	Active                     bool
	Repositories               int

	Node, Address              string `json:",omitempty"`
	Volume                     string `json:",omitempty"` // Spec.Volume.ID
	Enabled, Deleted, Draining bool   `json:",omitempty"`
	// CertificateID: hex ID of the store certificate the node reported it
	// serves for Endpoint's host (control.RegistryObservation.Certificate).
	CertificateID string `json:",omitempty"`
	// ObservedAt: the node's report that the current spec serves
	// (control.RegistryObservation.At, Unix ms); 0 = no observation.
	ObservedAt int64 `json:",omitempty"`
	// Maintenance: REQ-18 list summary (pending job, last GC).
	Maintenance *control.RegistryMaintenanceSummary `json:",omitempty"`
	// Spec is the stored definition; put-registry carries a changed copy.
	Spec registry.Specification `json:"-"`
}

func registryViewOf(r control.RegistryView) registryView {
	s := r.Spec
	v := registryView{Tenant: s.Tenant, ID: s.ID, Name: s.ID, Endpoint: s.Authority, Revision: r.Revision, Generation: r.Generation,
		Active: r.Active, Node: s.Node, Address: s.Address, Volume: s.Volume.ID, Enabled: s.Enabled,
		Deleted: r.Deleted, Draining: r.Draining, Maintenance: r.Maintenance, Spec: s}
	if r.Observation != nil {
		v.ObservedAt = r.Observation.At
		if r.Observation.Certificate != ([32]byte{}) {
			v.CertificateID = hex.EncodeToString(r.Observation.Certificate[:])
		}
	}
	return v
}

// status is the CLI's `sfcli registry show` status: deleted / stopping /
// stopped / draining / serving (the node reported the current spec;
// not an external TLS probe) / pending (enabled, no report yet).
func (v registryView) status() string {
	switch {
	case v.Deleted:
		return "deleted"
	case !v.Enabled && v.Active:
		return "stopping"
	case !v.Enabled:
		return "stopped"
	case v.Draining:
		return "draining"
	case v.ObservedAt != 0:
		return "serving"
	}
	return "pending"
}
