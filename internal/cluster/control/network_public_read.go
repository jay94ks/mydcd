// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/tenancy"
	"strings"
)

// NetworkReadTarget is an internal, exact owner/source request. It is not a
// public API grant and cannot authorize Step, native adoption or recreation.
type NetworkReadTarget struct {
	Network tenancy.Network
	Source  deployment.ObjectRef
}
type NetworkClosureStatus struct {
	State                                       string
	NativeGone                                  *bool                   `json:",omitempty"`
	PendingEndpoints, PendingFlows, PendingPins *uint64                 `json:",omitempty"`
	Closure                                     *tenancy.NetworkClosure `json:",omitempty"`
}

func (p Policy) NetworkClosureRead(s state.State, session access.Session, at int64, tenant, name string) (NetworkReadTarget, error) {
	p, err := p.Current(s)
	if err != nil {
		return NetworkReadTarget{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return NetworkReadTarget{}, err
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return NetworkReadTarget{}, err
	}
	n, ok := projection.Resources.Networks.Network(tenant, name)
	if !ok || !n.Draining || n.Logical == "" || c.AuthorizeSessionCleanup(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageNetwork) != nil {
		return NetworkReadTarget{}, access.ErrDenied
	}
	for key, source := range projection.ManagedSources {
		if source.Bridge != nil && source.Network.Tenant == n.Tenant && source.Network.ID == n.ID && source.Network.Generation == n.Generation && source.Network.Revision == n.Revision && source.Network.Owner == n.Owner {
			o := s.Object(key)
			return NetworkReadTarget{Network: n, Source: deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}}, nil
		}
	}
	return NetworkReadTarget{}, ErrCatalog
}
func (t NetworkReadTarget) VerifyClosure(cluster [32]byte, p tenancy.NetworkClosure) bool {
	n := t.Network
	return p.Cluster == cluster && p.Tenant == n.Tenant && p.Network == n.ID && p.Node == n.Node && p.Owner == n.Owner && p.Generation == n.Generation && p.Revision == n.Revision && p.NativeGone && p.PendingEndpoints == 0 && p.PendingFlows == 0 && p.PendingPins == 0 && ed25519.Verify(ed25519.PublicKey(p.Owner[:]), tenancy.NetworkClosureBytes(p), p.Signature)
}

// PendingNetworkEndpoints counts the exact unreleased allocation book consulted
// by networkQuiescent, not a guessed Docker endpoint census.
func PendingNetworkEndpoints(p ResourceProjection, n tenancy.Network) uint64 {
	var count uint64
	for _, allocation := range p.Addresses.Checkpoint().Allocations {
		if strings.HasPrefix(allocation.Pool, n.Tenant+"/"+n.ID+"/") {
			count++
		}
	}
	return count
}
