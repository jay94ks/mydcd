// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

type NetworkChangeFence struct {
	Tenant, ID string
	Generation uint64
	Closed     tenancy.NetworkClosure
}

func (p Policy) fenceNetworkChange(s state.State, c access.Catalog, r Resources, op UserOperation) (tenancy.Networks, map[string][]byte, error) {
	var q NetworkChangeFence
	if canonical(op.Change.Payload, &q) != nil || q.Closed.Tenant != q.Tenant || q.Closed.Network != q.ID {
		return r.Networks, nil, access.ErrInvalid
	}
	// Use the same immutable committed address/reference projection as Task,
	// DNS and route consumers. A native owner's zero-count claim alone cannot
	// erase their still-held allocations or authorize a new owner/generation.
	projection, err := p.ProjectResources(s)
	if err != nil {
		return r.Networks, nil, err
	}
	authority, err := projection.addressAuthority(p.Cluster)
	if err != nil {
		return r.Networks, nil, err
	}
	_, next, err := authority.FenceNetworkChange(c, r.Networks, op.Change.Principal, q.Tenant, q.ID, q.Generation, op.Change.Expected, q.Closed)
	if err != nil {
		return r.Networks, nil, err
	}
	writes := map[string][]byte{}
	for key, source := range projection.ManagedSources {
		if source.Network.Tenant != q.Tenant || source.Network.ID != q.ID {
			continue
		}
		// A one-member target has no TUN, but its previous TUN's Closed
		// descriptor remains under this network ID for original settlement.
		// Authority already validated the closure against the current member;
		// historical generations are neither new fence targets nor deletions.
		if source.Network.Generation != q.Closed.Generation {
			continue
		}
		if source.Closed != nil || !s.Object(key).Present || source.Bridge != nil && !source.Bridge.Lifecycle.Drain || source.Tunnel != nil && !source.Tunnel.Lifecycle.Drain {
			return r.Networks, nil, ErrCatalog
		}
		// Actual native closure and the shared preflight precede withdrawal.
		// Recreating this same key later gets the FSM's ordinary new generation.
		writes[key] = nil
	}
	return next, writes, nil
}
