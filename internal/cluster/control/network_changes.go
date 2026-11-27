// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// NetworkChangePlan reserves a complete candidate in the existing network
// catalog. Change is the stable workflow ID, distinct from the outer signed
// user operation's RequestID. Expected selects the original network revision.
type NetworkChangePlan struct {
	Tenant, ID, Change string
	Target             tenancy.Network
}

// NetworkChangeCancel selects the original reserved generation/revision.
// Metadata-only reservations require no native claim. Older native-candidate
// records still require their owner's exact positive closure in Candidate.
type NetworkChangeCancel struct {
	Tenant, ID string
	Generation uint64
	Candidate  tenancy.ChangeCandidateClose
}

func (p Policy) planNetworkChange(s state.State, c access.Catalog, r Resources, op UserOperation) (tenancy.Networks, error) {
	var q NetworkChangePlan
	if canonical(op.Change.Payload, &q) != nil || q.Target.Tenant != q.Tenant || q.Target.ID != q.ID {
		return r.Networks, access.ErrInvalid
	}
	original, ok := r.Networks.Network(q.Tenant, q.ID)
	if !ok {
		return r.Networks, access.ErrConflict
	}
	// Check both currently allowed nodes, as well as the signed tenant/action
	// scope. A target-node grant must not authorize taking over a revoked source.
	for _, node := range []string{original.Node, q.Target.Node} {
		if err := c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageNetwork, node); err != nil {
			return r.Networks, err
		}
	}
	originOwner, err := p.nodeOwner(s, original.Node)
	if err != nil || !p.ownsResource(s, originOwner, original.Owner) {
		return r.Networks, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, q.Target.Node)
	if err != nil || q.Target.Owner != ([32]byte{}) && q.Target.Owner != owner {
		return r.Networks, access.ErrDenied
	}
	q.Target.Owner = owner
	// Group add/remove/rebind needs all peer sources to close/rebuild. An
	// individual candidate cannot silently rename or dissolve that group.
	if q.Target.Logical != original.Logical {
		return r.Networks, access.ErrInvalid
	}
	next, err := r.Networks.PlanMetadataChange(c, op.Change.Principal, q.Tenant, q.ID, q.Change, op.Change.Expected, q.Target)
	if err != nil {
		return r.Networks, err
	}
	if err = r.Quotas.ValidateNetworks(next); err != nil {
		return r.Networks, err
	}
	return next, nil
}
