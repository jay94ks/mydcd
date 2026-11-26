// SPDX-License-Identifier: Apache-2.0

package secrets

import "slices"

// PublicApproval projects the same records that Revoke/retire inspect. It
// contains no signature, password verifier, provider reference or key material.
type PublicApproval struct {
	ID, Realm, Tenant, Group, User, App, Standalone, Deployment, Purpose string
	Services, Nodes                                                      []string
	ApprovedAt, ExpiresAt                                                int64
	Issuer                                                               [32]byte
	Revoking                                                             bool
	Consumers                                                            int
}

func (a Approvals) PublicApprovals(tree Tree, app string) []PublicApproval {
	rows := []PublicApproval{}
	for id, r := range a.records {
		target := r.Approval.Payload.Target
		if target.Realm != tree.Realm() || app != "" && target.App != app {
			continue
		}
		row := PublicApproval{ID: id, Realm: target.Realm, Tenant: target.Tenant, Group: target.Group, User: target.User, App: target.App, Deployment: target.Deployment, Purpose: target.Purpose, Services: slices.Clone(target.Services), ApprovedAt: r.Approval.Payload.ApprovedAt, Issuer: r.Approval.Issuer, Revoking: r.Revoking, Consumers: len(r.Consumers)}
		if group, ok := tree.Object(target.Group); ok && group.MaxApprovalAge > 0 && row.ApprovedAt <= int64(^uint64(0)>>1)-group.MaxApprovalAge {
			row.ExpiresAt = row.ApprovedAt + group.MaxApprovalAge
		}
		for _, node := range target.Nodes {
			row.Nodes = append(row.Nodes, node.ID)
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b PublicApproval) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return rows
}

type PublicUsage struct {
	ID, Realm, Tenant, User, App, Standalone, Deployment, Service, Node, Purpose string
	Generation                                                                   uint64
	Secrets                                                                      []string
	Live                                                                         bool
}

func (a Approvals) PublicUsages(tree Tree, id string) []PublicUsage {
	object, ok := tree.Object(id)
	if !ok {
		return nil
	}
	rows := []PublicUsage{}
	for key, u := range a.usages {
		if u.Grant.Realm != tree.Realm() {
			continue
		}
		referenced := false
		for _, dependency := range u.Plan.Dependencies {
			referenced = referenced || dependency.ID == id && dependency.Generation == object.Generation
		}
		if !referenced {
			continue
		}
		use := u.Grant.Use
		row := PublicUsage{ID: key, Realm: u.Grant.Realm, Tenant: use.Tenant, User: use.User, App: use.App, Deployment: use.Deployment, Service: use.Service, Node: use.Node, Purpose: use.Purpose, Generation: u.Grant.Generation, Live: true}
		for _, leaf := range u.Plan.Leaves {
			if path, err := tree.path(leaf.Secret); err == nil {
				for _, ancestor := range path {
					if ancestor.ID == id && ancestor.Generation == object.Generation {
						row.Secrets = append(row.Secrets, leaf.Secret)
						break
					}
				}
			}
		}
		slices.Sort(row.Secrets)
		row.Secrets = slices.Compact(row.Secrets)
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b PublicUsage) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return rows
}
