// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
)

// CD approvers: users who may approve or reject this app's candidates
// (cd-approve, cd-reject) without the tenant's ManageCD, as long as they can
// still read the tenant. Granting and revoking needs ManageCD. Nothing else
// of the app's CD is opened to an approver.

const maxCDApprovers = 64

// Approvers returns the app's approver user IDs (sorted, owned).
func (d Delivery) Approvers() []string { return slices.Clone(d.d.Approvers) }

// mayDecide: ManageCD on the tenant, or a granted approver who can still
// read the tenant.
func (d Delivery) mayDecide(c access.Catalog, actor string) bool {
	tenant := d.d.Inventory.Tenant
	if c.Authorize(actor, tenant, access.ManageCD, "") == nil {
		return true
	}
	return slices.Contains(d.d.Approvers, actor) && c.Authorize(actor, tenant, access.Read, "") == nil
}

// MayDecide is mayDecide for an accepted original's user.
func (d Delivery) MayDecide(c access.Catalog, actor string) bool { return d.mayDecide(c, actor) }

// SetApprover grants (or revokes) one user. Expected is the delivery
// revision; an unchanged list is refused so every operation changes it.
func (d Delivery) SetApprover(expected uint64, c access.Catalog, actor, user string, grant bool) (Delivery, error) {
	if expected != d.Revision() || c.Revision() < d.d.CatalogFloor || c.Authorize(actor, d.d.Inventory.Tenant, access.ManageCD, "") != nil || !identifier(user) {
		return d, ErrInputs
	}
	has := slices.Contains(d.d.Approvers, user)
	if grant == has {
		return d, ErrInputs
	}
	if grant {
		if u, ok := c.User(user); !ok || !u.Enabled || len(d.d.Approvers) >= maxCDApprovers {
			return d, ErrInputs
		}
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	if grant {
		n.d.Approvers = append(n.d.Approvers, user)
		slices.Sort(n.d.Approvers)
	} else {
		n.d.Approvers = slices.DeleteFunc(n.d.Approvers, func(v string) bool { return v == user })
		if len(n.d.Approvers) == 0 {
			n.d.Approvers = nil
		}
	}
	n.d.CatalogFloor = max(n.d.CatalogFloor, c.Revision())
	return n, nil
}

func validApprovers(list []string) bool {
	if list != nil && len(list) == 0 || len(list) > maxCDApprovers || !slices.IsSorted(list) {
		return false
	}
	for i, v := range list {
		if !identifier(v) || i > 0 && list[i-1] == v {
			return false
		}
	}
	return true
}
