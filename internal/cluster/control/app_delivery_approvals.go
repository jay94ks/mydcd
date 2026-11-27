// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

// Check before retiring the current app, and again before applying the frozen
// replacement. This is the same Tree.Plan/Approvals.Missing contract used by
// ordinary Inputs/Volume move; no Task generation or password is invented.
func (p Policy) checkCDGroupApprovals(s state.State, c access.Catalog, entry appEntry, b deployment.Blueprint, at int64) error {
	if at <= 0 {
		return access.ErrDenied
	}
	uses, err := b.ApprovalUses(entry.Origin.Session.Key)
	if err != nil {
		return err
	}
	if len(uses) == 0 {
		return nil
	}
	v, err := p.Vault(s)
	if err != nil {
		return err
	}
	var realms []string
	for realm := range uses {
		realms = append(realms, realm)
	}
	slices.Sort(realms)
	for _, realm := range realms {
		tree, exists := v.Trees[realm]
		if !exists {
			return access.ErrDenied
		}
		plan, err := tree.Plan(c, uses[realm])
		if err != nil || len(v.Approvals.Missing(c, tree, plan, at)) != 0 {
			return access.ErrDenied
		}
	}
	return nil
}
