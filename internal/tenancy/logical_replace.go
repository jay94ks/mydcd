// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
)

// ReplaceTUN consumes every original fenced member. It is a new explicit
// management decision, not a rewrite/retry of those original target intents.
// Their history must be archived by Authority in the same enclosing FSM write.
// Native source withdrawal/closed target metadata is checked by that owner.
func (n Networks) ReplaceTUN(c access.Catalog, quotas Quotas, actor string, expected uint64, versions []NetworkChangeVersion, target TUNDefinition) (Networks, error) {
	if target.System || target.Tenant == "" || expected != n.revision || len(versions) == 0 || len(versions) > 32 || len(target.Members) > 32 || target.GatewayMode != "" && target.GatewayMode != network.ManagedGatewayMode {
		return n, ErrPolicy
	}
	rows, err := n.TUNSources(target.Tenant, target.Name)
	if err != nil || len(rows) != len(versions) || !mayRetire(c, actor, target.Tenant, access.ManageNetwork) {
		return n, ErrPolicy
	}
	for i, row := range rows {
		v := versions[i]
		ch, found := n.Change(row.Network.Tenant, row.Network.ID)
		if v.Tenant != target.Tenant || v.ID != row.Network.ID || !found || ch.Generation != v.Generation || ch.Revision != v.Revision || ch.Phase != ChangeFenced || ch.SourceClosed == nil || !n.validSourceClose(ch, *ch.SourceClosed) {
			return n, ErrPolicy
		}
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	for _, v := range versions {
		delete(q.networks, key(v.Tenant, v.ID))
		delete(q.changes, key(v.Tenant, v.ID))
	}
	if len(target.Members) == 0 {
		if len(n.BridgesOf(BridgeEnd{target.Tenant, target.Name})) != 0 {
			return n, ErrBridgeAttached
		}
		if _, err := q.Encode(); err != nil {
			return n, err
		}
		return q, nil
	}
	// This staging view is never published. CreateTUN assigns the one next
	// revision after validating all new members against every remaining scope.
	q.revision = n.revision
	q, err = q.CreateTUN(c, quotas, actor, q.revision, target)
	if err != nil {
		return n, err
	}
	return q, nil
}
