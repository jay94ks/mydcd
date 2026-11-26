// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// Both limits and the original scope come from the SAME committed view used
// by NativePermit. This is current budget policy, never a native receipt.
func (p Policy) nativeConsumerBudget(tenant, node string, owner [32]byte, global, scoped tenancy.NodeLimit) *network.ConsumerBudget {
	return &network.ConsumerBudget{Scope: reconcile.ConsumerScope{Tenant: tenant, Node: node, Owner: engine.Owner(p.Cluster, owner)}, NodeMaxConsumers: global.MaxConsumers, TenantMaxConsumers: scoped.MaxConsumers}
}
