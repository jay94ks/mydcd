// SPDX-License-Identifier: Apache-2.0

package app

import (
	"net/netip"

	"github.com/jay94ks/seafield/internal/clusterapp"
)

// clusterAppJoin is the cluster-app part of the engine's join on this
// server's system bridge (purpose 36, seafield/docs/sfcd-socket.md). The
// system bridge's join handler calls it first: handled means the container
// is a cluster app's, and then allow is the whole answer. Only the exact
// container the cluster-app journal is creating or holds may join, with its
// fixed pool address; the cluster address (10.254.0.2) reaches it through
// the mydc_cluster_apps NAT and host route that reconcileWeb keeps, which a
// join does not change.
func (r *Runtime) clusterAppJoin(networkID, containerID, containerName string, labels map[string]string, addresses []netip.Prefix) (allow, handled bool) {
	if r.clusterApps == nil {
		handled, _ = (*clusterapp.Owner)(nil).Joining(containerName, labels, addresses)
		return false, handled
	}
	handled, allow = r.clusterApps.Joining(containerName, labels, addresses)
	return allow, handled
}
