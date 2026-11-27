// SPDX-License-Identifier: Apache-2.0

package network

import "net/netip"

// SystemRange is the system network's fixed address range (sfc-system;
// Jay 2026-11-26: no user ever changes it). ClusterBlock comes first, then
// one /24 pool per server that runs cluster apps (10.254.1.0/24 …
// 10.254.239.0/24), and ServerBlock last.
var SystemRange = netip.MustParsePrefix("10.254.0.0/16")

// ClusterBlock is kept for cluster-wide addresses (such as a cluster app's
// fixed address); no pool or server takes it.
var ClusterBlock = netip.MustParsePrefix("10.254.0.0/24")

// ServerBlock holds the server addresses: one fixed address per server,
// set when the server is added to the cluster and free again once it is
// removed. It is the server's tunnel address in every TUN network.
var ServerBlock = netip.MustParsePrefix("10.254.240.0/20")

// SharedServerPrefix reports a prefix inside ServerBlock. Server addresses
// are the tunnel addresses of every TUN network on their server, so they
// belong to no tenant in the isolation rules.
func SharedServerPrefix(p netip.Prefix) bool {
	return p.IsValid() && p.Bits() >= ServerBlock.Bits() && ServerBlock.Contains(p.Addr())
}

// ValidServerAddress: a host address of ServerBlock (not its first or last).
func ValidServerAddress(a netip.Addr) bool {
	return a.Is4() && ServerBlock.Contains(a) && a != ServerBlock.Addr() && a != netip.MustParseAddr("10.254.255.255")
}

// clusterAppHosts is each cluster app's fixed host number. The app's
// cluster address is that host in ClusterBlock (Jay 2026-11-27: web is
// 10.254.0.2 wherever it runs); its container sits at the same host in the
// system pool of the server that runs it (.1 is the pool's gateway). They
// stay in the lower half: Docker hands out only .128/25.
var clusterAppHosts = map[string]byte{"web": 2}

// ClusterAppAddress is app's cluster-wide address: the same on every
// server, whichever server runs it. Every other member's sfc-system TUN
// routes it to the runner, which hands it to the container
// (ClusterAppNAT).
func ClusterAppAddress(app string) (netip.Addr, bool) {
	return clusterAppHost(ClusterBlock, app)
}

// ClusterAppPoolAddress is app's container address in pool, the system
// pool of the one server that runs it. No server reports it: every server
// computes it.
func ClusterAppPoolAddress(pool netip.Prefix, app string) (netip.Addr, bool) {
	if !pool.Addr().Is4() || pool.Bits() != 24 || !SystemRange.Contains(pool.Addr()) || pool.Overlaps(ClusterBlock) || pool.Overlaps(ServerBlock) {
		return netip.Addr{}, false
	}
	return clusterAppHost(pool, app)
}

func clusterAppHost(block netip.Prefix, app string) (netip.Addr, bool) {
	host, ok := clusterAppHosts[app]
	if !ok {
		return netip.Addr{}, false
	}
	a := block.Masked().Addr().As4()
	a[3] = host
	return netip.AddrFrom4(a), true
}
