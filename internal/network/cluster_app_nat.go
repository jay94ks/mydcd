// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"net"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ClusterAppForward hands a cluster app's cluster-wide address to its
// container on the server that runs it: packets for Cluster go to Pool.
// Only those that come in on In, this server's sfc-system TUN, or that
// this server sends itself are rewritten; a packet for Cluster from any
// other interface (a LAN host that routes the address here, a workspace
// bridge) is left alone and finds no container. No In: only this server's
// own connections.
type ClusterAppForward struct {
	Cluster, Pool netip.Addr
	In            string
}

func (f ClusterAppForward) tag() []byte {
	return []byte("sfc-cluster-app:" + f.Cluster.String() + ">" + f.Pool.String() + "<" + f.In)
}

// clusterAppNATTable is sfcd's own table; nothing else writes it.
const clusterAppNATTable = "sfc_cluster_apps"

func clusterAppNATRules(forwards []ClusterAppForward) (*nftables.Table, []*nftables.Chain, map[string][]*nftables.Rule) {
	t := &nftables.Table{Name: clusterAppNATTable, Family: nftables.TableFamilyIPv4}
	accept := nftables.ChainPolicyAccept
	chains := []*nftables.Chain{
		{Name: "prerouting", Table: t, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest, Policy: &accept},
		{Name: "output", Table: t, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest, Policy: &accept},
	}
	rules := map[string][]*nftables.Rule{}
	for _, c := range chains {
		for _, f := range forwards {
			var match []expr.Any
			if c.Name == "prerouting" {
				if f.In == "" {
					continue
				}
				name := make([]byte, 16)
				copy(name, f.In)
				match = []expr.Any{&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name}}
			}
			cluster, pool := f.Cluster.As4(), f.Pool.As4()
			rules[c.Name] = append(rules[c.Name], &nftables.Rule{Table: t, Chain: c, UserData: f.tag(), Exprs: append(match,
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: cluster[:]},
				&expr.Immediate{Register: 1, Data: pool[:]},
				&expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1},
			)})
		}
	}
	return t, chains, rules
}

// clusterAppNATState reads sfcd's table: whether it is there and whether
// it holds exactly forwards (by each rule's tag, in order, in each chain).
func clusterAppNATState(c *nftables.Conn, forwards []ClusterAppForward) (present, same bool, err error) {
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return false, false, err
	}
	var table *nftables.Table
	for _, t := range tables {
		if t.Name == clusterAppNATTable {
			table = t
		}
	}
	if table == nil {
		return false, len(forwards) == 0, nil
	}
	if len(forwards) == 0 {
		return true, false, nil
	}
	_, want, wantRules := clusterAppNATRules(forwards)
	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return true, false, err
	}
	found := 0
	for _, got := range chains {
		if got.Table.Name != clusterAppNATTable {
			continue
		}
		i := slices.IndexFunc(want, func(w *nftables.Chain) bool { return w.Name == got.Name })
		if i < 0 || got.Type != want[i].Type || got.Hooknum == nil || *got.Hooknum != *want[i].Hooknum || got.Priority == nil || *got.Priority != *want[i].Priority {
			return true, false, nil
		}
		rules, err := c.GetRules(table, got)
		if err != nil {
			return true, false, err
		}
		expected := wantRules[got.Name]
		if len(rules) != len(expected) {
			return true, false, nil
		}
		for j, r := range rules {
			if !bytes.Equal(r.UserData, expected[j].UserData) {
				return true, false, nil
			}
		}
		found++
	}
	return true, found == len(want), nil
}

// clusterAppRouteProtocol marks sfcd's host routes for cluster addresses
// (an otherwise unused routing protocol number).
const clusterAppRouteProtocol = 109

func clusterAppRoute(f ClusterAppForward) netlink.Route {
	return netlink.Route{Dst: &net.IPNet{IP: net.IP(f.Cluster.AsSlice()), Mask: net.CIDRMask(32, 32)}, Gw: net.IP(f.Pool.AsSlice()), Table: unix.RT_TABLE_MAIN, Protocol: clusterAppRouteProtocol, Scope: netlink.SCOPE_UNIVERSE, Type: unix.RTN_UNICAST}
}

// setClusterAppRoutes keeps one host route per forward, cluster address via
// the container, so this server's own connections (ingress, the node.yaml
// port) find a route before the output hook rewrites the address. Routes
// with sfcd's mark that are no longer forwards go.
func setClusterAppRoutes(forwards []ClusterAppForward) error {
	rows, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_MAIN, Protocol: clusterAppRouteProtocol}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, r := range rows {
		want := slices.ContainsFunc(forwards, func(f ClusterAppForward) bool {
			return r.Dst != nil && r.Dst.String() == netip.PrefixFrom(f.Cluster, 32).String() && r.Gw.Equal(net.IP(f.Pool.AsSlice()))
		})
		if want {
			keep[r.Dst.String()] = true
			continue
		}
		if err = netlink.RouteDel(&r); err != nil {
			return err
		}
	}
	for _, f := range forwards {
		if keep[netip.PrefixFrom(f.Cluster, 32).String()] {
			continue
		}
		r := clusterAppRoute(f)
		if err = netlink.RouteReplace(&r); err != nil {
			return err
		}
	}
	return nil
}

// SetClusterApps is SetClusterAppNAT with the host routes: what the server
// that runs cluster apps keeps (no forwards on any other server).
func SetClusterApps(forwards []ClusterAppForward) error {
	if err := SetClusterAppNAT(forwards); err != nil {
		return err
	}
	return setClusterAppRoutes(forwards)
}

// SetClusterAppNAT makes this server hand each forward's cluster address to
// its container, and nothing else; no forwards removes the table. The table
// is replaced in one nft batch. Only sfc-system lets the address in from
// another server (its TUN routes and packet policy carry it); a workspace
// container on this server is still kept off the system bridge by Docker's
// bridge isolation after the address is rewritten.
func SetClusterAppNAT(forwards []ClusterAppForward) error {
	for _, f := range forwards {
		if len(f.In) > 15 || !f.Cluster.Is4() || !ClusterBlock.Contains(f.Cluster) || !f.Pool.Is4() || !SystemRange.Contains(f.Pool) || ClusterBlock.Contains(f.Pool) || ServerBlock.Contains(f.Pool) {
			return ErrPolicy
		}
	}
	c := &nftables.Conn{}
	present, same, err := clusterAppNATState(c, forwards)
	if err != nil || same {
		return err
	}
	t, chains, rules := clusterAppNATRules(forwards)
	if present {
		c.DelTable(t)
	}
	if len(forwards) != 0 {
		c.AddTable(t)
		for _, ch := range chains {
			c.AddChain(ch)
			for _, r := range rules[ch.Name] {
				c.AddRule(r)
			}
		}
	}
	if err = c.Flush(); err != nil {
		return err
	}
	if _, same, err = clusterAppNATState(c, forwards); err == nil && !same {
		err = ErrKernelOwnership
	}
	return err
}
