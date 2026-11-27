// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

// A cluster built with init, join and promote: both servers, the genesis
// one included, must admit each other's TUN path control for a network on
// both of them.
func TestGenesisAndJoinedNodesGrantManagedTunnel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	m := newManagedVoters(t, ctx, filepath.Join(root, "cluster"), admin, 2)
	read := func() (control.Resources, []byte) {
		view, err := m.Nodes[0].Engine().Read(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		r, err := m.Policy.Resources(view.State)
		if err != nil {
			t.Fatal(err)
		}
		return r, nil
	}
	m.Change(0, "tenant", "create-tenant", 0, control.TenantID{ID: "shop"})
	view, _ := m.Nodes[0].Engine().Read(ctx, false)
	catalog, _ := m.Policy.Catalog(view.State)
	tenant, _ := catalog.Tenant("shop")
	m.Change(0, "nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("shop", tenant.AllowedNodes, []string{"node-0", "node-1"}))
	for _, node := range []string{"node-0", "node-1"} {
		for _, scope := range []string{"", "shop"} {
			m.Change(0, "quota-"+node+"-"+scope, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: node, Capacity: workload.Resources{CPU: 1e9, Memory: 256 << 20}, Networks: 2, MaxConsumers: 8, PacketQueuePackets: 64, PacketQueueBytes: 128 << 10})
		}
	}
	r, _ := read()
	pool := func(prefix string) []tenancy.Subnet {
		p := netip.MustParsePrefix(prefix)
		return []tenancy.Subnet{{ID: "main", Prefix: p, Gateway: p.Addr().Next(), MTU: 1280}}
	}
	m.Change(0, "net", "create-tun-network", r.Networks.Revision(), tenancy.TUNDefinition{Tenant: "shop", Name: "shop-net", Members: []tenancy.TUNNode{
		{Node: "node-0", Pools: pool("10.241.10.0/24")},
		{Node: "node-1", Pools: pool("10.241.20.0/24")},
	}})
	time.Sleep(time.Second) // let node-1 apply the network
	for i, n := range m.Nodes {
		view, err := n.Engine().Read(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		d, _ := m.Policy.Members(view.State)
		local, remote := n.Identity.Public, m.Nodes[1-i].Identity.Public
		if !d.WorkKey(local) || !d.WorkKey(remote) {
			t.Errorf("node-%d: work keys local=%v remote=%v", i, d.WorkKey(local), d.WorkKey(remote))
		}
		for j, key := range [][32]byte{local, remote} {
			if got := m.Policy.ResourceWorkKey(view.State, key); got != key {
				t.Errorf("node-%d: ResourceWorkKey of key %d = %x", i, j, got[:4])
			}
		}
		if _, err := n.localTunnelWireKey(view); err != nil {
			t.Errorf("node-%d: local tunnel wire key: %v", i, err)
		}
		if !managedTunnelGrant(view.State, local, remote, m.Policy) {
			t.Errorf("node-%d does not grant the managed tunnel to node-%d", i, 1-i)
		}
	}
}

func TestPathRefusalIsAdmission(t *testing.T) {
	err := pathRefused("why")
	if !errors.Is(err, sfcp.ErrAdmission) || err.Error() != "managed TUN path refused: why" {
		t.Fatal(err)
	}
}
