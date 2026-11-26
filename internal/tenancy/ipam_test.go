// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"net/netip"
	"testing"

	"github.com/jay94ks/mydcd/internal/network"
)

func TestNetworkIPAMDockerRangeProjectsIdenticallyAndRequiresExplicitChange(t *testing.T) {
	f, q, d := logicalFixture(t)
	ipam := network.PoolIPAM{Dynamic: netip.MustParsePrefix("10.71.1.0/25")}
	d.Members[0].Pools[0].IPAM = ipam
	n, err := f.n.CreateTUN(f.c, q, "alice", f.n.Revision(), d)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(snapshotBytes(t, n))
	if err != nil {
		t.Fatal(err)
	}
	book, err := restored.AddressPlan(4)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := restored.TUNSources("first", "services")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Network.Node != "node-a" {
			continue
		}
		p := row.Network.Pools[0]
		if p.IPAM != ipam || row.Bridge.Pools[0].IPAM != ipam {
			t.Fatal("committed native projection lost reservation")
		}
		shared, ok := book.Pool("first/" + row.Network.ID + "/" + p.ID)
		if !ok || shared.IPAM != ipam {
			t.Fatal("shared allocator diverged from Bridge")
		}
		if _, _, err := book.Reserve("task", shared.Owner, shared.Network, shared.ID, 1, netip.MustParseAddr("10.71.1.128")); err != nil {
			t.Fatal("usable CIDR address outside Docker automatic range", err)
		}
		changed := shared
		changed.IPAM.Dynamic = netip.MustParsePrefix("10.71.1.128/25")
		if _, err := book.AddPool(changed); err == nil {
			t.Fatal("existing generation reservation silently rewritten")
		}
	}
	bad := copyTUN(d)
	bad.Members[0].Pools[0].IPAM.Dynamic = netip.MustParsePrefix("10.72.1.0/24")
	if _, err := f.n.CreateTUN(f.c, q, "alice", f.n.Revision(), bad); err == nil {
		t.Fatal("foreign Docker allocation range accepted by control definition")
	}
}
