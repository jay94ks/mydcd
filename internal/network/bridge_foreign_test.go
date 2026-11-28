// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/vishvananda/netlink"
)

func TestSFCBridgeNameIsTheEngineDeviceName(t *testing.T) {
	for name, want := range map[string]bool{"md257c3886de5b": true, "md11698ad5a563": true, "mdXYZ": false, "md257c3886de5B": false, "br-257c3886de5b": false, "md257c3886de5b0": false, "docker0": false} {
		if sfcBridgeName(name) != want {
			t.Error(name, want)
		}
	}
}

// A bridge left from an earlier cluster (state wiped, kernel device kept)
// is listed with its state and subnet; other bridges are not.
func TestRealBoundaryForeignBridgesListsLeftoverSFCBridges(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create bridges")
	}
	j, err := reconcile.OpenJournal(filepath.Join(t.TempDir(), "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	m := &Manager{journal: j, driver: &BridgeDriver{}}
	add := func(name, cidr string) {
		link := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}}
		if err := netlink.LinkAdd(link); err != nil {
			t.Skip("cannot create bridges here:", err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(link) })
		_, n, _ := net.ParseCIDR(cidr)
		ip, _, _ := net.ParseCIDR(cidr)
		n.IP = ip
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: n}); err != nil {
			t.Fatal(err)
		}
	}
	add("md0f0f0f0f0f0f", "10.99.1.1/24")
	add("sfctestbr0", "10.99.2.1/24")
	notes, err := m.ForeignBridges()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(notes, ", ")
	if !strings.Contains(joined, "md0f0f0f0f0f0f DOWN [10.99.1.1/24]") || strings.Contains(joined, "sfctestbr0") {
		t.Fatal(notes)
	}
}
