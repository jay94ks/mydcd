// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
)

func pool(id, prefix string) Pool {
	p := netip.MustParsePrefix(prefix)
	return Pool{ID: id, Network: "net", Owner: "node", Prefix: p, Gateway: p.Addr().Next(), MTU: 1400}
}
func TestMultiCIDRIPAMOwnershipExhaustionAndRestore(t *testing.T) {
	b, _ := NewBook(3)
	var err error
	b, err = b.AddPool(pool("a", "10.0.0.0/30"))
	if err != nil {
		t.Fatal(err)
	}
	b, err = b.AddPool(pool("b", "10.0.1.0/29"))
	if err != nil {
		t.Fatal(err)
	}
	before := b.Checkpoint()
	_, a, err := b.Reserve("ep1", "node", "net", "", 1, netip.Addr{})
	if err != nil || a.Address.String() != "10.0.0.2" {
		t.Fatal(a, err)
	}
	if !reflect.DeepEqual(before, b.Checkpoint()) {
		t.Fatal("allocation mutated published book")
	}
	b, a, _ = b.Reserve("ep1", "node", "net", "", 1, netip.Addr{})
	b, c, err := b.Reserve("ep2", "node", "net", "", 2, netip.Addr{})
	if err != nil || c.Pool != "b" {
		t.Fatal("did not move to next nonoverlapping CIDR", c, err)
	}
	if got, same, err := b.Reserve("ep1", "node", "net", "a", 1, a.Address); err != nil || same != a || got.Count() != 2 {
		t.Fatal("duplicate reserve changed state")
	}
	if _, _, err := b.Reserve("ep1", "foreign", "net", "a", 1, a.Address); err == nil {
		t.Fatal("owner overwritten")
	}
	if _, _, err := b.Reserve("ep3", "node", "net", "b", 3, c.Address); err == nil {
		t.Fatal("address collision")
	}
	if _, err := b.AddPool(pool("overlap", "10.0.0.0/24")); err == nil {
		t.Fatal("overlapping CIDR accepted")
	}
	b, err = b.DrainPool("a", "node")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.RemovePool("a", "node"); err == nil {
		t.Fatal("removed live pool")
	}
	data, _ := json.Marshal(b.Checkpoint())
	var j Journal
	_ = json.Unmarshal(data, &j)
	b, err = Restore(j)
	if err != nil {
		t.Fatal(err)
	}
	b, err = b.Release(a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Release(a); err == nil {
		t.Fatal("double release")
	}
	b, err = b.RemovePool("a", "node")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Reserve("ep1", "node", "net", "b", 1, netip.Addr{}); err == nil {
		t.Fatal("reused retired generation")
	}
	b, next, err := b.Reserve("ep1", "node", "net", "b", 4, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Release(a); err == nil || next.Generation != 4 {
		t.Fatal("old completion freed replacement")
	}
	if _, err := b.Resize(1); err == nil {
		t.Fatal("shrunk below usage")
	}
	b, err = b.Resize(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Reserve("ep3", "node", "net", "b", 5, netip.Addr{}); err == nil {
		t.Fatal("capacity exceeded")
	}
	j = b.Checkpoint()
	j.Allocations = append(j.Allocations, j.Allocations[0])
	if _, err := Restore(j); err == nil {
		t.Fatal("duplicate snapshot allocation")
	}
}
func TestAddressAndMTUPolicyBoundaries(t *testing.T) {
	b, _ := NewBook(8)
	b, _ = b.AddPool(pool("v4", "192.0.2.0/29"))
	b, _ = b.AddPool(pool("v6", "2001:db8::/64"))
	for _, address := range []string{"192.0.2.0", "192.0.2.1", "192.0.2.7", "198.51.100.1", "::ffff:192.0.2.2"} {
		if _, _, err := b.Reserve("ep", "node", "net", "v4", 1, netip.MustParseAddr(address)); err == nil {
			t.Fatal("reserved special/wrong address", address)
		}
	}
	_, a, err := b.Reserve("ipv6", "node", "net", "v6", 1, netip.Addr{})
	if err != nil || a.Address.String() != "2001:db8::2" {
		t.Fatal("unbounded IPv6 scan", a, err)
	}
	for _, c := range []struct{ tun, path, overhead, want int }{{1400, 1500, 100, 1400}, {1400, 1380, 100, 1280}, {1400, 1379, 100, 0}, {1200, 1500, 0, 0}, {1400, 1500, -1, 0}, {1400, 100, 100, 0}} {
		got, err := PacketBudget(c.tun, c.path, c.overhead)
		if got != c.want || (err != nil) != (c.want == 0) {
			t.Fatal(c, got, err)
		}
	}
}
func TestListenerWildcardsProtocolsLimitsAndStaleRelease(t *testing.T) {
	a := Listener{ID: "http", Owner: "app", Generation: 1, Address: netip.IPv4Unspecified(), Protocol: 6, Port: 443}
	current, err := ReserveListener(nil, a, 2)
	if err != nil {
		t.Fatal(err)
	}
	b := a
	b.ID = "other"
	b.Address = netip.MustParseAddr("127.0.0.1")
	if _, err := ReserveListener(current, b, 2); err == nil {
		t.Fatal("wildcard overlap")
	}
	b.Protocol = 17
	current, err = ReserveListener(current, b, 2)
	if err != nil {
		t.Fatal("TCP/UDP should be distinct", err)
	}
	if got, err := ReserveListener(current, a, 2); err != nil || len(got) != 2 {
		t.Fatal("idempotent listener")
	}
	b.ID = "third"
	b.Port = 80
	if _, err := ReserveListener(current, b, 2); err == nil {
		t.Fatal("listener limit")
	}
	a6 := a
	a6.Address = netip.IPv6Unspecified()
	a6.DualStack = true
	if !ListenerConflict(a6, a) {
		t.Fatal("dual-stack wildcard")
	}
	a6.DualStack = false
	if ListenerConflict(a6, a) {
		t.Fatal("IPv6-only blocks IPv4")
	}
	stale := a
	stale.Generation = 2
	if _, err := ReleaseListener(current, stale); err == nil {
		t.Fatal("foreign receipt released listener")
	}
	current, err = ReleaseListener(current, a)
	if err != nil || len(current) != 1 {
		t.Fatal(err)
	}
}
