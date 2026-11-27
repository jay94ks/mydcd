// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"net"
	"net/netip"
	"testing"
)

func TestAddressScope(t *testing.T) {
	for address, want := range map[string]string{
		"203.0.113.7": "public", "2001:db8::1": "public",
		"192.168.1.101": "private", "10.254.240.1": "private", "100.64.0.9": "private", "fd00::1": "private",
		"127.0.0.1": "loopback", "::1": "loopback",
		"169.254.1.1": "", "fe80::1": "", "0.0.0.0": "", "224.0.0.1": "",
	} {
		if got := AddressScope(netip.MustParseAddr(address)); got != want {
			t.Fatal(address, got, want)
		}
	}
}

func TestLocalAddressKeepsPrefixAndDropsLinkLocal(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.1.101/24")
	n.IP = net.ParseIP("192.168.1.101") // 16-byte form, as interfaces report it
	got, ok := localAddress("eth0", n)
	if !ok || got != (LocalAddress{Interface: "eth0", Prefix: netip.MustParsePrefix("192.168.1.101/24"), Scope: "private"}) {
		t.Fatal(got, ok)
	}
	_, link, _ := net.ParseCIDR("fe80::1/64")
	if _, ok := localAddress("eth0", link); ok {
		t.Fatal("link-local address offered to a gateway")
	}
	v := []LocalAddress{
		{Interface: "lo", Prefix: netip.MustParsePrefix("127.0.0.1/8"), Scope: "loopback"},
		{Interface: "eth0", Prefix: netip.MustParsePrefix("192.168.1.101/24"), Scope: "private"},
		{Interface: "eth1", Prefix: netip.MustParsePrefix("203.0.113.7/24"), Scope: "public"},
	}
	SortLocalAddresses(v)
	if v[0].Scope != "public" || v[1].Scope != "private" || v[2].Scope != "loopback" {
		t.Fatal(v)
	}
	if all, err := LocalAddresses(); err != nil {
		t.Fatal(err)
	} else {
		for _, a := range all {
			if a.Scope == "" || !a.Prefix.IsValid() || a.Interface == "" {
				t.Fatal(a)
			}
		}
	}
}
