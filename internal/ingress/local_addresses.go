// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"net"
	"net/netip"
	"slices"
	"strings"
)

// LocalAddress is one address of a server's own interface, read on that
// server when a gateway form asks which addresses it can listen on. It is an
// observation for choosing, never a stored setting: ValidateLocalGateways
// still checks the chosen addresses when the change is signed.
type LocalAddress struct {
	Interface string
	Prefix    netip.Prefix // the address with its interface prefix length
	Scope     string       // public, private or loopback
}

// LocalAddresses lists the addresses of the interfaces that are up. Link-local
// and multicast addresses are left out: a gateway cannot listen on them.
func LocalAddresses() ([]LocalAddress, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []LocalAddress
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addresses {
			if v, ok := localAddress(i.Name, a); ok {
				out = append(out, v)
			}
		}
	}
	SortLocalAddresses(out)
	return out, nil
}

func localAddress(name string, a net.Addr) (LocalAddress, bool) {
	n, ok := a.(*net.IPNet)
	if !ok {
		return LocalAddress{}, false
	}
	addr, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return LocalAddress{}, false
	}
	addr = addr.Unmap()
	bits, _ := n.Mask.Size()
	if addr.Is4() && bits > 32 {
		bits -= 96
	}
	prefix := netip.PrefixFrom(addr, bits)
	if !prefix.IsValid() {
		return LocalAddress{}, false
	}
	scope := AddressScope(addr)
	if scope == "" {
		return LocalAddress{}, false
	}
	return LocalAddress{Interface: name, Prefix: prefix, Scope: scope}, true
}

// AddressScope is public, private or loopback, or "" for an address a
// gateway cannot listen on (unspecified, link-local, multicast).
func AddressScope(a netip.Addr) string {
	switch {
	case !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast():
		return ""
	case a.IsLoopback():
		return "loopback"
	case a.IsPrivate() || sharedAddressSpace.Contains(a):
		return "private"
	case a.IsGlobalUnicast():
		return "public"
	}
	return ""
}

// RFC 6598 carrier-grade NAT space is not reachable from the internet.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// SortLocalAddresses orders public first, then private, then loopback, and
// by interface and address within each scope.
func SortLocalAddresses(v []LocalAddress) {
	rank := map[string]int{"public": 0, "private": 1, "loopback": 2}
	slices.SortFunc(v, func(a, b LocalAddress) int {
		if d := rank[a.Scope] - rank[b.Scope]; d != 0 {
			return d
		}
		if d := strings.Compare(a.Interface, b.Interface); d != 0 {
			return d
		}
		return a.Prefix.Addr().Compare(b.Prefix.Addr())
	})
}
