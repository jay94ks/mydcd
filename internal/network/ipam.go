// SPDX-License-Identifier: Apache-2.0

package network

import "net/netip"

// PoolIPAM is committed before native creation. Dynamic selects Docker's
// automatic IP allocation range within the node-owned CIDR. MyDC manages
// ownership and static endpoint reservations; it does not run a DHCP server.
type PoolIPAM struct {
	Dynamic netip.Prefix `json:",omitzero"`
}

func (p Pool) validIPAM() bool {
	d := p.IPAM.Dynamic
	return d == (netip.Prefix{}) || d.IsValid() && d == d.Masked() && d.Addr().Zone() == "" && !d.Addr().Is4In6() && d.Addr().BitLen() == p.Prefix.Addr().BitLen() && d.Bits() >= p.Prefix.Bits() && p.Prefix.Contains(d.Addr())
}
