// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type TenantPrefix struct {
	Tenant string
	Prefix netip.Prefix
}
type IsolationBridge struct {
	Tenant, Device string
	Prefixes       []netip.Prefix `json:",omitempty"`
	Managed        bool           `json:",omitempty"`
}
type IsolationTunnel struct {
	Tenant, Device string
	Prefixes       []netip.Prefix
}
type IsolationRoute struct {
	Device string
	Policy PacketRoutePolicy
}

// IsolationSpec is derived from committed source ownership and original native
// journals. It is not an app input, address allocator, or route admission grant.
type IsolationSpec struct {
	Schema   uint8
	Owner    string
	Prefixes []TenantPrefix
	Bridges  []IsolationBridge
	Routes   []IsolationRoute
	Tunnels  []IsolationTunnel `json:",omitempty"`
}

func nativeDevice(name, prefix string) bool {
	return len(name) == 14 && strings.HasPrefix(name, prefix) && strings.Trim(name[2:], "0123456789abcdef") == ""
}

func NormalizeIsolation(s IsolationSpec) (IsolationSpec, error) {
	owner := strings.Split(s.Owner, "/")
	if s.Schema != 1 || len(owner) != 2 || len(s.Prefixes) > 4096 || len(s.Bridges) > 4096 || len(s.Routes) > 4096 || len(s.Tunnels) > 4096 {
		return s, ErrPolicy
	}
	for _, part := range owner {
		if decoded, err := hex.DecodeString(part); err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != part || bytes.Equal(decoded, make([]byte, 32)) {
			return s, ErrPolicy
		}
	}
	s.Prefixes = slices.Clone(s.Prefixes)
	s.Bridges = slices.Clone(s.Bridges)
	s.Routes = slices.Clone(s.Routes)
	s.Tunnels = slices.Clone(s.Tunnels)
	slices.SortFunc(s.Prefixes, func(a, b TenantPrefix) int {
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}
		if a.Prefix.Bits() != b.Prefix.Bits() {
			return a.Prefix.Bits() - b.Prefix.Bits()
		}
		return strings.Compare(a.Tenant, b.Tenant)
	})
	s.Prefixes = slices.Compact(s.Prefixes)
	for i, p := range s.Prefixes {
		if p.Tenant == "" || len(p.Tenant) > 63 || strings.ContainsAny(p.Tenant, "/\x00") || !p.Prefix.IsValid() || p.Prefix != p.Prefix.Masked() || p.Prefix.Bits() == 0 || !packetAddress(p.Prefix.Addr()) {
			return s, ErrPolicy
		}
		for _, prior := range s.Prefixes[:i] {
			if p.Tenant != prior.Tenant && p.Prefix.Overlaps(prior.Prefix) {
				return s, ErrPolicy
			}
		}
	}
	slices.SortFunc(s.Bridges, func(a, b IsolationBridge) int { return strings.Compare(a.Device, b.Device) })
	for i := range s.Bridges {
		var err error
		s.Bridges[i].Prefixes, err = isolationPrefixes(s.Prefixes, s.Bridges[i].Tenant, s.Bridges[i].Prefixes)
		if err != nil || s.Bridges[i].Managed && len(s.Bridges[i].Prefixes) == 0 {
			return s, ErrPolicy
		}
	}
	s.Bridges = slices.CompactFunc(s.Bridges, func(a, b IsolationBridge) bool {
		return a.Tenant == b.Tenant && a.Device == b.Device && a.Managed == b.Managed && slices.Equal(a.Prefixes, b.Prefixes)
	})
	for i, b := range s.Bridges {
		if b.Tenant == "" || !nativeDevice(b.Device, "md") || i > 0 && s.Bridges[i-1].Device == b.Device {
			return s, ErrPolicy
		}
		if !slices.ContainsFunc(s.Prefixes, func(p TenantPrefix) bool { return p.Tenant == b.Tenant }) {
			return s, ErrPolicy
		}
	}
	slices.SortFunc(s.Tunnels, func(a, b IsolationTunnel) int { return strings.Compare(a.Device, b.Device) })
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		var err error
		t.Prefixes, err = isolationPrefixes(s.Prefixes, t.Tenant, t.Prefixes)
		// A lone member's TUN has no routes: no prefix is allowed through it.
		if err != nil || t.Tenant == "" || !nativeDevice(t.Device, "mt") {
			return s, ErrPolicy
		}
	}
	s.Tunnels = slices.CompactFunc(s.Tunnels, func(a, b IsolationTunnel) bool {
		return a.Tenant == b.Tenant && a.Device == b.Device && slices.Equal(a.Prefixes, b.Prefixes)
	})
	for i, t := range s.Tunnels {
		if i > 0 && s.Tunnels[i-1].Device == t.Device || slices.ContainsFunc(s.Routes, func(r IsolationRoute) bool { return r.Device == t.Device }) {
			return s, ErrPolicy
		}
	}
	for i := range s.Routes {
		r := &s.Routes[i]
		r.Policy.Ports = slices.Clone(r.Policy.Ports)
		remote := r.Policy.Source
		if r.Policy.LocalSource {
			remote = r.Policy.Destination
		}
		if !nativeDevice(r.Device, "mt") || !r.Policy.valid(TunnelSpec{Routes: []netip.Prefix{remote}}) || r.Policy.Bridge == "" {
			return s, ErrPolicy
		}
		var localTenant, sourceTenant, destinationTenant string
		for _, b := range s.Bridges {
			if b.Device == r.Policy.Bridge {
				localTenant = b.Tenant
			}
		}
		for _, p := range s.Prefixes {
			if p.Prefix == r.Policy.Source {
				sourceTenant = p.Tenant
			}
			if p.Prefix == r.Policy.Destination {
				destinationTenant = p.Tenant
			}
		}
		wanted := destinationTenant
		if r.Policy.LocalSource {
			wanted = sourceTenant
		}
		if localTenant == "" || sourceTenant == "" || destinationTenant == "" || sourceTenant == destinationTenant || wanted != localTenant {
			return s, ErrPolicy
		}
	}
	slices.SortFunc(s.Routes, func(a, b IsolationRoute) int {
		if c := strings.Compare(a.Device, b.Device); c != 0 {
			return c
		}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return bytes.Compare(x, y)
	})
	for i := 1; i < len(s.Routes); i++ {
		if s.Routes[i-1].Device == s.Routes[i].Device {
			return s, ErrPolicy
		}
	}
	return s, nil
}

func DecodeIsolation(raw string) (IsolationSpec, error) {
	var s IsolationSpec
	if len(raw) > 32<<20 || json.Unmarshal([]byte(raw), &s) != nil {
		return s, ErrPolicy
	}
	s, err := NormalizeIsolation(s)
	if err != nil {
		return s, err
	}
	canonical, _ := json.Marshal(s)
	if string(canonical) != raw {
		return s, ErrPolicy
	}
	return s, nil
}

func isolationTable(owner string) string {
	h := sha256.Sum256([]byte("mydc-isolation-1\x00" + owner))
	return "mydc_i_" + hex.EncodeToString(h[:16])
}

func IsolationExists(owner string) (bool, error) {
	if _, err := NormalizeIsolation(IsolationSpec{Schema: 1, Owner: owner}); err != nil {
		return false, err
	}
	c := &nftables.Conn{}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	for _, table := range tables {
		if table.Name == isolationTable(owner) {
			return true, nil
		}
	}
	return false, nil
}

func isolationRules(s IsolationSpec) tunnelFirewall {
	table := &nftables.Table{Name: isolationTable(s.Owner), Family: nftables.TableFamilyINet}
	f := tunnelFirewall{table: table, rules: map[string][]*nftables.Rule{}}
	raw, _ := json.Marshal(s)
	hash := sha256.Sum256(raw)
	alias := []byte("mydc-isolation-1:" + hex.EncodeToString(hash[:]))
	accept := nftables.ChainPolicyAccept
	priority := nftables.ChainPriority(-10)
	input := &nftables.Chain{Name: "input", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: &priority, Policy: &accept}
	forward := &nftables.Chain{Name: "forward", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookForward, Priority: &priority, Policy: &accept}
	f.chains = append(f.chains, input, forward)
	add := func(chain *nftables.Chain, expressions ...expr.Any) {
		f.rules[chain.Name] = append(f.rules[chain.Name], &nftables.Rule{Table: table, Chain: chain, Exprs: expressions, UserData: alias})
	}
	iface := func(key expr.MetaKey, device string) []expr.Any {
		name := make([]byte, 16)
		copy(name, device)
		return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name}}
	}
	prefixMatch := func(prefix netip.Prefix, destination bool) []expr.Any {
		family, offset, length := byte(unix.NFPROTO_IPV6), uint32(8), uint32(16)
		if prefix.Addr().Is4() {
			family, offset, length = unix.NFPROTO_IPV4, 12, 4
		}
		if destination {
			offset += length
		}
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: prefixNet(prefix).Mask, Xor: make([]byte, length)}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: prefix.Addr().AsSlice()}}
	}
	for index, b := range s.Bridges {
		if b.Managed {
			for _, expressions := range isolationNeighborRules(b, iface, prefixMatch) {
				add(input, expressions...)
				rule := append(iface(expr.MetaKeyOIFNAME, b.Device), expressions...)
				add(forward, rule...)
			}
			for _, expressions := range isolationLocalInputRules(s, b, iface, prefixMatch) {
				add(input, expressions...)
			}
		}
		for _, out := range []bool{true, false} {
			name := "in_"
			meta, otherMeta := expr.MetaKeyOIFNAME, expr.MetaKeyIIFNAME
			if out {
				name = "out_"
				meta, otherMeta = expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME
			}
			chain := &nftables.Chain{Name: fmtIsolationChain(name, index), Table: table}
			f.chains = append(f.chains, chain)
			jump := append(iface(meta, b.Device), &expr.Verdict{Kind: expr.VerdictJump, Chain: chain.Name})
			add(forward, jump...)
			if out {
				add(input, jump...)
			}
			if b.Managed {
				addressName := "dst_"
				if out {
					addressName = "src_"
				}
				address := &nftables.Chain{Name: fmtIsolationChain(addressName, index), Table: table}
				f.chains = append(f.chains, address)
				for _, prefix := range b.Prefixes {
					add(address, append(prefixMatch(prefix, !out), &expr.Verdict{Kind: expr.VerdictReturn})...)
				}
				add(address, &expr.Verdict{Kind: expr.VerdictDrop})
				add(chain, &expr.Verdict{Kind: expr.VerdictJump, Chain: address.Name})
			}
			for _, route := range s.Routes {
				if route.Policy.Bridge != b.Device {
					continue
				}
				for _, match := range routePacketRules(route.Policy, out) {
					rule := append(iface(otherMeta, route.Device), match...)
					add(chain, rule...)
				}
			}
			for _, prefix := range s.Prefixes {
				if prefix.Tenant == b.Tenant {
					continue
				}
				add(chain, append(prefixMatch(prefix.Prefix, out), &expr.Verdict{Kind: expr.VerdictDrop})...)
			}
			if b.Managed {
				for _, rule := range isolationManagedTraffic(s, b, out, iface, prefixMatch) {
					add(chain, rule...)
				}
			} else {
				add(chain, &expr.Verdict{Kind: expr.VerdictReturn})
			}
		}
	}
	for index, b := range s.Bridges {
		if !b.Managed {
			continue
		}
		chain := &nftables.Chain{Name: fmtIsolationChain("gateway_", index), Table: table}
		f.chains = append(f.chains, chain)
		for _, prefix := range b.Prefixes {
			add(input, append(prefixMatch(prefix, true), &expr.Verdict{Kind: expr.VerdictJump, Chain: chain.Name})...)
		}
		for _, rule := range isolationManagedTraffic(s, b, false, iface, prefixMatch) {
			add(chain, rule...)
		}
	}
	// Local gateway/DNS addresses take INPUT rather than FORWARD. Aggregate
	// by tenant so multiple local Bridges cannot veto each other's exact TUN
	// exception, while a foreign source on an ordinary TUN is still denied.
	var tenants []string
	for _, b := range s.Bridges {
		tenants = append(tenants, b.Tenant)
	}
	slices.Sort(tenants)
	tenants = slices.Compact(tenants)
	for index, tenant := range tenants {
		chain := &nftables.Chain{Name: fmtIsolationChain("host_", index), Table: table}
		f.chains = append(f.chains, chain)
		for _, p := range s.Prefixes {
			if p.Tenant == tenant {
				add(input, append(prefixMatch(p.Prefix, true), &expr.Verdict{Kind: expr.VerdictJump, Chain: chain.Name})...)
			}
		}
		for _, route := range s.Routes {
			local := false
			for _, b := range s.Bridges {
				local = local || b.Tenant == tenant && b.Device == route.Policy.Bridge
			}
			if !local {
				continue
			}
			for _, match := range routePacketRules(route.Policy, false) {
				add(chain, append(iface(expr.MetaKeyIIFNAME, route.Device), match...)...)
			}
		}
		for _, p := range s.Prefixes {
			if p.Tenant != tenant {
				add(chain, append(prefixMatch(p.Prefix, false), &expr.Verdict{Kind: expr.VerdictDrop})...)
			}
		}
		add(chain, &expr.Verdict{Kind: expr.VerdictReturn})
	}
	// Owner marker also makes an otherwise empty definition distinguishable
	// from a foreign table at the same name.
	add(input, &expr.Verdict{Kind: expr.VerdictReturn})
	add(forward, &expr.Verdict{Kind: expr.VerdictReturn})
	return f
}

func fmtIsolationChain(prefix string, index int) string {
	return prefix + hex.EncodeToString([]byte{byte(index >> 8), byte(index)})
}

// InspectIsolation only reads this exact owner's table; it neither repairs an
// absent table nor treats a foreign definition as an applied policy.
func InspectIsolation(s IsolationSpec) (bool, error) {
	if err := canonicalIsolation(s); err != nil {
		return false, err
	}
	_, table, err := lookupOwnedFirewall(isolationRules(s))
	return table != nil, err
}

// ApplyIsolation atomically replaces only the exact original/target table.
// create is false for recovery of an already dispatched operation.
func ApplyIsolation(ctx context.Context, previous *IsolationSpec, target IsolationSpec, create bool) error {
	if err := canonicalIsolation(target); err != nil {
		return err
	}
	if previous != nil {
		if err := canonicalIsolation(*previous); err != nil {
			return err
		}
		if previous.Owner != target.Owner {
			return ErrKernelOwnership
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	want := isolationRules(target)
	c, table, err := lookupOwnedFirewall(want)
	if err == nil && table != nil {
		return nil
	}
	if err != nil {
		if previous == nil {
			return err
		}
		c, table, err = lookupOwnedFirewall(isolationRules(*previous))
		if err != nil {
			return err
		}
	}
	if table == nil && (!create || previous != nil) {
		return ErrKernelOwnership
	}
	if table != nil {
		c.DelTable(table)
	}
	c.AddTable(want.table)
	for _, chain := range want.chains {
		c.AddChain(chain)
	}
	// Jump targets must exist when the kernel processes each rule, even
	// within one atomic batch. Base chains can reference later child chains.
	for _, chain := range want.chains {
		for _, rule := range want.rules[chain.Name] {
			c.AddRule(rule)
		}
	}
	if err := c.Flush(); err != nil {
		return err
	}
	present, err := InspectIsolation(target)
	if !present {
		return errors.Join(err, ErrKernelOwnership)
	}
	return err
}

func RemoveIsolation(ctx context.Context, original IsolationSpec) error {
	if err := canonicalIsolation(original); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c, table, err := lookupOwnedFirewall(isolationRules(original))
	if err != nil || table == nil {
		return err
	}
	c.DelTable(table)
	if err := c.Flush(); err != nil {
		return err
	}
	present, err := InspectIsolation(original)
	if present {
		return errors.Join(err, ErrKernelOwnership)
	}
	return err
}

func canonicalIsolation(s IsolationSpec) error {
	normalized, err := NormalizeIsolation(s)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(s)
	b, _ := json.Marshal(normalized)
	if !bytes.Equal(a, b) {
		return ErrPolicy
	}
	return nil
}
