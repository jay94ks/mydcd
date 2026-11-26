// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"errors"
	"reflect"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

type tunnelFirewall struct {
	table  *nftables.Table
	chains []*nftables.Chain
	rules  map[string][]*nftables.Rule
}

func tunnelRules(s TunnelSpec, id tunnelIdentity) tunnelFirewall {
	return tunnelRulesMode(s, id, false)
}

func tunnelRulesMode(s TunnelSpec, id tunnelIdentity, fenced bool) tunnelFirewall {
	t := &nftables.Table{Name: id.table, Family: nftables.TableFamilyINet}
	f := tunnelFirewall{table: t, rules: make(map[string][]*nftables.Rule)}
	for _, name := range []string{"from", "to"} {
		f.chains = append(f.chains, &nftables.Chain{Name: name, Table: t})
	}
	accept := nftables.ChainPolicyAccept
	for _, h := range []struct {
		name string
		hook *nftables.ChainHook
	}{{"input", nftables.ChainHookInput}, {"forward", nftables.ChainHookForward}, {"output", nftables.ChainHookOutput}} {
		f.chains = append(f.chains, &nftables.Chain{Name: h.name, Table: t, Type: nftables.ChainTypeFilter, Hooknum: h.hook, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	}
	add := func(c *nftables.Chain, expressions ...expr.Any) {
		f.rules[c.Name] = append(f.rules[c.Name], &nftables.Rule{Table: t, Chain: c, Exprs: expressions, UserData: []byte(id.alias)})
	}
	for _, c := range f.chains {
		if c.Name != "from" && c.Name != "to" {
			for _, direction := range []struct {
				meta expr.MetaKey
				jump string
				skip bool
			}{{expr.MetaKeyIIFNAME, "from", c.Name == "output"}, {expr.MetaKeyOIFNAME, "to", c.Name == "input"}} {
				if direction.skip {
					continue
				}
				name := make([]byte, 16)
				copy(name, id.name)
				add(c, &expr.Meta{Key: direction.meta, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: name}, &expr.Verdict{Kind: expr.VerdictJump, Chain: direction.jump})
			}
			continue
		}
		if s.RoutePolicy != nil {
			if !fenced {
				for _, expressions := range routePacketRules(*s.RoutePolicy, c.Name == "to") {
					add(c, expressions...)
				}
			}
			add(c, &expr.Verdict{Kind: expr.VerdictDrop})
			continue
		}
		for _, p := range s.Routes {
			family, offset := byte(unix.NFPROTO_IPV6), uint32(8)
			if p.Addr().Is4() {
				family, offset = unix.NFPROTO_IPV4, 12
			}
			address := p.Addr().AsSlice()
			if c.Name == "to" {
				offset += uint32(len(address))
			}
			mask := prefixNet(p).Mask
			add(c, &expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(address))},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(address)), Mask: []byte(mask), Xor: make([]byte, len(address))},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: address}, &expr.Verdict{Kind: expr.VerdictReturn})
		}
		add(c, &expr.Verdict{Kind: expr.VerdictDrop})
	}
	if hasRouteSelector(s) {
		addRouteSelectorFirewallMode(&f, s, id, !fenced)
	}
	return f
}

func lookupTunnelFirewall(s TunnelSpec, id tunnelIdentity) (*nftables.Conn, *nftables.Table, error) {
	return lookupTunnelFirewallMode(s, id, false)
}

func lookupTunnelFirewallMode(s TunnelSpec, id tunnelIdentity, fenced bool) (*nftables.Conn, *nftables.Table, error) {
	return lookupOwnedFirewall(tunnelRulesMode(s, id, fenced))
}

func lookupOwnedFirewall(want tunnelFirewall) (*nftables.Conn, *nftables.Table, error) {
	return lookupOwnedFirewallRoutes(want, false)
}

// routeChain: the per-route accept chains of a tunnel without a route policy.
func routeChain(name string) bool { return name == "from" || name == "to" }

// lookupOwnedFirewallRoutes with anyRoutes accepts any rule list in the
// route chains as long as every rule carries this owner's alias. It proves the
// table is this tunnel's own before its route rules are rewritten in place.
func lookupOwnedFirewallRoutes(want tunnelFirewall, anyRoutes bool) (*nftables.Conn, *nftables.Table, error) {
	c := &nftables.Conn{}
	tables, err := c.ListTablesOfFamily(want.table.Family)
	if err != nil {
		return nil, nil, err
	}
	var table *nftables.Table
	for _, t := range tables {
		if t.Name == want.table.Name {
			if table != nil || t.Flags != 0 {
				return nil, nil, ErrKernelOwnership
			}
			table = t
		}
	}
	if table == nil {
		return c, nil, nil
	}
	sets, err := c.GetSets(table)
	if err != nil {
		return nil, nil, err
	}
	if len(sets) != 0 {
		return nil, nil, ErrKernelOwnership
	}
	chains, err := c.ListChains()
	if err != nil {
		return nil, nil, err
	}
	count := 0
	for _, got := range chains {
		if got.Table.Name != table.Name || got.Table.Family != table.Family {
			continue
		}
		count++
		var expected *nftables.Chain
		for _, ch := range want.chains {
			if ch.Name == got.Name {
				expected = ch
			}
		}
		if expected == nil || expected.Type != got.Type || expected.Device != got.Device || !reflect.DeepEqual(expected.Hooknum, got.Hooknum) || !reflect.DeepEqual(expected.Priority, got.Priority) || !reflect.DeepEqual(expected.Policy, got.Policy) {
			return nil, nil, ErrKernelOwnership
		}
		rules, err := c.GetRules(table, got)
		if err != nil {
			return nil, nil, err
		}
		if anyRoutes && routeChain(got.Name) {
			alias := want.rules[got.Name][0].UserData
			for _, r := range rules {
				if !bytes.Equal(r.UserData, alias) {
					return nil, nil, ErrKernelOwnership
				}
			}
			continue
		}
		if len(rules) != len(want.rules[got.Name]) {
			return nil, nil, ErrKernelOwnership
		}
		for i, r := range rules {
			expected := want.rules[got.Name][i]
			if !bytes.Equal(r.UserData, expected.UserData) || !reflect.DeepEqual(r.Exprs, expected.Exprs) {
				return nil, nil, ErrKernelOwnership
			}
		}
	}
	if count != len(want.chains) {
		return nil, nil, ErrKernelOwnership
	}
	return c, table, nil
}

func inspectTunnelFirewall(s TunnelSpec, id tunnelIdentity) (bool, error) {
	_, t, err := lookupTunnelFirewall(s, id)
	return t != nil, err
}
func ensureTunnelFirewall(s TunnelSpec, id tunnelIdentity) error {
	c, t, err := lookupTunnelFirewall(s, id)
	if errors.Is(err, ErrKernelOwnership) && s.RoutePolicy == nil {
		return rewriteTunnelRouteRules(s, id)
	}
	if err != nil || t != nil {
		return err
	}
	want := tunnelRules(s, id)
	c.AddTable(want.table)
	for _, chain := range want.chains {
		c.AddChain(chain)
		for _, rule := range want.rules[chain.Name] {
			c.AddRule(rule)
		}
	}
	if err := c.Flush(); err != nil {
		return err
	}
	present, err := inspectTunnelFirewall(s, id)
	if !present {
		return errors.Join(err, ErrKernelOwnership)
	}
	return err
}

// rewriteTunnelRouteRules replaces the accept rules of the route chains with
// the spec's route set in one nft batch, so no packet sees an empty chain. Only
// the tunnel's own table qualifies: same chains, hook rules and alias.
func rewriteTunnelRouteRules(s TunnelSpec, id tunnelIdentity) error {
	want := tunnelRules(s, id)
	c, t, err := lookupOwnedFirewallRoutes(want, true)
	if err != nil || t == nil {
		return errors.Join(err, ErrKernelOwnership)
	}
	for _, chain := range want.chains {
		if !routeChain(chain.Name) {
			continue
		}
		c.FlushChain(chain)
		for _, rule := range want.rules[chain.Name] {
			c.AddRule(rule)
		}
	}
	if err = c.Flush(); err != nil {
		return err
	}
	present, err := inspectTunnelFirewall(s, id)
	if !present {
		return errors.Join(err, ErrKernelOwnership)
	}
	return err
}

func removeTunnelFirewall(s TunnelSpec, id tunnelIdentity) error {
	c, t, err := lookupTunnelFirewallEither(s, id)
	if err != nil || t == nil {
		return err
	}
	c.DelTable(t)
	return c.Flush()
}

func lookupTunnelFirewallEither(s TunnelSpec, id tunnelIdentity) (*nftables.Conn, *nftables.Table, error) {
	c, table, err := lookupTunnelFirewall(s, id)
	if err == nil || s.RoutePolicy == nil {
		return c, table, err
	}
	c, table, fencedErr := lookupTunnelFirewallMode(s, id, true)
	if fencedErr != nil {
		return nil, nil, errors.Join(err, fencedErr)
	}
	return c, table, nil
}

// Same original identity/spec, a monotonic retirement mode. Chain replacement
// is one nft batch after exact serving-mode ownership/readback. No foreign
// table/rule is adopted and no empty-policy interval is published.
func fenceTunnelFirewall(s TunnelSpec, id tunnelIdentity) error {
	if s.RoutePolicy == nil {
		return ErrPolicy
	}
	if _, table, err := lookupTunnelFirewallMode(s, id, true); err == nil && table != nil {
		return nil
	}
	c, table, err := lookupTunnelFirewall(s, id)
	if err != nil || table == nil {
		return errors.Join(err, ErrKernelOwnership)
	}
	want := tunnelRulesMode(s, id, true)
	for _, chain := range want.chains {
		rules, err := c.GetRules(table, chain)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if err := c.DelRule(rule); err != nil {
				return err
			}
		}
		for _, rule := range want.rules[chain.Name] {
			c.AddRule(rule)
		}
	}
	if err := c.Flush(); err != nil {
		return err
	}
	_, table, err = lookupTunnelFirewallMode(s, id, true)
	if err != nil || table == nil {
		return errors.Join(err, ErrKernelOwnership)
	}
	return nil
}
