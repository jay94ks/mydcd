// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// Real is the kernel's netfilter, reached over netlink (no iptables or nft
// program). sfcd writes into the "filter" tables iptables-nft uses, in the
// shapes iptables-nft writes, so the operator's own iptables keeps reading
// and changing the same tables (devel/design/node-firewall.md).
var Real Host = netlinkHost{}

// ErrLegacy is a server whose rules are in iptables-legacy (x_tables):
// sfcd cannot place its chain before them over nftables.
var ErrLegacy = errors.New("this server uses iptables-legacy (x_tables tables are in use): sfcd controls the firewall only through nftables (iptables-nft); switch with update-alternatives --set iptables /usr/sbin/iptables-nft, or turn firewall.managed off")

type netlinkHost struct{}

func tableFamily(family int) nftables.TableFamily {
	if family == 6 {
		return nftables.TableFamilyIPv6
	}
	return nftables.TableFamilyIPv4
}

// legacy says whether x_tables (iptables-legacy) tables are loaded.
func legacy() bool {
	for _, f := range []string{"/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"} {
		if b, err := os.ReadFile(f); err == nil && len(bytes.TrimSpace(b)) > 0 {
			return true
		}
	}
	return false
}

func conn() (*nftables.Conn, error) { return nftables.New() }

// filterChains finds family's filter table and its INPUT and SFC-INPUT
// chains; any of them may be missing.
func filterChains(c *nftables.Conn, family int) (*nftables.Table, *nftables.Chain, *nftables.Chain, error) {
	fam := tableFamily(family)
	tables, err := c.ListTablesOfFamily(fam)
	if err != nil {
		return nil, nil, nil, err
	}
	var table *nftables.Table
	for _, t := range tables {
		if t.Name == "filter" {
			table = t
		}
	}
	if table == nil {
		return nil, nil, nil, nil
	}
	chains, err := c.ListChainsOfTableFamily(fam)
	if err != nil {
		return nil, nil, nil, err
	}
	var input, own *nftables.Chain
	for _, ch := range chains {
		if ch.Table.Name != "filter" {
			continue
		}
		switch ch.Name {
		case "INPUT":
			input = ch
		case Chain:
			own = ch
		}
	}
	return table, input, own, nil
}

func isJump(r *nftables.Rule) bool {
	for _, e := range r.Exprs {
		if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictJump && v.Chain == Chain {
			return true
		}
	}
	return false
}

func (netlinkHost) State(ctx context.Context, family int) (ChainState, error) {
	if legacy() {
		return ChainState{}, ErrLegacy
	}
	c, err := conn()
	if err != nil {
		return ChainState{}, err
	}
	defer c.CloseLasting()
	table, input, own, err := filterChains(c, family)
	if err != nil || table == nil {
		return ChainState{}, err
	}
	var st ChainState
	if input != nil {
		rules, err := c.GetRules(table, input)
		if err != nil {
			return st, err
		}
		for i, r := range rules {
			if isJump(r) {
				st.Jumps++
				st.First = st.First || i == 0
			}
		}
	}
	if own != nil {
		st.Exists = true
		rules, err := c.GetRules(table, own)
		if err != nil {
			return st, err
		}
		st.Count = len(rules)
		if len(rules) > 0 {
			for _, e := range rules[0].Exprs {
				if m, ok := e.(*expr.Match); ok && m.Name == "comment" {
					if cm, ok := m.Info.(*xt.Comment); ok {
						st.Marker = string(*cm)
					}
				}
			}
		}
	}
	return st, nil
}

func (netlinkHost) Write(ctx context.Context, plan map[int][]Line) error {
	if legacy() {
		return ErrLegacy
	}
	c, err := conn()
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	for _, family := range Families {
		lines, ok := plan[family]
		if !ok {
			continue
		}
		table, input, own, err := filterChains(c, family)
		if err != nil {
			return err
		}
		if lines == nil {
			if table == nil {
				continue
			}
			if err := dropJumps(c, table, input); err != nil {
				return err
			}
			if own != nil {
				c.FlushChain(own)
				c.DelChain(own)
			}
			continue
		}
		rules := make([][]expr.Any, len(lines))
		for i, l := range lines {
			if rules[i], err = lineExprs(family, l); err != nil {
				return err
			}
		}
		if table == nil {
			table = c.AddTable(&nftables.Table{Family: tableFamily(family), Name: "filter"})
		}
		if input == nil {
			// The base chain iptables-nft itself would create.
			accept := nftables.ChainPolicyAccept
			input = c.AddChain(&nftables.Chain{Name: "INPUT", Table: table, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &accept})
		} else if err := dropJumps(c, table, input); err != nil {
			return err
		}
		if own == nil {
			own = c.AddChain(&nftables.Chain{Name: Chain, Table: table})
		} else {
			c.FlushChain(own)
		}
		for _, e := range rules {
			c.AddRule(&nftables.Rule{Table: table, Chain: own, Exprs: e})
		}
		c.InsertRule(&nftables.Rule{Table: table, Chain: input, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictJump, Chain: Chain}}})
	}
	// One batch: every family commits together or not at all.
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	return nil
}

func dropJumps(c *nftables.Conn, table *nftables.Table, input *nftables.Chain) error {
	if input == nil {
		return nil
	}
	rules, err := c.GetRules(table, input)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if isJump(r) {
			if err := c.DelRule(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// lineExprs is l in the expressions iptables-nft writes for the same
// iptables line (payload and meta for addresses, protocols, ports and
// interfaces; xt matches for conntrack, icmp6 and comment).
func lineExprs(family int, l Line) ([]expr.Any, error) {
	out := []expr.Any{}
	cmp := func(data []byte) *expr.Cmp { return &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data} }
	if l.Src != "" {
		p, err := netip.ParsePrefix(l.Src)
		if err != nil {
			return nil, err
		}
		offset, size := uint32(12), 4
		if family == 6 {
			offset, size = 8, 16
		}
		addr := p.Masked().Addr().AsSlice()
		bits := p.Bits()
		switch {
		case bits == 0:
		case bits%8 == 0:
			n := bits / 8
			out = append(out, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(n)}, cmp(addr[:n]))
		default:
			mask := net.CIDRMask(bits, size*8)
			out = append(out, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(size)},
				&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(size), Mask: mask, Xor: make([]byte, size)}, cmp(addr))
		}
	}
	if l.Iface != "" {
		name := []byte(l.Iface + "\x00")
		if strings.HasSuffix(l.Iface, "+") {
			name = []byte(strings.TrimSuffix(l.Iface, "+"))
		}
		out = append(out, &expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1}, cmp(name))
	}
	if l.Proto != "" {
		number := map[string]byte{"tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58}[l.Proto]
		if number == 0 {
			return nil, fmt.Errorf("firewall: protocol %q", l.Proto)
		}
		if family == 6 {
			out = append(out, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, cmp([]byte{number}))
		} else {
			out = append(out, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1}, cmp([]byte{number}))
		}
	}
	if l.PortLo != 0 {
		port := &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}
		lo, hi := []byte{byte(l.PortLo >> 8), byte(l.PortLo)}, []byte{byte(l.PortHi >> 8), byte(l.PortHi)}
		if l.PortHi == l.PortLo {
			out = append(out, port, cmp(lo))
		} else {
			out = append(out, port, &expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: lo, ToData: hi})
		}
	}
	if l.ICMPv6 != 0 {
		// The native form iptables-nft reads back as -m icmp6 (an xt icmp6
		// match would need the rule's compat protocol).
		out = append(out, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1}, cmp([]byte{l.ICMPv6}))
	}
	if l.Established {
		zero, mask := net.IPv4zero.To4(), net.IPMask(net.IPv4zero.To4())
		if family == 6 {
			zero, mask = net.IPv6zero, net.IPMask(net.IPv6zero)
		}
		base := xt.ConntrackMtinfoBase{OrigSrcAddr: zero, OrigSrcMask: mask, OrigDstAddr: zero, OrigDstMask: mask, ReplSrcAddr: zero, ReplSrcMask: mask, ReplDstAddr: zero, ReplDstMask: mask, MatchFlags: 1}
		info := xt.ConntrackMtinfo3{ConntrackMtinfo2: xt.ConntrackMtinfo2{ConntrackMtinfoBase: base, StateMask: 0x6}}
		out = append(out, &expr.Match{Name: "conntrack", Rev: 3, Info: &info})
	}
	if l.Comment != "" {
		cm := xt.Comment(l.Comment)
		out = append(out, &expr.Match{Name: "comment", Rev: 0, Info: &cm})
	}
	out = append(out, &expr.Counter{})
	switch l.Target {
	case "":
	case "ACCEPT":
		out = append(out, &expr.Verdict{Kind: expr.VerdictAccept})
	case "DROP":
		out = append(out, &expr.Verdict{Kind: expr.VerdictDrop})
	case "RETURN":
		out = append(out, &expr.Verdict{Kind: expr.VerdictReturn})
	default:
		return nil, fmt.Errorf("firewall: target %q", l.Target)
	}
	return out, nil
}

func (netlinkHost) Operator(ctx context.Context) ([]string, bool, error) {
	if legacy() {
		return nil, false, ErrLegacy
	}
	c, err := conn()
	if err != nil {
		return nil, false, err
	}
	defer c.CloseLasting()
	chains, err := c.ListChains()
	if err != nil {
		return nil, false, err
	}
	return operatorLines(chains, func(ch *nftables.Chain) ([]*nftables.Rule, error) { return c.GetRules(ch.Table, ch) })
}
