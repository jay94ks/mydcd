// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// operatorLines lists every base chain on the input hook (any table, any
// family sfcd shows), then the chains those jump to, as readable lines in
// a form close to `nft list`. Expressions it does not know are written by
// name and value: the operator reads them. SFC-INPUT and the jump to it are
// left out, and so are sfcd's own sfc_* tables.
func operatorLines(chains []*nftables.Chain, rules func(*nftables.Chain) ([]*nftables.Rule, error)) ([]string, bool, error) {
	byName := map[string]*nftables.Chain{}
	queue := []*nftables.Chain{}
	for _, ch := range chains {
		// sfc_* tables are sfcd's own (cluster app NAT, isolation), not the
		// operator's.
		if !shownFamily(ch.Table.Family) || strings.HasPrefix(ch.Table.Name, "sfc_") {
			continue
		}
		byName[chainKey(ch.Table, ch.Name)] = ch
		if ch.Hooknum != nil && *ch.Hooknum == *nftables.ChainHookInput && ch.Type == nftables.ChainTypeFilter {
			queue = append(queue, ch)
		}
	}
	out := []string{}
	seen := map[string]bool{}
	truncated := false
	add := func(s string) bool {
		if len(out) == OperatorLimit {
			truncated = true
			return false
		}
		if len(s) > 512 {
			s = s[:512]
		}
		out = append(out, s)
		return true
	}
	for len(queue) > 0 && !truncated {
		ch := queue[0]
		queue = queue[1:]
		key := chainKey(ch.Table, ch.Name)
		if seen[key] || ch.Name == Chain && ch.Table.Name == "filter" {
			continue
		}
		seen[key] = true
		head := familyName(ch.Table.Family) + " " + ch.Table.Name + " " + ch.Name
		if ch.Hooknum != nil {
			head += fmt.Sprintf(" (hook input, priority %d, policy %s)", priority(ch), policy(ch))
		}
		if !add(head) {
			break
		}
		list, err := rules(ch)
		if err != nil {
			return out, truncated, err
		}
		for _, r := range list {
			if isJump(r) {
				continue
			}
			if !add("  " + RuleText(r.Table.Family, r.Exprs)) {
				break
			}
			for _, e := range r.Exprs {
				if v, ok := e.(*expr.Verdict); ok && (v.Kind == expr.VerdictJump || v.Kind == expr.VerdictGoto) {
					if next, ok := byName[chainKey(ch.Table, v.Chain)]; ok {
						queue = append(queue, next)
					}
				}
			}
		}
	}
	return out, truncated, nil
}

func shownFamily(f nftables.TableFamily) bool {
	return f == nftables.TableFamilyIPv4 || f == nftables.TableFamilyIPv6 || f == nftables.TableFamilyINet
}

func chainKey(t *nftables.Table, name string) string {
	return strconv.Itoa(int(t.Family)) + "/" + t.Name + "/" + name
}

func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	}
	return "family" + strconv.Itoa(int(f))
}

func priority(ch *nftables.Chain) int32 {
	if ch.Priority == nil {
		return 0
	}
	return int32(*ch.Priority)
}

func policy(ch *nftables.Chain) string {
	if ch.Policy != nil && *ch.Policy == nftables.ChainPolicyDrop {
		return "drop"
	}
	return "accept"
}

// field is what the register holds: a name and how to print a value.
type field struct {
	name string
	kind string // addr4, addr6, port, proto, iface, ctstate, number
	mask []byte
	size int
}

var protoNames = map[uint64]string{1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp", 47: "gre", 50: "esp", 132: "sctp"}

// RuleText is one rule's expressions in a form close to `nft list`.
func RuleText(family nftables.TableFamily, exprs []expr.Any) string {
	parts := []string{}
	var reg *field
	l4 := "th"
	for _, e := range exprs {
		switch v := e.(type) {
		case *expr.Payload:
			reg = payloadField(family, v, l4)
		case *expr.Meta:
			reg = metaField(v)
		case *expr.Ct:
			if v.Key == expr.CtKeySTATE {
				reg = &field{name: "ct state", kind: "ctstate"}
			} else {
				reg = &field{name: fmt.Sprintf("ct key %d", v.Key), kind: "number"}
			}
		case *expr.Bitwise:
			if reg != nil {
				reg.mask = v.Mask
			}
		case *expr.Cmp:
			name, value := "reg", hexValue(v.Data)
			if reg != nil && reg.kind == "ctstate" && len(reg.mask) == 4 && v.Op == expr.CmpOpNeq && allZero(v.Data) {
				// nft writes "ct state new,established" as (state & mask) != 0.
				parts = append(parts, "ct state "+ctStates(binary.NativeEndian.Uint32(reg.mask)))
				reg = nil
				continue
			}
			if reg != nil && reg.mask != nil && reg.kind != "addr4" && reg.kind != "addr6" {
				reg.name += " & " + hexValue(reg.mask)
			}
			if reg != nil {
				name, value = reg.name, reg.format(v.Data)
				if reg.kind == "proto" {
					l4 = value
				}
			}
			parts = append(parts, name+cmpOp(v.Op)+value)
			reg = nil
		case *expr.Range:
			name, lo, hi := "reg", hexValue(v.FromData), hexValue(v.ToData)
			if reg != nil {
				name, lo, hi = reg.name, reg.format(v.FromData), reg.format(v.ToData)
			}
			op := " "
			if v.Op == expr.CmpOpNeq {
				op = " != "
			}
			parts = append(parts, name+op+lo+"-"+hi)
			reg = nil
		case *expr.Lookup:
			name := "reg"
			if reg != nil {
				name = reg.name
			}
			not := ""
			if v.Invert {
				not = "!= "
			}
			parts = append(parts, name+" "+not+"@"+v.SetName)
			reg = nil
		case *expr.Match:
			parts = append(parts, matchText(v))
		case *expr.Target:
			parts = append(parts, "xt target "+v.Name)
		case *expr.Counter:
			parts = append(parts, "counter")
		case *expr.Log:
			parts = append(parts, "log")
		case *expr.Limit:
			parts = append(parts, fmt.Sprintf("limit rate %d/%s burst %d", v.Rate, limitUnit(v.Unit), v.Burst))
		case *expr.Reject:
			parts = append(parts, "reject")
		case *expr.Verdict:
			parts = append(parts, verdictText(v))
		default:
			parts = append(parts, strings.TrimPrefix(fmt.Sprintf("%T", e), "*expr."))
		}
	}
	return strings.Join(parts, " ")
}

func payloadField(family nftables.TableFamily, p *expr.Payload, l4 string) *field {
	switch p.Base {
	case expr.PayloadBaseNetworkHeader:
		if family == nftables.TableFamilyIPv6 {
			switch {
			case p.Offset == 8 && p.Len <= 16:
				return &field{name: "ip6 saddr", kind: "addr6", size: int(p.Len)}
			case p.Offset == 24 && p.Len <= 16:
				return &field{name: "ip6 daddr", kind: "addr6", size: int(p.Len)}
			case p.Offset == 6 && p.Len == 1:
				return &field{name: "ip6 nexthdr", kind: "proto"}
			}
		} else {
			switch {
			case p.Offset == 12 && p.Len <= 4:
				return &field{name: "ip saddr", kind: "addr4", size: int(p.Len)}
			case p.Offset == 16 && p.Len <= 4:
				return &field{name: "ip daddr", kind: "addr4", size: int(p.Len)}
			case p.Offset == 9 && p.Len == 1:
				return &field{name: "ip protocol", kind: "proto"}
			}
		}
		return &field{name: fmt.Sprintf("@nh,%d,%d", p.Offset*8, p.Len*8), kind: "number"}
	case expr.PayloadBaseTransportHeader:
		switch {
		case p.Offset == 0 && p.Len == 2:
			return &field{name: l4 + " sport", kind: "port"}
		case p.Offset == 2 && p.Len == 2:
			return &field{name: l4 + " dport", kind: "port"}
		case p.Offset == 0 && p.Len == 1 && (l4 == "icmp" || l4 == "ipv6-icmp"):
			return &field{name: l4 + " type", kind: "number"}
		}
		return &field{name: fmt.Sprintf("@th,%d,%d", p.Offset*8, p.Len*8), kind: "number"}
	}
	return &field{name: fmt.Sprintf("@ll,%d,%d", p.Offset*8, p.Len*8), kind: "number"}
}

func metaField(m *expr.Meta) *field {
	switch m.Key {
	case expr.MetaKeyIIFNAME:
		return &field{name: "iifname", kind: "iface"}
	case expr.MetaKeyOIFNAME:
		return &field{name: "oifname", kind: "iface"}
	case expr.MetaKeyL4PROTO:
		return &field{name: "meta l4proto", kind: "proto"}
	case expr.MetaKeyNFPROTO:
		return &field{name: "meta nfproto", kind: "number"}
	case expr.MetaKeyMARK:
		return &field{name: "meta mark", kind: "number"}
	case expr.MetaKeyIIF:
		return &field{name: "iif", kind: "number"}
	}
	return &field{name: fmt.Sprintf("meta key %d", m.Key), kind: "number"}
}

func (f *field) format(data []byte) string {
	switch f.kind {
	case "addr4", "addr6":
		full := 4
		if f.kind == "addr6" {
			full = 16
		}
		b := make([]byte, full)
		copy(b, data)
		addr, _ := netip.AddrFromSlice(b)
		bits := len(data) * 8
		if len(f.mask) == full {
			bits = 0
			for _, m := range f.mask {
				for ; m != 0; m <<= 1 {
					bits++
				}
			}
		}
		if bits == full*8 {
			return addr.String()
		}
		return netip.PrefixFrom(addr, bits).String()
	case "port":
		if len(data) == 2 {
			return strconv.Itoa(int(binary.BigEndian.Uint16(data)))
		}
	case "proto":
		if len(data) == 1 {
			if n, ok := protoNames[uint64(data[0])]; ok {
				return n
			}
			return strconv.Itoa(int(data[0]))
		}
	case "iface":
		s := string(data)
		if strings.HasSuffix(s, "\x00") {
			return strconv.Quote(strings.TrimRight(s, "\x00"))
		}
		return strconv.Quote(s + "*")
	case "ctstate":
		if len(data) == 4 {
			return ctStates(binary.NativeEndian.Uint32(data))
		}
	}
	if len(data) <= 4 {
		var n uint64
		for _, b := range data {
			n = n<<8 | uint64(b)
		}
		return strconv.FormatUint(n, 10)
	}
	return hexValue(data)
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func hexValue(b []byte) string { return fmt.Sprintf("0x%x", b) }

func cmpOp(op expr.CmpOp) string {
	switch op {
	case expr.CmpOpNeq:
		return " != "
	case expr.CmpOpLt:
		return " < "
	case expr.CmpOpLte:
		return " <= "
	case expr.CmpOpGt:
		return " > "
	case expr.CmpOpGte:
		return " >= "
	}
	return " "
}

// ctStates names conntrack state bits (invalid 1, established 2, related
// 4, new 8, untracked 64).
func ctStates(bits uint32) string {
	names := []string{}
	for _, s := range []struct {
		bit  uint32
		name string
	}{{1, "invalid"}, {2, "established"}, {4, "related"}, {8, "new"}, {64, "untracked"}} {
		if bits&s.bit != 0 {
			names = append(names, s.name)
		}
	}
	if len(names) == 0 {
		return strconv.FormatUint(uint64(bits), 10)
	}
	return strings.Join(names, ",")
}

func matchText(m *expr.Match) string {
	switch info := m.Info.(type) {
	case *xt.Comment:
		return "comment " + strconv.Quote(string(*info))
	case *xt.ConntrackMtinfo3:
		return "ct state " + ctStates(uint32(info.StateMask))
	case *xt.ConntrackMtinfo2:
		return "ct state " + ctStates(uint32(info.StateMask))
	case *xt.ConntrackMtinfo1:
		return "ct state " + ctStates(uint32(info.StateMask))
	case *xt.Unknown:
		if m.Name == "icmp6" && len(*info) >= 1 {
			return "icmpv6 type " + strconv.Itoa(int((*info)[0]))
		}
		if m.Name == "icmp" && len(*info) >= 1 {
			return "icmp type " + strconv.Itoa(int((*info)[0]))
		}
	}
	return "xt match " + m.Name
}

func verdictText(v *expr.Verdict) string {
	switch v.Kind {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictJump:
		return "jump " + v.Chain
	case expr.VerdictGoto:
		return "goto " + v.Chain
	case expr.VerdictQueue:
		return "queue"
	}
	return fmt.Sprintf("verdict %d", v.Kind)
}

func limitUnit(u expr.LimitTime) string {
	switch u {
	case expr.LimitTimeSecond:
		return "second"
	case expr.LimitTimeMinute:
		return "minute"
	case expr.LimitTimeHour:
		return "hour"
	case expr.LimitTimeDay:
		return "day"
	case expr.LimitTimeWeek:
		return "week"
	}
	return "unit" + strconv.Itoa(int(u))
}
