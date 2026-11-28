// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Port is one port the locked rules keep open.
type Port struct {
	Proto  string // tcp or udp
	Port   uint16
	From   []string // source prefixes; empty: anywhere (keep-open only)
	Reason string   // sfcp, keep-open or ingress
}

// Locks are what stays open whatever the operator rules say: sfcd's own
// SFCP port, node.yaml keep_open and this server's ingress listeners.
type Locks struct {
	Ports []Port
}

// Locked is one locked rule as the show reply lists it.
type Locked struct {
	Name   string
	Proto  string   `json:",omitempty"`
	Port   uint16   `json:",omitempty"`
	From   []string `json:",omitempty"`
	Reason string
}

// Families: 4 is iptables, 6 is ip6tables.
var Families = []int{4, 6}

// List is the locked rules in the order SFC-INPUT checks them.
func (l Locks) List() []Locked {
	out := []Locked{
		{Name: "established", Reason: "replies to connections already open"},
		{Name: "loopback", Reason: "the server talking to itself (lo)"},
		{Name: "sfc-devices", Reason: "Seafield bridges (md*) and TUN networks (mt*); their isolation rules decide"},
		{Name: "icmpv6-neighbor", Reason: "IPv6 neighbor discovery and packet-too-big"},
	}
	for _, p := range l.sorted() {
		out = append(out, Locked{Name: p.Reason, Proto: p.Proto, Port: p.Port, From: p.From, Reason: map[string]string{"sfcp": "SFCP between servers and remote CLI", "keep-open": "node.yaml firewall.keep_open", "ingress": "an ingress listener on this server"}[p.Reason]})
	}
	return out
}

func (l Locks) sorted() []Port {
	seen := map[string]bool{}
	out := []Port{}
	for _, p := range l.Ports {
		k := p.Proto + "/" + strconv.Itoa(int(p.Port)) + " " + strings.Join(p.From, ",")
		if p.Port == 0 || p.Proto != "tcp" && p.Proto != "udp" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}

// Line is one SFC-INPUT rule. sfcd writes it to the kernel over netlink in
// the shape iptables-nft itself uses, so `iptables -S SFC-INPUT` prints
// String on a server that has iptables.
type Line struct {
	Src         string // source prefix
	Iface       string // input interface; a trailing + matches a prefix
	Proto       string // tcp, udp, icmp or ipv6-icmp
	PortLo      uint16 // destination port (tcp, udp)
	PortHi      uint16
	ICMPv6      uint8 // ICMPv6 type (ipv6-icmp); 0: any
	Established bool  // conntrack RELATED,ESTABLISHED
	Comment     string
	Target      string // ACCEPT, DROP or RETURN; empty: the marker
}

// String is the line as `iptables -S` prints it, without "-A SFC-INPUT".
func (l Line) String() string {
	parts := []string{}
	if l.Src != "" {
		parts = append(parts, "-s "+l.Src)
	}
	if l.Iface != "" {
		parts = append(parts, "-i "+l.Iface)
	}
	if l.Proto != "" {
		parts = append(parts, "-p "+l.Proto)
	}
	if l.PortLo != 0 {
		ports := strconv.Itoa(int(l.PortLo))
		if l.PortHi != l.PortLo {
			ports += ":" + strconv.Itoa(int(l.PortHi))
		}
		parts = append(parts, "-m "+l.Proto+" --dport "+ports)
	}
	if l.ICMPv6 != 0 {
		parts = append(parts, "-m icmp6 --icmpv6-type "+strconv.Itoa(int(l.ICMPv6)))
	}
	if l.Established {
		parts = append(parts, "-m conntrack --ctstate RELATED,ESTABLISHED")
	}
	if l.Comment != "" {
		parts = append(parts, "-m comment --comment \""+l.Comment+"\"")
	}
	if l.Target != "" {
		parts = append(parts, "-j "+l.Target)
	}
	return strings.Join(parts, " ")
}

// icmpv6Types are the ICMPv6 types the locked rules let in: packet-too-big,
// router solicitation and advertisement, neighbour solicitation and
// advertisement.
var icmpv6Types = []uint8{2, 133, 134, 135, 136}

// Rules are the SFC-INPUT rules for one family. The first is a no-target
// marker carrying the digest of the rest, so a later check can tell the
// chain is still ours.
//
// Order: locks, cluster required deny and allow, server deny and allow,
// cluster deny and allow, then the effective policy. A server rule wins over
// a cluster rule, a required cluster rule over both.
func Rules(family int, ls Layers, l Locks) []Line {
	body := []Line{
		{Established: true, Target: "ACCEPT"},
		{Iface: "lo", Target: "ACCEPT"},
		{Iface: "md+", Target: "RETURN"},
		{Iface: "mt+", Target: "RETURN"},
	}
	if family == 6 {
		for _, t := range icmpv6Types {
			body = append(body, Line{Proto: "ipv6-icmp", ICMPv6: t, Target: "ACCEPT"})
		}
	}
	for _, p := range l.sorted() {
		for _, src := range sources(family, p.From) {
			body = append(body, Line{Src: src, Proto: p.Proto, PortLo: p.Port, PortHi: p.Port, Comment: "sfc lock " + p.Reason, Target: "ACCEPT"})
		}
	}
	pass := func(s State, required bool) {
		for _, action := range []string{"deny", "allow"} {
			for _, r := range s.Rules {
				if r.Action == action && r.Required == required {
					body = append(body, ruleLines(family, r)...)
				}
			}
		}
	}
	pass(ls.Cluster, true)
	pass(ls.Node, false)
	pass(ls.Cluster, false)
	if Effective(ls.Node, ls.Cluster) == PolicyDrop {
		body = append(body, Line{Comment: "sfc policy drop", Target: "DROP"})
	}
	text := make([]string, len(body))
	for i, b := range body {
		text[i] = b.String()
	}
	h := sha256.Sum256([]byte(strings.Join(text, "\n")))
	marker := Line{Comment: fmt.Sprintf("sfc revision %d/%d %s", ls.Node.Revision, ls.Cluster.Revision, hex.EncodeToString(h[:8]))}
	return append([]Line{marker}, body...)
}

// Lines are Rules as `iptables -S` text.
func Lines(family int, ls Layers, l Locks) []string {
	rules := Rules(family, ls, l)
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.String()
	}
	return out
}

// sources are the prefixes of from that belong to family; [""] is anywhere.
// A list with no prefix of this family matches nothing here.
func sources(family int, from []string) []string {
	if len(from) == 0 {
		return []string{""}
	}
	out := []string{}
	for _, f := range from {
		p, _ := netip.ParsePrefix(f)
		if p.Addr().Is4() == (family == 4) {
			out = append(out, f)
		}
	}
	return out
}

func ruleLines(family int, r Rule) []Line {
	base := Line{Comment: "sfc " + r.ID, Target: "ACCEPT"}
	if r.Action == "deny" {
		base.Target = "DROP"
	}
	switch r.Proto {
	case "tcp", "udp":
		base.Proto = r.Proto
		base.PortLo, base.PortHi, _ = PortRange(r.Ports)
	case "icmp":
		base.Proto = "icmp"
		if family == 6 {
			base.Proto = "ipv6-icmp"
		}
	}
	out := []Line{}
	for _, src := range sources(family, r.From) {
		l := base
		l.Src = src
		out = append(out, l)
	}
	return out
}

// ChainState is what a family's filter table holds of sfcd's chain.
type ChainState struct {
	Exists bool
	Marker string // comment of the first SFC-INPUT rule
	Count  int    // SFC-INPUT rules
	Jumps  int    // rules in INPUT that jump to SFC-INPUT
	First  bool   // INPUT's first rule is such a jump
}

// OperatorLimit bounds the operator lines one show returns.
const OperatorLimit = 400

// Host is the kernel's netfilter for sfcd's chain. Tests replace it.
type Host interface {
	// State reads family's SFC-INPUT and its jumps.
	State(ctx context.Context, family int) (ChainState, error)
	// Write changes every family in plan in one transaction: lines makes
	// SFC-INPUT hold exactly them with one jump at the top of INPUT; nil
	// takes the jump and the chain out. Nothing else changes.
	Write(ctx context.Context, plan map[int][]Line) error
	// Operator is every input-hook chain of the server's other rules (and
	// the chains they jump to) as readable lines; read only.
	Operator(ctx context.Context) (lines []string, truncated bool, err error)
}

// Installed says whether family's SFC-INPUT already holds exactly lines
// with its jump first in INPUT.
func Installed(ctx context.Context, h Host, family int, lines []string) (bool, error) {
	st, err := h.State(ctx, family)
	if err != nil || !st.Exists {
		return false, err
	}
	// Only the marker (with the digest of what was written) and the count
	// are compared.
	return st.Jumps == 1 && st.First && st.Count == len(lines) && st.Marker == markerText(lines[0]), nil
}

func markerText(marker string) string {
	_, after, _ := strings.Cut(marker, "--comment ")
	return strings.Trim(after, "\"")
}

// Apply puts ls into SFC-INPUT for every family in one transaction: the
// server is never left half changed.
func Apply(ctx context.Context, h Host, ls Layers, l Locks) error {
	plan := map[int][]Line{}
	for _, family := range Families {
		plan[family] = Rules(family, ls, l)
	}
	return h.Write(ctx, plan)
}

// Remove takes the jump and SFC-INPUT out of every family; a family without
// the chain is left as it is.
func Remove(ctx context.Context, h Host) error {
	plan := map[int][]Line{}
	for _, family := range Families {
		st, err := h.State(ctx, family)
		if err != nil {
			return err
		}
		if st.Exists || st.Jumps > 0 {
			plan[family] = nil
		}
	}
	if len(plan) == 0 {
		return nil
	}
	return h.Write(ctx, plan)
}

// Operator is the server's other input rules as readable lines.
func Operator(ctx context.Context, h Host) ([]string, bool, error) {
	return h.Operator(ctx)
}
