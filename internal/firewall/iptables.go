// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
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

// Lines are the SFC-INPUT rules for one family, without the chain name
// prefix "-A SFC-INPUT". The first line is a no-target marker carrying the
// digest of the rest, so a later check can tell the chain is still ours.
//
// Order: locks, cluster required deny and allow, server deny and allow,
// cluster deny and allow, then the effective policy. A server rule wins over
// a cluster rule, a required cluster rule over both.
func Lines(family int, ls Layers, l Locks) []string {
	body := []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-i lo -j ACCEPT",
		"-i md+ -j RETURN",
		"-i mt+ -j RETURN",
	}
	if family == 6 {
		for _, t := range []string{"packet-too-big", "router-solicitation", "router-advertisement", "neighbour-solicitation", "neighbour-advertisement"} {
			body = append(body, "-p ipv6-icmp -m icmp6 --icmpv6-type "+t+" -j ACCEPT")
		}
	}
	for _, p := range l.sorted() {
		for _, src := range sources(family, p.From) {
			line := ""
			if src != "" {
				line = "-s " + src + " "
			}
			body = append(body, line+fmt.Sprintf("-p %s -m %s --dport %d -m comment --comment \"sfc lock %s\" -j ACCEPT", p.Proto, p.Proto, p.Port, p.Reason))
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
		body = append(body, "-m comment --comment \"sfc policy drop\" -j DROP")
	}
	h := sha256.Sum256([]byte(strings.Join(body, "\n")))
	marker := fmt.Sprintf("-m comment --comment \"sfc revision %d/%d %s\"", ls.Node.Revision, ls.Cluster.Revision, hex.EncodeToString(h[:8]))
	return append([]string{marker}, body...)
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

func ruleLines(family int, r Rule) []string {
	match := ""
	switch r.Proto {
	case "tcp", "udp":
		lo, hi, _ := PortRange(r.Ports)
		ports := strconv.Itoa(int(lo))
		if hi != lo {
			ports += ":" + strconv.Itoa(int(hi))
		}
		match = fmt.Sprintf(" -p %s -m %s --dport %s", r.Proto, r.Proto, ports)
	case "icmp":
		match = " -p icmp"
		if family == 6 {
			match = " -p ipv6-icmp"
		}
	}
	target := "ACCEPT"
	if r.Action == "deny" {
		target = "DROP"
	}
	out := []string{}
	for _, src := range sources(family, r.From) {
		line := ""
		if src != "" {
			line = "-s " + src
		}
		line = strings.TrimSpace(line + match + " -m comment --comment \"sfc " + r.ID + "\" -j " + target)
		out = append(out, line)
	}
	return out
}

// Host runs iptables-save style reads and iptables-restore writes for one
// family. Tests replace it.
type Host interface {
	// List is `iptables -S CHAIN`; missing reports a chain that does not
	// exist.
	List(ctx context.Context, family int, chain string) (lines []string, missing bool, err error)
	// Restore is `iptables-restore --noflush` with input.
	Restore(ctx context.Context, family int, input []byte) error
}

// Real is the host's iptables and ip6tables.
var Real Host = execHost{}

type execHost struct{}

func tool(family int, restore bool) string {
	name := "iptables"
	if family == 6 {
		name = "ip6tables"
	}
	if restore {
		name += "-restore"
	}
	return name
}

func (execHost) List(ctx context.Context, family int, chain string) ([]string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, tool(family, false), "-w", "5", "-S", chain)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := errb.String()
		if strings.Contains(msg, "No chain/target/match by that name") || strings.Contains(msg, "does not exist") {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("%s -S %s: %w: %s", tool(family, false), chain, err, firstLine(msg))
	}
	lines := []string{}
	for _, l := range strings.Split(out.String(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, false, nil
}

func (execHost) Restore(ctx context.Context, family int, input []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var errb bytes.Buffer
	cmd := exec.CommandContext(ctx, tool(family, true), "-w", "5", "--noflush")
	cmd.Stdin, cmd.Stderr = bytes.NewReader(input), &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", tool(family, true), err, firstLine(errb.String()))
	}
	return nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

const jumpLine = "-A INPUT -j " + Chain

// inputJumps counts sfcd's jump lines in INPUT and says whether the first
// rule of INPUT is one.
func inputJumps(lines []string) (count int, first bool) {
	seenRule := false
	for _, l := range lines {
		if !strings.HasPrefix(l, "-A INPUT") {
			continue
		}
		if l == jumpLine {
			count++
			if !seenRule {
				first = true
			}
		}
		seenRule = true
	}
	return count, first
}

// applyInput is the iptables-restore input that makes SFC-INPUT hold lines
// and leaves exactly one jump to it at the top of INPUT. Declaring the chain
// creates it or, when it exists, flushes it; nothing else in the filter
// table changes. The whole input commits at once or not at all.
func applyInput(lines []string, jumps int) []byte {
	var b strings.Builder
	b.WriteString("*filter\n:" + Chain + " - [0:0]\n")
	for _, l := range lines {
		b.WriteString("-A " + Chain + " " + l + "\n")
	}
	for i := 0; i < jumps; i++ {
		b.WriteString("-D INPUT -j " + Chain + "\n")
	}
	b.WriteString("-I INPUT 1 -j " + Chain + "\nCOMMIT\n")
	return []byte(b.String())
}

func removeInput(jumps int) []byte {
	var b strings.Builder
	b.WriteString("*filter\n")
	for i := 0; i < jumps; i++ {
		b.WriteString("-D INPUT -j " + Chain + "\n")
	}
	b.WriteString("-F " + Chain + "\n-X " + Chain + "\nCOMMIT\n")
	return []byte(b.String())
}

// Installed says whether family's SFC-INPUT already holds exactly lines
// with its jump first in INPUT.
func Installed(ctx context.Context, h Host, family int, lines []string) (bool, error) {
	input, _, err := h.List(ctx, family, "INPUT")
	if err != nil {
		return false, err
	}
	if jumps, first := inputJumps(input); jumps != 1 || !first {
		return false, nil
	}
	chain, missing, err := h.List(ctx, family, Chain)
	if err != nil || missing {
		return false, err
	}
	rules := []string{}
	for _, l := range chain {
		if strings.HasPrefix(l, "-A "+Chain+" ") {
			rules = append(rules, l)
		}
	}
	// iptables -S writes matches in its own spelling, so only the marker
	// (with the digest of what was written) and the count are compared.
	return len(rules) == len(lines) && strings.Contains(rules[0], markerText(lines[0])), nil
}

func markerText(marker string) string {
	_, after, _ := strings.Cut(marker, "--comment ")
	return strings.Trim(after, "\"")
}

// Apply puts ls into SFC-INPUT for every family. When a later family fails,
// the earlier ones are put back to previous (nil: removed), so the server is
// never left half changed.
func Apply(ctx context.Context, h Host, ls Layers, l Locks, previous *Layers) error {
	for i, family := range Families {
		if err := applyFamily(ctx, h, family, Lines(family, ls, l)); err != nil {
			for _, done := range Families[:i] {
				var undo error
				if previous == nil {
					undo = removeFamily(ctx, h, done)
				} else {
					undo = applyFamily(ctx, h, done, Lines(done, *previous, l))
				}
				err = errors.Join(err, undo)
			}
			return err
		}
	}
	return nil
}

func applyFamily(ctx context.Context, h Host, family int, lines []string) error {
	input, _, err := h.List(ctx, family, "INPUT")
	if err != nil {
		return err
	}
	jumps, _ := inputJumps(input)
	return h.Restore(ctx, family, applyInput(lines, jumps))
}

// Remove takes the jump and SFC-INPUT out of every family; a family without
// the chain is left as it is.
func Remove(ctx context.Context, h Host) error {
	var result error
	for _, family := range Families {
		result = errors.Join(result, removeFamily(ctx, h, family))
	}
	return result
}

func removeFamily(ctx context.Context, h Host, family int) error {
	_, missing, err := h.List(ctx, family, Chain)
	if err != nil || missing {
		return err
	}
	input, _, err := h.List(ctx, family, "INPUT")
	if err != nil {
		return err
	}
	jumps, _ := inputJumps(input)
	return h.Restore(ctx, family, removeInput(jumps))
}

// MaxOperatorLines bounds the operator INPUT lines one show returns per
// family.
const MaxOperatorLines = 200

// Operator is the operator's own INPUT rules of family as `iptables -S
// INPUT` prints them, without sfcd's jump. It is read only.
func Operator(ctx context.Context, h Host, family int) ([]string, bool, error) {
	lines, _, err := h.List(ctx, family, "INPUT")
	if err != nil {
		return nil, false, err
	}
	out := []string{}
	truncated := false
	for _, l := range lines {
		if l == jumpLine {
			continue
		}
		if len(out) == MaxOperatorLines {
			truncated = true
			break
		}
		if len(l) > 512 {
			l = l[:512]
		}
		out = append(out, l)
	}
	return out, truncated, nil
}
