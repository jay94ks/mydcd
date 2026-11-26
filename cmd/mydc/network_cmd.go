// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// network: 작업 공간의 망. A network spans servers: each member server has
// its own address pool and a tunnel address, and all members reach each
// other. One network.yaml describes the whole network; create and update
// apply it, and applying the same file twice changes nothing.

func networkCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "network",
		Short: "Manage a tenant's networks (network.yaml)",
		Sub: []*cli.Command{
			networkListCommand(g),
			networkShowCommand(g),
			networkCreateCommand(g),
			networkUpdateCommand(g),
			networkDeleteCommand(g),
			networkUsersCommand(g),
			networkSystemCommand(g),
		},
	}
}

// networkFile is network.yaml (docs/cli/network.md).
type networkFile struct {
	Version int                   `yaml:"version"`
	Name    string                `yaml:"name"`
	Gateway string                `yaml:"gateway,omitempty"`
	MTU     int                   `yaml:"mtu,omitempty"`
	Members map[string]memberFile `yaml:"members"`
	DNS     *dnsFile              `yaml:"dns,omitempty"`
	// Toggles: network options by name (tenancy.NetworkToggles), true or
	// false. One the file does not name keeps its current value.
	Toggles map[string]bool `yaml:"toggles,omitempty"`
}

type memberFile struct {
	Subnet  string `yaml:"subnet"`
	Gateway string `yaml:"gateway,omitempty"`
	Dynamic string `yaml:"dynamic,omitempty"`
	Tunnel  string `yaml:"tunnel"`
}

type dnsFile struct {
	Zone      string        `yaml:"zone"`
	TTL       time.Duration `yaml:"ttl,omitempty"`
	Upstreams []string      `yaml:"upstreams,omitempty"`
	Reverse   bool          `yaml:"reverse,omitempty"`
}

// networkSpec is a checked network.yaml.
type networkSpec struct {
	Name    string
	Members []tenancy.TUNNode // sorted by node
	DNS     *dnsFile
	MTUSet  bool                           // the file names mtu; otherwise an update may keep the current one (keepMTU)
	Toggles map[tenancy.NetworkToggle]bool // the toggles the file names
}

// defaultMTU is the MTU of a one-server network, which has no tunnel.
// defaultTUNMTU is the MTU of a network on two or more servers: the TUN
// between them must fit in a 1500-byte server network with the MYDCP
// overhead (mydcp.TUNUnderlayMTU), and 1280 is the smallest MTU allowed.
const (
	defaultMTU    = 1500
	defaultTUNMTU = 1280
)

func readNetworkFile(path string) ([]byte, error) {
	if path == "" {
		return nil, cli.Usagef("give the network file with -f FILE")
	}
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, 64<<10+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 64<<10 {
		return nil, errors.New("the network file is larger than 64KiB")
	}
	return raw, nil
}

func parseNetworkFile(raw []byte) (networkSpec, error) {
	var f networkFile
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if err := d.Decode(&f); err != nil {
		return networkSpec{}, fmt.Errorf("network file: %v", err)
	}
	bad := func(format string, args ...any) (networkSpec, error) {
		return networkSpec{}, fmt.Errorf("network file: "+format, args...)
	}
	if f.Version != 1 {
		return bad("version must be 1")
	}
	if !cli.ValidID(f.Name) {
		return bad("name %q: lower-case letters, digits and '-'", f.Name)
	}
	if f.Gateway != "" && f.Gateway != "nat" {
		return bad("gateway can only be nat")
	}
	if len(f.Members) == 0 || len(f.Members) > 32 {
		return bad("members: 1 to 32 servers")
	}
	mtu := f.MTU
	if mtu == 0 {
		mtu = defaultMTU
		if len(f.Members) > 1 {
			mtu = defaultTUNMTU
		}
	}
	if mtu < 1280 || mtu > 9000 {
		return bad("mtu must be 1280..9000")
	}
	spec := networkSpec{Name: f.Name, DNS: f.DNS, MTUSet: f.MTU != 0, Toggles: map[tenancy.NetworkToggle]bool{}}
	for name, on := range f.Toggles {
		t := tenancy.NetworkToggle(name)
		if !slices.Contains(tenancy.NetworkToggles(), t) {
			return bad("toggles: %q is not one of %v", name, tenancy.NetworkToggles())
		}
		if !tenancy.ToggleAllowed(t, on, len(f.Members)) {
			return bad("toggles.%s: %v is not allowed with %d servers", name, on, len(f.Members))
		}
		spec.Toggles[t] = on
	}
	nodes := make([]string, 0, len(f.Members))
	for node := range f.Members {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	for _, node := range nodes {
		m := f.Members[node]
		if !cliprofile.ValidKeyName(node) {
			return bad("members: %q is not a server name", node)
		}
		prefix, err := netip.ParsePrefix(m.Subnet)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() > 29 {
			return bad("members.%s.subnet: an IPv4 network such as 10.240.10.0/24 (at most /29)", node)
		}
		gw := prefix.Addr().Next()
		if m.Gateway != "" {
			if gw, err = netip.ParseAddr(m.Gateway); err != nil || !prefix.Contains(gw) || gw == prefix.Addr() {
				return bad("members.%s.gateway: a host address inside the subnet", node)
			}
		}
		pool := tenancy.Subnet{ID: "main", Prefix: prefix, Gateway: gw, MTU: mtu}
		if m.Dynamic != "" {
			dyn, err := netip.ParsePrefix(m.Dynamic)
			if err != nil || dyn != dyn.Masked() || !prefix.Contains(dyn.Addr()) || dyn.Bits() < prefix.Bits() {
				return bad("members.%s.dynamic: a range inside the subnet, such as 10.240.10.0/25", node)
			}
			pool.IPAM = network.PoolIPAM{Dynamic: dyn}
		}
		tunnel, err := netip.ParsePrefix(m.Tunnel)
		if err != nil {
			if a, aerr := netip.ParseAddr(m.Tunnel); aerr == nil {
				tunnel, err = netip.PrefixFrom(a, 32), nil
			}
		}
		if err != nil || !tunnel.Addr().Is4() || tunnel.Bits() != 32 || tunnel.Addr().IsUnspecified() || tunnel.Addr().IsLoopback() || tunnel.Addr().IsMulticast() || tunnel.Addr().IsLinkLocalUnicast() {
			return bad("members.%s.tunnel: an IPv4 host address such as 10.240.30.1/32", node)
		}
		spec.Members = append(spec.Members, tenancy.TUNNode{Node: node, Pools: []tenancy.Subnet{pool}, Addresses: []netip.Prefix{tunnel}})
	}
	for i, a := range spec.Members {
		for j, b := range spec.Members {
			if i != j && a.Addresses[0] == b.Addresses[0] {
				return bad("members %s and %s have the same tunnel address", a.Node, b.Node)
			}
			if b.Pools[0].Prefix.Contains(a.Addresses[0].Addr()) || i < j && a.Pools[0].Prefix.Overlaps(b.Pools[0].Prefix) {
				return bad("member subnets must not overlap each other or any tunnel address (%s, %s)", a.Node, b.Node)
			}
		}
	}
	if f.DNS != nil {
		zone, err := services.Domain(f.DNS.Zone)
		if err != nil || len(zone) > 200 {
			return bad("dns.zone: a domain name such as shop.mydc.test")
		}
		f.DNS.Zone = zone
		if f.DNS.TTL != 0 && (f.DNS.TTL < time.Second || f.DNS.TTL > time.Hour || f.DNS.TTL%time.Second != 0) {
			return bad("dns.ttl: whole seconds from 1s to 1h")
		}
		if len(f.DNS.Upstreams) > 4 {
			return bad("dns.upstreams: at most 4")
		}
		for _, u := range f.DNS.Upstreams {
			if _, err := upstream(u); err != nil {
				return bad("dns.upstreams: %q is not an address such as 1.1.1.1 or 1.1.1.1:53", u)
			}
		}
	}
	return spec, nil
}

func upstream(text string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(text); err == nil {
		return ap, nil
	}
	a, err := netip.ParseAddr(text)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, 53), nil
}

// definition is the server's form of the spec. pools keeps the current
// pool ID of a member that stays.
func (n networkSpec) definition(tenant string, pools map[string]string, current []tenancy.NetworkToggle) tenancy.TUNDefinition {
	d := tenancy.TUNDefinition{Tenant: tenant, Name: n.Name, Members: []tenancy.TUNNode{}, GatewayMode: network.ManagedGatewayMode, Toggles: n.toggles(current)}
	for _, m := range n.Members {
		m.Pools = slices.Clone(m.Pools)
		if id, ok := pools[m.Node]; ok {
			m.Pools[0].ID = id
		}
		d.Members = append(d.Members, m)
	}
	return d
}

// toggles are the toggles that end up on: the ones the file names, and the
// others as they are now (current). nil when none.
func (n networkSpec) toggles(current []tenancy.NetworkToggle) []tenancy.NetworkToggle {
	var out []tenancy.NetworkToggle
	for _, t := range tenancy.NetworkToggles() {
		on, named := n.Toggles[t]
		if !named {
			on = slices.Contains(current, t)
		}
		if on {
			out = append(out, t)
		}
	}
	return out
}

// netMember is one server's part of a network as the server reports it.
type netMember struct {
	Source tenancy.Network
	Change *control.NetworkChangeStatus
}

// netState is a network read from the tenant's resources.
type netState struct {
	Tenant, Name string
	Members      []netMember // sorted by node
	DNS          *control.DNSPolicyView
	Networks     uint64 // revision of the tenant networks (CAS of create/commit)
}

// toggles are the network's toggles that are on now.
func (v *netState) toggles() []tenancy.NetworkToggle {
	if len(v.Members) == 0 {
		return nil
	}
	return v.Members[0].Source.Toggles
}

// toggleStep sets the first toggle the file changes whose new value the
// network may hold with its current servers. A value that needs other
// servers (local on after a removal) waits until they have changed. No step
// while a server changes.
func toggleStep(v *netState, want *networkSpec) (netStep, bool) {
	for _, m := range v.Members {
		if m.phase() != "" || m.Source.Draining {
			return netStep{}, false
		}
	}
	cur := v.toggles()
	for _, t := range tenancy.NetworkToggles() {
		on, named := want.Toggles[t]
		if !named || on == slices.Contains(cur, t) || !tenancy.ToggleAllowed(t, on, len(v.Members)) {
			continue
		}
		label := fmt.Sprintf("turn %s %s", t, map[bool]string{true: "on", false: "off"}[on])
		return netStep{Label: label, Key: fmt.Sprintf("t%s-%d", t, v.Networks), Action: "set-network-toggle", Expected: v.Networks,
			Payload: control.NetworkToggleSet{Tenant: v.Tenant, Name: v.Name, Toggle: t, On: on}}, true
	}
	return netStep{}, false
}

func memberName(n tenancy.Network) string {
	if n.Logical != "" {
		return n.Logical
	}
	return n.ID
}

func poolText(n tenancy.Network) string {
	var parts []string
	for _, p := range n.Pools {
		parts = append(parts, p.Prefix.String())
	}
	text := n.Node + " " + strings.Join(parts, ",")
	if len(n.TunnelAddresses) > 0 {
		text += " tunnel " + n.TunnelAddresses[0].Addr().String()
	}
	return text
}

func groupNetworks(rows []control.ResourceEntry, networks uint64) []*netState {
	byName := map[string]*netState{}
	var out []*netState
	for _, e := range rows {
		if e.Network == nil {
			continue
		}
		key := e.Network.Tenant + "/" + memberName(*e.Network)
		v := byName[key]
		if v == nil {
			v = &netState{Tenant: e.Network.Tenant, Name: memberName(*e.Network), Networks: networks}
			byName[key] = v
			out = append(out, v)
		}
		v.Members = append(v.Members, netMember{Source: *e.Network, Change: e.Change})
		if e.DNS != nil {
			v.DNS = e.DNS
		}
	}
	for _, v := range out {
		sort.Slice(v.Members, func(i, j int) bool { return v.Members[i].Source.Node < v.Members[j].Source.Node })
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tenant != out[j].Tenant {
			return out[i].Tenant < out[j].Tenant
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func readNetwork(c *cli.Context, g *globals, s *session, tenant, name string) (*netState, error) {
	rows, networks, err := readResources(c, g, s, tenant)
	if err != nil {
		return nil, err
	}
	for _, v := range groupNetworks(rows, networks) {
		if v.Tenant == tenant && v.Name == name {
			return v, nil
		}
	}
	return nil, nil
}

// phase is the member's change in progress, or "" when none.
func (m netMember) phase() tenancy.ChangePhase {
	if m.Change == nil || m.Change.Phase == tenancy.ChangeCommitted || m.Change.Phase == tenancy.ChangeCancelled {
		return ""
	}
	return m.Change.Phase
}

func sameMember(cur tenancy.Network, want tenancy.TUNNode) bool {
	if cur.Node != want.Node || len(cur.Pools) != 1 || !slices.Equal(cur.TunnelAddresses, want.Addresses) {
		return false
	}
	a, b := cur.Pools[0], want.Pools[0]
	return a.Prefix == b.Prefix && a.Gateway == b.Gateway && a.MTU == b.MTU && a.IPAM == b.IPAM
}

func sameNodes(v *netState, want *networkSpec) bool {
	if len(v.Members) != len(want.Members) {
		return false
	}
	for i := range v.Members {
		if v.Members[i].Source.Node != want.Members[i].Node {
			return false
		}
	}
	return true
}

func sameTopology(v *netState, want *networkSpec) bool {
	if !sameNodes(v, want) {
		return false
	}
	for i := range v.Members {
		if v.Members[i].phase() != "" || !sameMember(v.Members[i].Source, want.Members[i]) {
			return false
		}
	}
	return true
}

// wantDNS returns the DNS policy the file asks for and whether it differs
// from the current one. Limits the file does not name keep their current
// (or default) values.
func wantDNS(cur *control.DNSPolicyView, d *dnsFile) (services.ManagedDNSPolicy, bool) {
	p := services.ManagedDNSPolicy{TTL: 30, NegativeTTL: 5, Transports: []string{"udp", "tcp"}, Upstreams: []netip.AddrPort{},
		MaxQueries: 64, MaxCacheEntries: 512, MaxResponseBytes: 4096, MaxConnections: 64, RequestTimeoutMS: 5000}
	if cur != nil && cur.Policy.Transports != nil {
		p = cur.Policy
		p.Upstreams = slices.Clone(p.Upstreams)
		if p.Upstreams == nil {
			p.Upstreams = []netip.AddrPort{}
		}
	}
	old := p
	if d == nil {
		if cur == nil || !cur.Policy.Enabled {
			return p, false
		}
		p.Enabled = false
		return p, true
	}
	p.Enabled, p.Zone, p.Reverse = true, d.Zone, d.Reverse
	if d.TTL != 0 {
		p.TTL = uint32(d.TTL / time.Second)
	}
	p.NegativeTTL = min(p.NegativeTTL, p.TTL)
	p.Upstreams = []netip.AddrPort{}
	for _, u := range d.Upstreams {
		ap, _ := upstream(u)
		p.Upstreams = append(p.Upstreams, ap)
	}
	changed := cur == nil || old.Enabled != p.Enabled || old.Zone != p.Zone || old.Reverse != p.Reverse || old.TTL != p.TTL || old.NegativeTTL != p.NegativeTTL || !slices.Equal(old.Upstreams, p.Upstreams)
	return p, changed
}

// netStep is the next server change that brings a network toward the file
// (or toward deletion when want is nil).
type netStep struct {
	Label    string // what the step does, for people
	Key      string // unique for this step and the state it starts from
	Action   string
	Expected uint64
	Payload  any
	// Closure, when set, is the member whose owner must first report that
	// nothing uses it; the payload's closure is filled in from that report.
	Closure *netMember
	Done    bool
}

func nextNetworkStep(v *netState, want *networkSpec) (netStep, error) {
	dnsRev := uint64(0)
	if v.DNS != nil {
		dnsRev = v.DNS.Revision
	}
	dnsStep := func(p services.ManagedDNSPolicy) netStep {
		label := "set DNS " + p.Zone
		if !p.Enabled {
			label = "turn DNS off"
		}
		return netStep{Label: label, Key: fmt.Sprintf("n%d", dnsRev), Action: "configure-network-dns", Expected: dnsRev,
			Payload: services.ManagedDNSDefinition{Schema: 1, Tenant: v.Tenant, Network: v.Name, Policy: p}}
	}
	if want == nil && v.DNS != nil && v.DNS.Policy.Enabled {
		p, _ := wantDNS(v.DNS, nil)
		return dnsStep(p), nil
	}
	if want != nil {
		want = keepMTU(v, want)
	}
	if want != nil {
		for _, t := range tenancy.NetworkToggles() {
			on := slices.Contains(v.toggles(), t)
			if _, named := want.Toggles[t]; !named && !tenancy.ToggleAllowed(t, on, len(want.Members)) {
				return netStep{}, fmt.Errorf("%s has %s %v, which does not allow %d servers; set toggles.%s in the file", v.Name, t, on, len(want.Members), t)
			}
		}
		if step, ok := toggleStep(v, want); ok {
			return step, nil
		}
	}
	if want != nil && sameTopology(v, want) {
		if p, changed := wantDNS(v.DNS, want.DNS); changed {
			return dnsStep(p), nil
		}
		return netStep{Done: true}, nil
	}
	if want == nil {
		// Delete: each server leaves on its owner's closure; the last one
		// to leave removes the network. A server whose change is in
		// progress finishes that first (op resume continues it).
		for i := range v.Members {
			if m := &v.Members[i]; m.phase() == "" {
				return leaveStep(v, m), nil
			}
		}
		if len(v.Members) == 0 {
			return netStep{Done: true}, nil
		}
	}
	if step, ok := memberStep(v, want); ok {
		return step, nil
	}
	same := want != nil && sameNodes(v, want)
	// Every member is planned, drained and fenced; then one commit (same
	// servers) or reconfigure (servers added, removed or deleted) publishes
	// the new network.
	for i := range v.Members {
		m := &v.Members[i]
		if m.phase() != "" {
			continue
		}
		target := m.Source
		target.Pools = slices.Clone(m.Source.Pools)
		if same {
			w := want.Members[i]
			pool := w.Pools[0]
			if len(target.Pools) > 0 {
				pool.ID = target.Pools[0].ID
			}
			target.Pools = []tenancy.Subnet{pool}
			target.TunnelAddresses = slices.Clone(w.Addresses)
		}
		target.Owner, target.Draining, target.PendingChange = [32]byte{}, false, 0
		target.Generation, target.Revision = 0, 0
		key := fmt.Sprintf("p%d-%d", i, m.Source.Revision)
		return netStep{Label: "plan " + m.Source.Node, Key: key, Action: "plan-network-change", Expected: m.Source.Revision,
			Payload: control.NetworkChangePlan{Tenant: v.Tenant, ID: m.Source.ID, Change: key, Target: target}}, nil
	}
	for i := range v.Members {
		m := &v.Members[i]
		if m.phase() == tenancy.ChangeReserved {
			return netStep{Label: "stop new use on " + m.Source.Node, Key: fmt.Sprintf("d%d-%d", i, m.Source.Revision), Action: "drain-network", Expected: m.Source.Revision,
				Payload: control.NetworkSelection{Tenant: v.Tenant, ID: m.Source.ID}}, nil
		}
	}
	for i := range v.Members {
		m := &v.Members[i]
		if m.phase() == tenancy.ChangeDraining {
			return netStep{Label: "close " + m.Source.Node, Key: fmt.Sprintf("f%d-%d", i, m.Change.Revision), Action: "fence-network-change", Expected: m.Change.Revision, Closure: m}, nil
		}
	}
	var versions []tenancy.NetworkChangeVersion
	pools := map[string]string{}
	for _, m := range v.Members {
		versions = append(versions, tenancy.NetworkChangeVersion{Tenant: v.Tenant, ID: m.Source.ID, Generation: m.Change.Generation, Revision: m.Change.Revision})
		if len(m.Source.Pools) > 0 {
			pools[m.Source.Node] = m.Source.Pools[0].ID
		}
	}
	key := fmt.Sprintf("c%d", v.Networks)
	if same {
		return netStep{Label: "apply the new addresses", Key: key, Action: "commit-network-change", Expected: v.Networks,
			Payload: control.NetworkChangeCommit{Tenant: v.Tenant, Network: v.Name, Members: versions}}, nil
	}
	target := tenancy.TUNDefinition{Tenant: v.Tenant, Name: v.Name, Members: []tenancy.TUNNode{}}
	label := "remove the network"
	if want != nil {
		target, label = want.definition(v.Tenant, pools, v.toggles()), "apply the new servers"
	}
	return netStep{Label: label, Key: key, Action: "reconfigure-tun-network", Expected: v.Networks,
		Payload: control.NetworkReconfigure{Target: target, Members: versions}}, nil
}

// keepMTU keeps the network's current MTU when the file does not name one
// and the current MTU still fits the new member count: any MTU for one
// server, at most defaultTUNMTU for two or more. Adding or removing a
// server then changes no MTU, which would reconfigure every server.
func keepMTU(v *netState, want *networkSpec) *networkSpec {
	if want.MTUSet || len(v.Members) == 0 || len(v.Members[0].Source.Pools) == 0 {
		return want
	}
	mtu := v.Members[0].Source.Pools[0].MTU
	if len(want.Members) > 1 && mtu > defaultTUNMTU {
		return want
	}
	out := *want
	out.Members = make([]tenancy.TUNNode, len(want.Members))
	for i, m := range want.Members {
		m.Pools = slices.Clone(m.Pools)
		m.Pools[0].MTU = mtu
		out.Members[i] = m
	}
	return &out
}

// memberStep is the next step when the file only adds or removes servers
// and every staying server keeps its addresses: one join-tun-network per
// added server, then drain-network and leave-tun-network per removed one.
// The other servers keep their devices; only their routes change. ok is
// false when the change needs the fenced path (addresses or MTU change, or
// a change already in progress).
// leaveStep drains one server, then has it leave on its owner's closure.
func leaveStep(v *netState, m *netMember) netStep {
	if !m.Source.Draining {
		return netStep{Label: "stop new use on " + m.Source.Node, Key: fmt.Sprintf("d%s-%d", m.Source.Node, m.Source.Revision), Action: "drain-network", Expected: m.Source.Revision,
			Payload: control.NetworkSelection{Tenant: v.Tenant, ID: m.Source.ID}}
	}
	return netStep{Label: "remove " + m.Source.Node, Key: fmt.Sprintf("l%s-%d", m.Source.Node, m.Source.Revision), Action: "leave-tun-network", Expected: m.Source.Revision, Closure: m}
}

func memberStep(v *netState, want *networkSpec) (netStep, bool) {
	if want == nil || len(v.Members) == 0 || len(v.Members[0].Source.Pools) == 0 {
		return netStep{}, false
	}
	mtu := v.Members[0].Source.Pools[0].MTU
	wanted := map[string]tenancy.TUNNode{}
	for _, w := range want.Members {
		wanted[w.Node] = w
	}
	current := map[string]bool{}
	var leaving []*netMember
	draining := -1
	for i := range v.Members {
		m := &v.Members[i]
		current[m.Source.Node] = true
		if m.phase() != "" {
			return netStep{}, false
		}
		w, stays := wanted[m.Source.Node]
		switch {
		case !stays:
			if m.Source.Draining {
				draining = len(leaving)
			}
			leaving = append(leaving, m)
		case m.Source.Draining || !sameMember(m.Source, w):
			return netStep{}, false
		}
	}
	var joining []tenancy.TUNNode
	for _, w := range want.Members {
		if !current[w.Node] {
			if w.Pools[0].MTU != mtu {
				return netStep{}, false
			}
			joining = append(joining, w)
		}
	}
	if len(joining) == 0 && len(leaving) == 0 {
		return netStep{}, false
	}
	leave := func(m *netMember) netStep { return leaveStep(v, m) }
	// A server being removed blocks joins until it is gone, so finish it
	// first; otherwise add before removing, so the network never runs out
	// of servers.
	if draining >= 0 {
		return leave(leaving[draining]), true
	}
	if len(joining) > 0 {
		w := joining[0]
		return netStep{Label: "add " + w.Node, Key: fmt.Sprintf("j%s-%d", w.Node, v.Networks), Action: "join-tun-network", Expected: v.Networks,
			Payload: control.NetworkJoin{Tenant: v.Tenant, Name: v.Name, Member: w}}, true
	}
	return leave(leaving[0]), true
}

// readClosure asks the member's server whether anything still uses it.
// closed is nil while something does; detail says what.
func readClosure(c *cli.Context, g *globals, s *session, m *netMember) (*tenancy.NetworkClosure, string, error) {
	ctx, cancel := g.Deadline(c)
	defer cancel()
	reply, err := s.Client.PublicRead(ctx, s.Target, s.Stored.Session, "network-closure", m.Source.Tenant, control.PublicReadQuery{Name: m.Source.ID}, "")
	if err != nil {
		return nil, "", err
	}
	if reply.PublicRead != nil {
		for _, r := range reply.PublicRead.Rows {
			if r.Closure == nil {
				continue
			}
			switch {
			case r.Closure.State == "closed" && r.Closure.Closure != nil:
				return r.Closure.Closure, "", nil
			case r.Closure.State == "unreachable":
				return nil, "server " + m.Source.Node + " does not answer", nil
			case r.Closure.PendingEndpoints != nil && *r.Closure.PendingEndpoints > 0:
				return nil, fmt.Sprintf("%d containers on %s still use it", *r.Closure.PendingEndpoints, m.Source.Node), nil
			}
			return nil, "waiting for " + m.Source.Node + " to close it", nil
		}
	}
	return nil, "", errors.New("the server gave no closure report for " + m.Source.Node)
}

// applyNetwork moves the network toward want (nil: delete) one server
// change at a time, re-reading the network after each. Each step has its
// own operation ID derived from opID and the state it starts from, so a
// resumed run continues the same step instead of starting another.
// mode netShow only reports the next step and sends nothing.
func applyNetwork(c *cli.Context, g *globals, s *session, opID, tenant, name string, want *networkSpec, mode netMode) (cli.State, string, error) {
	waiting := ""
	for {
		v, err := readNetwork(c, g, s, tenant, name)
		if err != nil {
			return cli.Accepted, "", err
		}
		if v == nil {
			if want == nil {
				return cli.Done, "network " + name + " deleted", nil
			}
			return cli.Failed, "network " + name + " does not exist", fmt.Errorf("network %s does not exist in %s; create it with 'mydc network create'", name, tenant)
		}
		step, err := nextNetworkStep(v, want)
		if err != nil {
			return cli.Failed, err.Error(), err
		}
		if step.Done {
			return cli.Done, "network " + name + " is up to date", nil
		}
		if mode == netShow && step.Closure == nil {
			return cli.Accepted, "next: " + step.Label, nil
		}
		if step.Closure != nil {
			closure, detail, err := readClosure(c, g, s, step.Closure)
			if err != nil {
				return cli.Accepted, "", err
			}
			if closure == nil {
				if detail != waiting {
					waiting = detail
					fmt.Fprintf(c.Err, "Waiting: %s (stop the apps that use %s).\n", detail, name)
				}
				if mode != netWait {
					return cli.Accepted, detail, nil
				}
				select {
				case <-c.Ctx.Done():
					fmt.Fprintf(c.Err, "Stopped waiting. Continue later with: mydc op resume %s\n", opID)
					return cli.Accepted, detail, cli.ExitError{Code: exitUnknown}
				case <-time.After(3 * time.Second):
				}
				continue
			}
			if mode == netShow {
				return cli.Accepted, "next: " + step.Label, nil
			}
			if step.Action == "leave-tun-network" {
				step.Payload = *closure
			} else {
				step.Payload = control.NetworkChangeFence{Tenant: tenant, ID: step.Closure.Source.ID, Generation: step.Closure.Change.Generation, Closed: *closure}
			}
		}
		waiting = ""
		fmt.Fprintf(c.Err, "%s: %s\n", name, step.Label)
		id := opID + "-" + step.Key
		if _, err = g.send(c, s, change{Summary: fmt.Sprintf("network %s: %s", name, step.Label), ID: id, Action: step.Action, Expected: step.Expected, Payload: step.Payload}); err != nil {
			return cli.Accepted, "", err
		}
	}
}

type netMode int

const (
	netShow   netMode = iota // report the next step only
	netNoWait                // send the steps that need no waiting
	netWait                  // send every step, waiting for closures
)

func waitMode(wait bool) netMode {
	if wait {
		return netWait
	}
	return netNoWait
}

// specPath keeps the network file of an update until it is done, so 'mydc
// op resume' applies the same file.
func specPath(opID string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".mydc", "network")
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, opID+".yaml"), nil
}

func networkListCommand(g *globals) *cli.Command {
	var all bool
	return &cli.Command{
		Name:  "list",
		Short: "List the tenant's networks",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&all, "all", false, "every tenant's networks (system administrator)")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("list takes no arguments")
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant := ""
			if !all {
				if tenant, err = g.Tenant(s, true); err != nil {
					return err
				}
			}
			rows, networks, err := readResources(c, g, s, tenant)
			if err != nil {
				return err
			}
			views := []networkView{}
			for _, v := range groupNetworks(rows, networks) {
				views = append(views, v.view())
			}
			return cli.Print(c.Out, g.output.Format(), views, func() cli.Rows {
				r := cli.Rows{Header: []string{"tenant", "name", "servers", "dns", "state"}}
				for _, v := range views {
					var nodes []string
					for _, m := range v.Members {
						nodes = append(nodes, m.Node)
					}
					dns := ""
					if v.DNS != nil && v.DNS.Enabled {
						dns = v.DNS.Zone
					}
					r.Add(v.Tenant, v.Name, strings.Join(nodes, ","), dns, v.State)
				}
				return r
			})
		}),
	}
}

// networkView is how show and list print a network.
type networkView struct {
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`  // tun or bridge
	State  string `json:"state"` // configured, draining or changing
	MTU    int    `json:"mtu,omitempty"`
	// UnderlayMTU is the server network MTU a TUN of this MTU needs on
	// every member server.
	UnderlayMTU int                 `json:"underlay_mtu,omitempty"`
	Members     []networkMemberView `json:"members"`
	DNS         *networkDNSView     `json:"dns,omitempty"`
	// Toggles: every known toggle of a TUN network and whether it is on.
	Toggles map[string]bool `json:"toggles,omitempty"`
}

type networkMemberView struct {
	Node     string `json:"node"`
	Subnet   string `json:"subnet"`
	Gateway  string `json:"gateway,omitempty"`
	Dynamic  string `json:"dynamic,omitempty"`
	Tunnel   string `json:"tunnel,omitempty"`
	Revision uint64 `json:"revision"`
	Change   string `json:"change,omitempty"` // reserved, draining or fenced
}

type networkDNSView struct {
	Zone      string   `json:"zone"`
	Enabled   bool     `json:"enabled"`
	TTL       string   `json:"ttl"`
	Upstreams []string `json:"upstreams,omitempty"`
	State     string   `json:"state,omitempty"`
	Resolvers []string `json:"resolvers,omitempty"`
}

func (v *netState) view() networkView {
	// configured: the cluster has the network. Whether each server has
	// opened it is reported by that server, not by this record.
	out := networkView{Tenant: v.Tenant, Name: v.Name, Kind: "tun", State: "configured", Members: []networkMemberView{}, Toggles: map[string]bool{}}
	for _, t := range tenancy.NetworkToggles() {
		out.Toggles[string(t)] = slices.Contains(v.toggles(), t)
	}
	if len(v.Members) > 0 && len(v.Members[0].Source.Pools) > 0 {
		out.MTU = v.Members[0].Source.Pools[0].MTU
		if len(v.Members) > 1 {
			out.UnderlayMTU = mydcp.TUNUnderlayMTU(out.MTU)
		}
	}
	for _, m := range v.Members {
		mv := networkMemberView{Node: m.Source.Node, Revision: m.Source.Revision, Change: string(m.phase())}
		if len(m.Source.Pools) > 0 {
			p := m.Source.Pools[0]
			mv.Subnet, mv.Gateway = p.Prefix.String(), p.Gateway.String()
			if p.IPAM.Dynamic.IsValid() {
				mv.Dynamic = p.IPAM.Dynamic.String()
			}
		}
		if len(m.Source.TunnelAddresses) > 0 {
			mv.Tunnel = m.Source.TunnelAddresses[0].String()
		}
		if mv.Change != "" {
			out.State = "changing"
		} else if m.Source.Draining && out.State == "configured" {
			out.State = "draining"
		}
		out.Members = append(out.Members, mv)
	}
	if v.DNS != nil {
		d := &networkDNSView{Zone: strings.TrimSuffix(v.DNS.Policy.Zone, "."), Enabled: v.DNS.Policy.Enabled, TTL: (time.Duration(v.DNS.Policy.TTL) * time.Second).String(), State: v.DNS.State, Resolvers: v.DNS.Resolvers}
		for _, u := range v.DNS.Policy.Upstreams {
			d.Upstreams = append(d.Upstreams, u.String())
		}
		out.DNS = d
	}
	return out
}

func networkName(args []string) (string, error) {
	if len(args) != 1 || !cli.ValidID(args[0]) {
		return "", cli.Usagef("expected NETWORK (lower-case letters, digits and '-')")
	}
	return args[0], nil
}

func networkShowCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "show",
		Args:  "NETWORK",
		Short: "Show a network's servers, addresses, DNS and any change in progress",
		Run: guard(func(c *cli.Context, args []string) error {
			name, err := networkName(args)
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			v, err := readNetwork(c, g, s, tenant, name)
			if err != nil {
				return err
			}
			if v == nil {
				return fmt.Errorf("no network %s in %s", name, tenant)
			}
			return cli.Print(c.Out, g.output.Format(), v.view(), nil)
		}),
	}
}

func networkCreateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var file string
	return &cli.Command{
		Name:  "create",
		Args:  "-f network.yaml",
		Short: "Create a network from network.yaml (- reads standard input)",
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&file, "f", "", "network `file`")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("create takes the network from -f FILE")
			}
			raw, err := readNetworkFile(file)
			if err != nil {
				return err
			}
			spec, err := parseNetworkFile(raw)
			if err != nil {
				return err
			}
			if w := mtuWarning(spec); w != "" {
				fmt.Fprintln(c.Err, w)
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			v, err := readNetwork(c, g, s, tenant, spec.Name)
			if err != nil {
				return err
			}
			if v != nil {
				return fmt.Errorf("network %s already exists; change it with 'mydc network update -f'", spec.Name)
			}
			rows, networks, err := readResources(c, g, s, tenant)
			if err != nil {
				return err
			}
			if err = systemRangeConflict(rows, spec); err != nil {
				return err
			}
			opID := id.Get()
			if _, err = g.send(c, s, change{Summary: "network create " + spec.Name, ID: opID, Action: "create-tun-network", Expected: networks, Payload: spec.definition(tenant, nil, nil)}); err != nil {
				return err
			}
			if spec.DNS != nil {
				if _, _, err = applyNetwork(c, g, s, opID, tenant, spec.Name, &spec, netNoWait); err != nil {
					return err
				}
			}
			fmt.Fprintf(c.Out, "network %s created\n", spec.Name)
			return nil
		}),
	}
}

func networkUpdateCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var file string
	var noWait bool
	return &cli.Command{
		Name:  "update",
		Args:  "-f network.yaml",
		Short: "Change a network to match network.yaml",
		Long: `Change a network to match the file. A DNS change applies at once.
Changing addresses or servers takes the network out of use: each server
stops new use of it, waits until no container uses it any more, and then
the new network is applied. Stop the apps on the network first; the command
waits for them and says what it is waiting for. With --no-wait, or when
interrupted, continue with 'mydc op resume ID'.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.StringVar(&file, "f", "", "network `file`")
			fs.BoolVar(&noWait, "no-wait", false, "do the steps that need no waiting and return")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			if len(args) != 0 {
				return cli.Usagef("update takes the network from -f FILE")
			}
			raw, err := readNetworkFile(file)
			if err != nil {
				return err
			}
			spec, err := parseNetworkFile(raw)
			if err != nil {
				return err
			}
			if w := mtuWarning(spec); w != "" {
				fmt.Fprintln(c.Err, w)
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			v, err := readNetwork(c, g, s, tenant, spec.Name)
			if err != nil {
				return err
			}
			if v == nil {
				return fmt.Errorf("no network %s in %s; create it with 'mydc network create -f'", spec.Name, tenant)
			}
			rows, _, err := readResources(c, g, s, tenant)
			if err != nil {
				return err
			}
			if err = systemRangeConflict(rows, spec); err != nil {
				return err
			}
			if sameTopology(v, &spec) {
				if _, changed := wantDNS(v.DNS, spec.DNS); !changed {
					fmt.Fprintf(c.Out, "network %s is up to date\n", spec.Name)
					return nil
				}
			} else {
				fmt.Fprintf(c.Err, "Network %s will change servers or addresses. Its containers must stop using it first; new use stops now.\n", spec.Name)
				if err = g.Prompter(c).Confirm("Change network " + spec.Name + "?"); err != nil {
					return err
				}
			}
			opID := id.Get()
			path, err := specPath(opID)
			if err != nil {
				return err
			}
			if err = os.WriteFile(path, raw, 0o600); err != nil {
				return err
			}
			if err = g.Record(s, "network-update", "network update "+spec.Name, opID); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Operation %s\n", opID)
			st, detail, err := applyNetwork(c, g, s, opID, tenant, spec.Name, &spec, waitMode(!noWait))
			g.settle(opID, st, detail)
			if st.Final() {
				_ = os.Remove(path)
			}
			if err != nil {
				return err
			}
			if !st.Final() {
				fmt.Fprintf(c.Out, "%s; continue with: mydc op resume %s\n", detail, opID)
				return nil
			}
			fmt.Fprintln(c.Out, detail)
			return nil
		}),
	}
}

func networkDeleteCommand(g *globals) *cli.Command {
	var id cli.IDFlag
	var noWait bool
	return &cli.Command{
		Name:  "delete",
		Args:  "NETWORK",
		Short: "Delete a network once no container uses it",
		Long: `Delete a network. New use stops at once (DNS is turned off first);
the network is removed when no container uses it any more. Stop the apps on
it first. With --no-wait, or when interrupted, continue with
'mydc op resume ID'.`,
		Flags: func(fs *flag.FlagSet) {
			fs.Var(&id, "id", "operation `ID` (default: a new one)")
			fs.BoolVar(&noWait, "no-wait", false, "do the steps that need no waiting and return")
		},
		Run: guard(func(c *cli.Context, args []string) error {
			name, err := networkName(args)
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			v, err := readNetwork(c, g, s, tenant, name)
			if err != nil {
				return err
			}
			if v == nil {
				return fmt.Errorf("no network %s in %s", name, tenant)
			}
			fmt.Fprintf(c.Err, "Network %s on %d servers will stop accepting new use and be removed once no container uses it.\n", name, len(v.Members))
			if err = g.Prompter(c).Confirm("Delete network " + name + "?"); err != nil {
				return err
			}
			opID := id.Get()
			if err = g.Record(s, "network-delete", "network delete "+name, opID); err != nil {
				return err
			}
			fmt.Fprintf(c.Err, "Operation %s\n", opID)
			st, detail, err := applyNetwork(c, g, s, opID, tenant, name, nil, waitMode(!noWait))
			g.settle(opID, st, detail)
			if err != nil {
				return err
			}
			if !st.Final() {
				fmt.Fprintf(c.Out, "%s; continue with: mydc op resume %s\n", detail, opID)
				return nil
			}
			fmt.Fprintln(c.Out, detail)
			return nil
		}),
	}
}

func init() {
	handler := func(g *globals, update bool) cli.Handler {
		settle := func(c *cli.Context, op cli.Op, resume bool) (cli.State, string, error) {
			prefix := "network delete "
			if update {
				prefix = "network update "
			}
			name, ok := strings.CutPrefix(op.Summary, prefix)
			if !ok {
				return "", "", errors.New("not a network operation")
			}
			var want *networkSpec
			var path string
			if update {
				var err error
				if path, err = specPath(op.ID); err != nil {
					return "", "", err
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					return "", "", fmt.Errorf("the network file of %s is no longer on this computer: run 'mydc network update -f' again", op.ID)
				}
				spec, err := parseNetworkFile(raw)
				if err != nil {
					return "", "", err
				}
				want = &spec
			}
			s, err := openOpSession(g, c, op)
			if err != nil {
				return "", "", err
			}
			defer s.Close()
			mode := netShow
			if resume {
				mode = netWait
			}
			st, detail, err := applyNetwork(c, g, s, op.ID, op.Tenant, name, want, mode)
			if st.Final() && path != "" {
				_ = os.Remove(path)
			}
			if err != nil && st == "" {
				return "", "", err
			}
			if err != nil {
				var exit cli.ExitError
				if errors.As(err, &exit) {
					return st, detail, nil
				}
				return "", "", err
			}
			return st, detail, nil
		}
		return cli.Handler{
			Show:   func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, false) },
			Resume: func(c *cli.Context, op cli.Op) (cli.State, string, error) { return settle(c, op, true) },
		}
	}
	opKinds["network-update"] = func(g *globals) cli.Handler { return handler(g, true) }
	opKinds["network-delete"] = func(g *globals) cli.Handler { return handler(g, false) }
}

func networkUsersCommand(g *globals) *cli.Command {
	return &cli.Command{
		Name:  "users",
		Args:  "NETWORK",
		Short: "List the apps and containers that use a network",
		Run: guard(func(c *cli.Context, args []string) error {
			name, err := networkName(args)
			if err != nil {
				return err
			}
			s, err := openSession(g, c)
			if err != nil {
				return err
			}
			defer s.Close()
			tenant, err := g.Tenant(s, true)
			if err != nil {
				return err
			}
			users := []control.PublicResourceUser{}
			err = publicReadAll(c, g, s, "network-users", tenant, control.PublicReadQuery{Name: name}, func(r control.PublicReadRow) {
				if r.User != nil {
					users = append(users, *r.User)
				}
			})
			if err != nil {
				return err
			}
			return cli.Print(c.Out, g.output.Format(), users, func() cli.Rows {
				r := cli.Rows{Header: []string{"kind", "app", "service", "node", "state"}}
				for _, u := range users {
					app := u.App
					if u.Standalone != "" {
						app = u.Standalone
					}
					r.Add(u.Kind, app, u.Service, u.Node, u.Observed)
				}
				return r
			})
		}),
	}
}

// publicReadAll reads every page of a public read.
func publicReadAll(c *cli.Context, g *globals, s *session, method, tenant string, q control.PublicReadQuery, row func(control.PublicReadRow)) error {
	after := ""
	for {
		ctx, cancel := g.Deadline(c)
		reply, err := s.Client.PublicRead(ctx, s.Target, s.Stored.Session, method, tenant, q, after)
		cancel()
		if err != nil {
			return err
		}
		if reply.PublicRead == nil {
			return errors.New("the server returned no rows")
		}
		for _, r := range reply.PublicRead.Rows {
			row(r)
		}
		if after = reply.PublicRead.Next; after == "" {
			return nil
		}
	}
}

// mtuWarning says, for a network on two or more servers, what server network
// MTU its TUN needs when that is more than the common 1500.
func mtuWarning(spec networkSpec) string {
	if len(spec.Members) < 2 || len(spec.Members[0].Pools) == 0 {
		return ""
	}
	mtu := spec.Members[0].Pools[0].MTU
	if need := mydcp.TUNUnderlayMTU(mtu); need > 1500 {
		return fmt.Sprintf("Note: mtu %d needs a server network MTU of at least %d on every server; on a 1500 network the servers cannot connect (use %d or leave mtu out).", mtu, need, 1500-(need-mtu))
	}
	return ""
}

// systemRangeConflict refuses a network.yaml whose subnets or tunnel
// addresses overlap the system network's range; mydcd refuses it too.
func systemRangeConflict(rows []control.ResourceEntry, spec networkSpec) error {
	for _, e := range rows {
		if e.System == nil {
			continue
		}
		r := e.System.RangeOrDefault()
		for _, m := range spec.Members {
			var prefixes []netip.Prefix
			for _, p := range m.Pools {
				prefixes = append(prefixes, p.Prefix)
			}
			for _, p := range append(prefixes, m.Addresses...) {
				if p.Overlaps(r) {
					return fmt.Errorf("server %s: %s overlaps the system network range %s; pick another range", m.Node, p, r)
				}
			}
		}
	}
	return nil
}
