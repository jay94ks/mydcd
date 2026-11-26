// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/miekg/dns"
)

// DNSName refers to an exact committed address generation; it does not supply
// an arbitrary address. Addresses come from the committed CIDR/IPAM Book.
type DNSName struct {
	Name, Endpoint string
	Generation     uint64
}
type DNSLeaseName struct {
	Name, Service, Client string
	Generation, Revision  uint64
}
type DNSConfig struct {
	Tenant, ID, Network, Pool string
	Source                    uint64
	// Serial is assigned once by the shared DNS projection transaction. Each
	// node must consume the same value even if it skipped intermediate views.
	Serial                                        uint32
	Enabled, Reverse                              bool
	Zone, ClientZone                              string
	TTL, NegativeTTL                              uint32
	QuerySeconds                                  uint32
	MaxQueries, MaxCacheEntries, MaxResponseBytes int
	Members                                       []string
	Names                                         []DNSName
	Leases                                        []DNSLeaseName
	Upstreams                                     []netip.AddrPort
}
type dnsRecord struct {
	Name                           string
	Address                        netip.Addr
	Allocation                     network.Allocation
	Lease                          [32]byte
	LeaseService, LeaseClient      string
	LeaseGeneration, LeaseRevision uint64
	ExpiresAt                      int64
}
type dnsProjection struct {
	Config      DNSConfig
	Serial      uint32
	Local       Source
	Members     []Source
	ReverseZone string
	Records     []dnsRecord
}

func ownDNSConfig(c DNSConfig) DNSConfig {
	c.Members = slices.Clone(c.Members)
	c.Names = slices.Clone(c.Names)
	c.Leases = slices.Clone(c.Leases)
	c.Upstreams = slices.Clone(c.Upstreams)
	return c
}
func ownProjection(p dnsProjection) dnsProjection {
	p.Config = ownDNSConfig(p.Config)
	p.Members = slices.Clone(p.Members)
	p.Records = slices.Clone(p.Records)
	return p
}
func projectionHash(p dnsProjection) [32]byte {
	raw, _ := json.Marshal(p)
	return sha256.Sum256(append([]byte("mydc-dns-view-1\x00"), raw...))
}
func dnsKey(tenant, id string) string { return tenant + "/" + id }
func reverseZone(prefix netip.Prefix) (string, error) {
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Is4() && prefix.Bits() != 24 || prefix.Addr().Is6() && (prefix.Bits() < 4 || prefix.Bits()%4 != 0) {
		return "", ErrProtocol
	}
	r, err := dns.ReverseAddr(prefix.Addr().String())
	if err != nil {
		return "", ErrProtocol
	}
	labels := dns.SplitDomainName(r)
	skip := 1
	if prefix.Addr().Is6() {
		skip = 32 - prefix.Bits()/4
	}
	return strings.Join(labels[skip:], ".") + ".", nil
}

// DNSReverseZone exposes the same supported-prefix contract to single-file
// validation. Unsupported prefixes cannot be accepted then fail at native use.
func DNSReverseZone(prefix netip.Prefix) (string, error) { return reverseZone(prefix) }
func canonicalName(s, zone string) (string, error) {
	if !strings.HasSuffix(s, ".") {
		s = s + "." + zone
	}
	name, err := Domain(s)
	if err != nil || !dns.IsSubDomain(zone, name) || name == zone || name == "ns."+zone {
		return "", ErrProtocol
	}
	return name, nil
}
func memberPool(p dnsProjection, pool string) (Source, bool) {
	for _, s := range p.Members {
		if fullPool(s) == pool {
			return s, true
		}
	}
	return Source{}, false
}
func validDNSConfig(input DNSConfig) bool {
	if len(input.Leases) != 0 || !id(input.Tenant) || !id(input.ID) || !id(input.Network) || !id(input.Pool) || input.Source == 0 || input.TTL < 1 || input.TTL > 3600 || input.NegativeTTL < 1 || input.NegativeTTL > input.TTL || input.QuerySeconds < 1 || input.QuerySeconds > 61 || input.MaxQueries < 1 || input.MaxQueries > 4096 || input.MaxCacheEntries < 0 || input.MaxCacheEntries > 4096 || input.MaxResponseBytes < 512 || input.MaxResponseBytes > 65535 || len(input.Names)+len(input.Leases) > maxRecords || len(input.Members) > 16 || len(input.Upstreams) > 4 {
		return false
	}
	for _, v := range input.Names {
		if v.Endpoint == "" || len(v.Endpoint) > 256 || v.Generation == 0 {
			return false
		}
	}
	return true
}
func validUpstreams(p dnsProjection) bool {
	seen := map[netip.AddrPort]bool{}
	for _, u := range p.Config.Upstreams {
		if !u.IsValid() || u.Port() == 0 || u.Addr().IsUnspecified() || u.Addr().IsMulticast() || u.Addr().Is4In6() || u.Addr().Zone() != "" || seen[u] {
			return false
		}
		seen[u] = true
		for _, s := range p.Members {
			if u.Addr() == s.Gateway {
				return false
			}
		}
	}
	return true
}
func buildDNS(c access.Catalog, n tenancy.Networks, a Authority, actor string, input DNSConfig) (dnsProjection, error) {
	return buildDNSView(c, n, a, actor, input, false)
}

func buildRetiringDNS(c access.Catalog, n tenancy.Networks, a Authority, actor string, input DNSConfig) (dnsProjection, error) {
	if input.Enabled {
		return dnsProjection{}, ErrProtocol
	}
	return buildDNSView(c, n, a, actor, input, true)
}

func buildDNSView(c access.Catalog, n tenancy.Networks, a Authority, actor string, input DNSConfig, retiring bool) (dnsProjection, error) {
	if a.cluster == ([32]byte{}) || n.Cluster() != a.cluster || !validDNSConfig(input) {
		return dnsProjection{}, ErrProtocol
	}
	local, ok := source(n, a.cluster, input.Tenant, input.Network, input.Pool)
	lookup := source
	if retiring {
		lookup = retainedSource
		local, ok = lookup(n, a.cluster, input.Tenant, input.Network, input.Pool)
	}
	allowed := c.Authorize(actor, input.Tenant, access.ManageServices, local.Node)
	if !input.Enabled {
		allowed = c.AuthorizeCleanup(actor, input.Tenant, access.ManageServices)
	}
	if !ok || allowed != nil {
		return dnsProjection{}, ErrProtocol
	}
	p := dnsProjection{Config: ownDNSConfig(input), Serial: input.Serial, Local: local}
	var err error
	p.Config.Zone, err = Domain(input.Zone)
	if err != nil {
		return dnsProjection{}, err
	}
	if input.ClientZone != "" {
		p.Config.ClientZone, err = Domain(input.ClientZone)
		if err != nil || dns.IsSubDomain(p.Config.ClientZone, p.Config.Zone) {
			return dnsProjection{}, ErrProtocol
		}
	}
	// Explicit same-tenant members describe one logical DNS view over several
	// node-owned network resources. They grant no route or cross-tenant access.
	p.Config.Members = append(p.Config.Members, input.Network)
	slices.Sort(p.Config.Members)
	p.Config.Members = slices.Compact(p.Config.Members)
	if len(p.Config.Members) > 16 {
		return dnsProjection{}, ErrProtocol
	}
	for _, name := range p.Config.Members {
		v, known := n.Network(input.Tenant, name)
		allowed := c.Authorize(actor, input.Tenant, access.ManageServices, v.Node)
		if !input.Enabled {
			allowed = c.AuthorizeCleanup(actor, input.Tenant, access.ManageServices)
		}
		if !known || v.Draining && !retiring || allowed != nil {
			return dnsProjection{}, ErrProtocol
		}
		for _, pool := range v.Pools {
			s, known := lookup(n, a.cluster, input.Tenant, name, pool.ID)
			if !known {
				return dnsProjection{}, ErrProtocol
			}
			p.Members = append(p.Members, s)
		}
	}
	if len(p.Members) > 64 {
		return dnsProjection{}, ErrProtocol
	}
	slices.SortFunc(p.Members, func(a, b Source) int { return strings.Compare(fullPool(a), fullPool(b)) })
	book := a.book.Checkpoint()
	pools := map[string]network.Pool{}
	for _, v := range book.Pools {
		pools[v.ID] = v
	}
	for _, s := range p.Members {
		v, known := pools[fullPool(s)]
		if !known || v.Draining && !retiring || v.Owner != poolOwner(s) || v.Network != s.Tenant+"/"+s.Network || v.Prefix != s.Prefix || v.Gateway != s.Gateway || v.MTU != s.MTU {
			return dnsProjection{}, ErrProtocol
		}
	}
	if !validUpstreams(p) {
		return dnsProjection{}, ErrProtocol
	}
	seen := map[string]bool{}
	for _, ref := range input.Names {
		name, e := canonicalName(ref.Name, p.Config.Zone)
		alloc, exists := a.book.Allocation(ref.Endpoint)
		member, belongs := memberPool(p, alloc.Pool)
		if e != nil || !exists || !belongs || alloc.Owner != poolOwner(member) || ref.Generation == 0 || alloc.Generation != ref.Generation || strings.HasPrefix(alloc.Endpoint, "dhcp/") || p.Config.ClientZone != "" && dns.IsSubDomain(p.Config.ClientZone, name) {
			return dnsProjection{}, ErrProtocol
		}
		key := name + "/" + alloc.Address.String()
		if seen[key] {
			return dnsProjection{}, ErrProtocol
		}
		seen[key] = true
		p.Records = append(p.Records, dnsRecord{Name: name, Address: alloc.Address, Allocation: alloc})
	}
	if input.Reverse {
		p.ReverseZone, err = reverseZone(local.Prefix)
		if err != nil {
			return dnsProjection{}, err
		}
	}
	slices.SortFunc(p.Records, func(a, b dnsRecord) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return a.Address.Compare(b.Address)
	})
	slices.SortFunc(p.Config.Names, func(a, b DNSName) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.Endpoint, b.Endpoint)
	})
	slices.SortFunc(p.Config.Leases, func(a, b DNSLeaseName) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		if a.Service != b.Service {
			return strings.Compare(a.Service, b.Service)
		}
		return strings.Compare(a.Client, b.Client)
	})
	return p, nil
}

// SerialAfter uses the DNS 32-bit sequence space; source indices themselves
// remain full-width and monotonic. Exactly half the space is not ordered.
func SerialAfter(next, old uint32) bool { d := next - old; return d != 0 && d < 1<<31 }
