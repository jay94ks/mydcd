// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/sha256"
	"encoding/base32"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// ManagedDNSDefinition is tenant management policy. It contains neither app
// registrations nor native readiness. Its source is committed by control.
type ManagedDNSDefinition struct {
	Schema          uint8
	Tenant, Network string
	Policy          ManagedDNSPolicy
	// Explicit opt-in keeps old committed refusals replayable. This only
	// selects validation of an existing disabled policy's reserved members.
	RetainReserved bool `json:",omitempty" yaml:"retain_reserved,omitempty"`
}

// ManagedDNSSource is the committed policy envelope shared by planning and
// control. It carries configuration, never a native readiness receipt.
type ManagedDNSSource struct {
	Schema     uint8
	Cluster    [32]byte
	Principal  string
	Definition ManagedDNSDefinition
}

type ManagedDNSPolicy struct {
	Enabled, Reverse                              bool
	Zone, ClientZone                              string
	TTL, NegativeTTL                              uint32
	Transports                                    []string
	Upstreams                                     []netip.AddrPort
	MaxQueries, MaxCacheEntries, MaxResponseBytes int
	MaxConnections, RequestTimeoutMS              int
	// Records are the names added by hand (DNSRecord), at most MaxDNSRecords.
	Records []DNSRecord `json:",omitempty"`
}

// DNSRegistration is derived from an original committed Task and its exact
// address reservations. The caller verifies that Task/Binding/current source;
// this core checks the same authority book and prevents cross-app name claims.
type DNSRegistration struct {
	Tenant, Network, App, Service string
	Task                          string `json:",omitempty"` // exact replica key; omitted for historical singleton registrations
	Aliases                       []string
	Addresses                     []DNSAddressReference
}

type DNSAddressReference struct {
	Endpoint   string
	Generation uint64
}

// ManagedDNSPlan is public metadata for the existing local DNSOwner. BridgeKey
// still needs the exact committed generation, native readback and fresh permit.
type ManagedDNSPlan struct {
	Node, BridgeKey                  string
	Owner                            [32]byte
	Config                           DNSConfig
	MaxConnections, RequestTimeoutMS int
}

const ManagedDNSPrefix = "control/network-services/dns/"

// DefaultDNSTTL and DefaultDNSNegativeTTL are the TTLs (seconds) a new
// managed DNS policy gets when its writer names none. TTL is also the most
// a forwarded answer is cached and passed on for: apps on the network find
// each other by name, and a moved service is found again within 10 seconds.
const (
	DefaultDNSTTL         = 10
	DefaultDNSNegativeTTL = 5
)

func ManagedDNSKey(tenant, name string) string {
	if !id(tenant) || !id(name) {
		return ""
	}
	return ManagedDNSPrefix + tenant + "/" + name
}

func ManagedDNSServiceID(tenant, name, pool string) string {
	h := sha256.Sum256([]byte("sfc-managed-dns-service-1\x00" + tenant + "/" + name + "/" + pool))
	return "d" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:]))
}

// Plans reuses the existing DNS projection validator and address authority.
// No clock, allocation, state write, native I/O or inferred Task generation.
// A failure returns no partial owner plans.
func (d ManagedDNSDefinition) Plans(c access.Catalog, n tenancy.Networks, a Authority, actor string, source uint64, serial uint32, registrations []DNSRegistration) ([]ManagedDNSPlan, error) {
	return d.plans(c, n, a, actor, source, serial, registrations, false)
}

// RetainedPlans reconstructs an already committed policy while its unchanged
// networks have reserved candidates. It grants no new policy/native use; the
// control consumer must still match original source and Bridge references.
func (d ManagedDNSDefinition) RetainedPlans(c access.Catalog, n tenancy.Networks, a Authority, actor string, source uint64, serial uint32, registrations []DNSRegistration) ([]ManagedDNSPlan, error) {
	return d.plans(c, n, a, actor, source, serial, registrations, true)
}

func (d ManagedDNSDefinition) plans(c access.Catalog, n tenancy.Networks, a Authority, actor string, source uint64, serial uint32, registrations []DNSRegistration, retained bool) ([]ManagedDNSPlan, error) {
	p := d.Policy
	if d.Schema != 1 || ManagedDNSKey(d.Tenant, d.Network) == "" || source == 0 || serial == 0 || n.Cluster() != a.Cluster() || len(registrations) > maxRecords || p.MaxConnections < 1 || p.MaxConnections > 4096 || p.RequestTimeoutMS < 1 || p.RequestTimeoutMS > 60000 || len(p.Transports) != 2 || !slices.Contains(p.Transports, "udp") || !slices.Contains(p.Transports, "tcp") {
		return nil, ErrProtocol
	}
	rows, err := n.TUNSources(d.Tenant, d.Network)
	if err != nil || len(rows) > 16 {
		return nil, ErrProtocol
	}
	zone, err := Domain(p.Zone)
	if err != nil {
		return nil, err
	}
	names, err := d.registrationNames(zone, registrations)
	if err != nil {
		return nil, err
	}
	records, err := d.policyRecords(zone)
	if err != nil {
		return nil, err
	}
	records, _ = splitDNSRecords(records, names)
	for _, name := range names {
		allocation, found := a.AddressBook().Allocation(name.Endpoint)
		if !found || allocation.Generation != name.Generation || allocation.Address.Is4() != strings.HasSuffix(name.Endpoint, "/0") {
			return nil, ErrProtocol
		}
	}
	members := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.Network.Draining || !retained && row.Network.PendingChange != 0 {
			return nil, ErrProtocol
		}
		members = append(members, row.Network.ID)
	}
	slices.Sort(members)
	var out []ManagedDNSPlan
	for _, row := range rows {
		for _, pool := range row.Network.Pools {
			cfg := DNSConfig{Tenant: d.Tenant, ID: ManagedDNSServiceID(d.Tenant, d.Network, pool.ID), Network: row.Network.ID, Pool: pool.ID, Source: source, Serial: serial, Enabled: p.Enabled, Reverse: p.Reverse, Zone: zone, ClientZone: p.ClientZone, TTL: p.TTL, NegativeTTL: p.NegativeTTL, QuerySeconds: uint32((p.RequestTimeoutMS+999)/1000) + 1, MaxQueries: p.MaxQueries, MaxCacheEntries: p.MaxCacheEntries, MaxResponseBytes: p.MaxResponseBytes, Members: slices.Clone(members), Names: slices.Clone(names), Records: slices.Clone(records), Upstreams: slices.Clone(p.Upstreams)}
			projection, err := buildDNS(c, n, a, actor, cfg)
			if err != nil {
				return nil, err
			}
			out = append(out, ManagedDNSPlan{Node: row.Network.Node, BridgeKey: row.BridgeKey, Owner: row.Network.Owner, Config: ownDNSConfig(projection.Config), MaxConnections: p.MaxConnections, RequestTimeoutMS: p.RequestTimeoutMS})
		}
	}
	slices.SortFunc(out, func(a, b ManagedDNSPlan) int {
		return strings.Compare(a.Config.Network+"/"+a.Config.Pool, b.Config.Network+"/"+b.Config.Pool)
	})
	return out, nil
}

func (d ManagedDNSDefinition) registrationNames(zone string, registrations []DNSRegistration) ([]DNSName, error) {
	owners := map[string]string{}
	services := map[string]bool{}
	var out []DNSName
	for _, r := range registrations {
		if r.Tenant != d.Tenant || r.Network != d.Network || !id(r.App) || !id(r.Service) || len(r.Aliases) > 32 || len(r.Addresses) < 1 || len(r.Addresses) > 2 {
			return nil, ErrProtocol
		}
		owner := r.App + "/" + r.Service
		task := "workload/task/" + r.Tenant + "/" + r.App + "/" + r.Service
		if r.Task != "" {
			parts := strings.Split(strings.TrimPrefix(r.Task, task+"/"), "/")
			if !strings.HasPrefix(r.Task, task+"/") || len(parts) != 2 || !id(parts[0]) || !strings.HasPrefix(parts[1], "r") {
				return nil, ErrProtocol
			}
			ordinal, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "r"), 10, 32)
			if err != nil || ordinal == 0 || ordinal > 128 || parts[1] != "r"+strconv.FormatUint(ordinal, 10) {
				return nil, ErrProtocol
			}
			task = r.Task
		}
		if services[task] {
			return nil, ErrProtocol
		}
		services[task] = true
		labels := append([]string{r.Service + "." + r.App}, r.Aliases...)
		var names []string
		localNames := map[string]bool{}
		for _, label := range labels {
			name, err := canonicalName(label, zone)
			if err != nil || localNames[name] || owners[name] != "" && owners[name] != owner {
				return nil, ErrProtocol
			}
			localNames[name] = true
			owners[name] = owner
			names = append(names, name)
		}
		endpoints := map[string]bool{}
		families := map[string]bool{}
		prefix := task + "/"
		for _, address := range r.Addresses {
			parts := strings.Split(strings.TrimPrefix(address.Endpoint, prefix), "/")
			if !strings.HasPrefix(address.Endpoint, prefix) || len(parts) != 2 || !id(parts[0]) || parts[1] != "0" && parts[1] != "1" || address.Generation == 0 || endpoints[address.Endpoint] || families[parts[1]] {
				return nil, ErrProtocol
			}
			endpoints[address.Endpoint] = true
			families[parts[1]] = true
			for _, name := range names {
				if len(out) >= maxRecords {
					return nil, ErrProtocol
				}
				out = append(out, DNSName{Name: name, Endpoint: address.Endpoint, Generation: address.Generation})
			}
		}
	}
	slices.SortFunc(out, func(a, b DNSName) int {
		return strings.Compare(a.Name+"\x00"+a.Endpoint, b.Name+"\x00"+b.Endpoint)
	})
	return out, nil
}

// Names is the name set a managed DNS serves for registrations (the same
// one its plans carry), for reading back. It allocates and checks nothing
// beyond the registrations' own shape.
func (d ManagedDNSDefinition) Names(registrations []DNSRegistration) ([]DNSName, error) {
	zone, err := Domain(d.Policy.Zone)
	if err != nil {
		return nil, err
	}
	return d.registrationNames(zone, registrations)
}
