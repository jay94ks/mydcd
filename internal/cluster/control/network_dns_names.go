// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
)

// NetworkDNSNamesQuery selects one tenant network's managed DNS names.
type NetworkDNSNamesQuery struct {
	Network string
}

func (q NetworkDNSNamesQuery) Valid() bool { return validID(q.Network) }

// NetworkDNSName is one name the network's managed DNS answers: the app
// service (or replica) it belongs to and the reserved address it returns.
type NetworkDNSName struct {
	Name, App, Service string
	Task               string `json:",omitempty"`
	Family             string `json:",omitempty"` // "ipv4" or "ipv6", from Address
	Address            string
}

// NetworkDNSRecord is a name added by hand (services.DNSRecord). Served is
// false while an app service has the same name: the app's name is answered.
type NetworkDNSRecord struct {
	Name, Type, Value string
	TTL               uint32 `json:",omitempty"`
	Served            bool
}

// NetworkDNSNames is the committed name set of a network's managed DNS.
// Managed is false when the network has no managed DNS.
type NetworkDNSNames struct {
	Managed  bool
	Revision uint64
	Zone     string
	Names    []NetworkDNSName
	Records  []NetworkDNSRecord
}

// NetworkDNSNames reads tenant's network names for a session with Read on
// that tenant. They come from the same accepted tasks and address
// reservations the DNS owners serve; whether an owner has them yet is the
// network's DNS State.
func (p Policy) NetworkDNSNames(s state.State, session access.Session, now int64, tenant string, q NetworkDNSNamesQuery) (NetworkDNSNames, error) {
	if !validID(tenant) || !q.Valid() {
		return NetworkDNSNames{}, access.ErrInvalid
	}
	p, err := p.Current(s)
	if err != nil {
		return NetworkDNSNames{}, err
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return NetworkDNSNames{}, err
	}
	if err := catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), now, tenant, access.Read, ""); err != nil {
		return NetworkDNSNames{}, err
	}
	sources, err := p.ManagedDNS(s)
	if err != nil {
		return NetworkDNSNames{}, err
	}
	key := services.ManagedDNSKey(tenant, q.Network)
	source, ok := sources[key]
	if !ok {
		return NetworkDNSNames{Names: []NetworkDNSName{}, Records: []NetworkDNSRecord{}}, nil
	}
	definition := source.Definition
	out := NetworkDNSNames{Managed: true, Revision: s.Object(key).Revision, Names: []NetworkDNSName{}, Records: []NetworkDNSRecord{}}
	out.Zone, _ = services.Domain(definition.Policy.Zone)
	projection, err := p.ProjectResources(s)
	if err != nil || !projection.Compatible {
		return NetworkDNSNames{}, ErrCatalog
	}
	authority, err := projection.addressAuthority(p.Cluster)
	if err != nil {
		return NetworkDNSNames{}, err
	}
	registrations, err := p.managedDNSRegistrations(s, projection, definition, nil)
	if err != nil {
		return NetworkDNSNames{}, err
	}
	names, err := definition.Names(registrations)
	if err != nil {
		return NetworkDNSNames{}, err
	}
	owner := map[string]services.DNSRegistration{}
	for _, r := range registrations {
		for _, a := range r.Addresses {
			owner[a.Endpoint] = r
		}
	}
	book := authority.AddressBook()
	for _, n := range names {
		r := owner[n.Endpoint]
		row := NetworkDNSName{Name: n.Name, App: r.App, Service: r.Service, Task: r.Task}
		if a, found := book.Allocation(n.Endpoint); found && a.Generation == n.Generation {
			row.Address, row.Family = a.Address.String(), "ipv4"
			if a.Address.Is6() && !a.Address.Is4In6() {
				row.Family = "ipv6"
			}
		}
		out.Names = append(out.Names, row)
	}
	slices.SortStableFunc(out.Names, func(a, b NetworkDNSName) int { return strings.Compare(a.Name, b.Name) })
	served, shadowed, err := definition.Records(registrations)
	if err != nil {
		return NetworkDNSNames{}, err
	}
	for _, r := range served {
		out.Records = append(out.Records, NetworkDNSRecord{Name: r.Name, Type: r.Type, Value: r.Value, TTL: r.TTL, Served: true})
	}
	for _, r := range shadowed {
		out.Records = append(out.Records, NetworkDNSRecord{Name: r.Name, Type: r.Type, Value: r.Value, TTL: r.TTL})
	}
	slices.SortStableFunc(out.Records, func(a, b NetworkDNSRecord) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
