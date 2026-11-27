// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Expected is the Networks revision; Members fixes every original change CAS.
// The outer operation independently fixes Resources' root revision.
type NetworkChangeCommit struct {
	Tenant, Network string
	Members         []tenancy.NetworkChangeVersion
}

func (p Policy) commitNetworkChange(s state.State, c access.Catalog, r Resources, op UserOperation) (tenancy.Networks, map[string][]byte, error) {
	var q NetworkChangeCommit
	if canonical(op.Change.Payload, &q) != nil || q.Network == "" || len(q.Members) == 0 || len(q.Members) > 32 || op.Change.Expected != r.Networks.Revision() {
		return r.Networks, nil, access.ErrConflict
	}
	sortChangeVersions(q.Members)
	rows, err := r.Networks.TUNSources(q.Tenant, q.Network)
	if err != nil || len(rows) != len(q.Members) {
		return r.Networks, nil, ErrCatalog
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return r.Networks, nil, err
	}
	for i, row := range rows {
		version := q.Members[i]
		change, found := r.Networks.Change(q.Tenant, row.Network.ID)
		if version.Tenant != q.Tenant || version.ID != row.Network.ID || !found || change.Generation != version.Generation || change.Revision != version.Revision || change.Phase != tenancy.ChangeFenced || change.SourceClosed == nil || change.Target.Logical != q.Network {
			return r.Networks, nil, ErrCatalog
		}
		owner, err := p.workNodeOwner(s, change.Target.Node)
		if err != nil || owner != change.Target.Owner || c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.ManageNetwork, change.Target.Node) != nil {
			return r.Networks, nil, access.ErrDenied
		}
		for _, key := range []string{row.BridgeKey, row.TunnelKey} {
			if key == "" {
				continue
			}
			source, known := projection.ManagedSources[key]
			object := s.Object(key)
			if !known || source.Closed == nil || object.Present || object.Generation == 0 {
				return r.Networks, nil, ErrCatalog
			}
		}
	}
	authority, err := projection.addressAuthority(p.Cluster)
	if err != nil {
		return r.Networks, nil, err
	}
	authority, next, err := authority.CommitNetworkChanges(c, r.Networks, op.Change.Principal, q.Members)
	if err != nil || r.Quotas.ValidateNetworks(next) != nil {
		if err == nil {
			err = ErrCatalog
		}
		return r.Networks, nil, err
	}
	writes, err := p.networkTransitionWrites(s, authority, next, q.Tenant, q.Network, true)
	return next, writes, err
}

// sortChangeVersions puts member versions in the order TUNSources returns
// members (by network ID), so a client may list them in any order.
func sortChangeVersions(v []tenancy.NetworkChangeVersion) {
	slices.SortFunc(v, func(a, b tenancy.NetworkChangeVersion) int {
		return strings.Compare(a.Tenant+"/"+a.ID, b.Tenant+"/"+b.ID)
	})
}

// Both target replacement and membership changes publish the same Authority,
// serial floors and source rows, without a second checkpoint or executor.
func (p Policy) networkTransitionWrites(s state.State, authority services.Authority, next tenancy.Networks, tenant, name string, publish bool) (map[string][]byte, error) {
	apps, err := p.Apps(s)
	if err != nil {
		return nil, err
	}
	network := appNetworkState{Revision: 1, Authority: authority}
	if apps.network != nil {
		network = *apps.network
		network.Authority = authority
		network.Groups = slices.Clone(network.Groups)
		for i, group := range network.Groups {
			group.Owners = slices.Clone(group.Owners)
			group.Owners = slices.DeleteFunc(group.Owners, func(row AppDNSOwner) bool { _, exists := authority.ReferenceConsumer(row.Reference); return !exists })
			group.Digest = appDNSDigest(group.Owners)
			network.Groups[i] = group
		}
	}
	apps.network = &network
	writes, code := p.appsCheckpoint(s, apps)
	if code != state.Applied {
		return nil, ErrCatalog
	}
	if publish {
		sources, err := newManagedNetworkSources(s, next, tenant, name)
		if err != nil {
			return nil, err
		}
		for key, raw := range sources {
			writes[key] = raw
		}
	}
	return writes, nil
}
