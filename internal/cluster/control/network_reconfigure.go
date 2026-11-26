// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

type NetworkReconfigure struct {
	Target  tenancy.TUNDefinition
	Members []tenancy.NetworkChangeVersion
}

func (p Policy) reconfigureNetwork(s state.State, c access.Catalog, r Resources, op UserOperation) (tenancy.Networks, map[string][]byte, error) {
	var q NetworkReconfigure
	if canonical(op.Change.Payload, &q) != nil || len(q.Members) == 0 || len(q.Members) > 32 || q.Target.Members == nil || len(q.Target.Members) > 32 || op.Change.Expected != r.Networks.Revision() {
		return r.Networks, nil, access.ErrConflict
	}
	sortChangeVersions(q.Members)
	rows, err := r.Networks.TUNSources(q.Target.Tenant, q.Target.Name)
	if err != nil || len(rows) != len(q.Members) {
		return r.Networks, nil, ErrCatalog
	}
	if q.Target.GatewayMode == "" {
		q.Target.GatewayMode = rows[0].Network.GatewayMode
		for _, row := range rows {
			if row.Network.GatewayMode != q.Target.GatewayMode {
				return r.Networks, nil, ErrCatalog
			}
		}
	}
	for i := range q.Target.Members {
		member := &q.Target.Members[i]
		owner, err := p.workNodeOwner(s, member.Node)
		if err != nil || member.Owner != ([32]byte{}) && member.Owner != owner || c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Target.Tenant, access.ManageNetwork, member.Node) != nil {
			return r.Networks, nil, access.ErrDenied
		}
		member.Owner = owner
	}
	if len(q.Target.Members) == 0 {
		policies, err := p.ManagedDNS(s)
		if err != nil || policies[services.ManagedDNSKey(q.Target.Tenant, q.Target.Name)].Definition.Policy.Enabled {
			return r.Networks, nil, ErrCatalog
		}
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return r.Networks, nil, err
	}
	descriptors := map[string][]services.RetiredNativeSource{}
	for i, row := range rows {
		version := q.Members[i]
		change, exists := r.Networks.Change(q.Target.Tenant, row.Network.ID)
		if version.Tenant != q.Target.Tenant || version.ID != row.Network.ID || !exists || change.Generation != version.Generation || change.Revision != version.Revision || change.Phase != tenancy.ChangeFenced {
			return r.Networks, nil, ErrCatalog
		}
		for _, key := range []string{row.BridgeKey, row.TunnelKey} {
			if key == "" {
				continue
			}
			source, found := projection.ManagedSources[key]
			object := s.Object(key)
			if !found || source.Closed == nil || object.Present || object.Generation == 0 {
				return r.Networks, nil, ErrCatalog
			}
			descriptors[version.ID] = append(descriptors[version.ID], services.RetiredNativeSource{Key: key, Generation: object.Generation, Revision: object.Revision, Bridge: source.Bridge, Tunnel: source.Tunnel})
		}
	}
	authority, err := projection.addressAuthority(p.Cluster)
	if err != nil {
		return r.Networks, nil, err
	}
	authority, next, err := authority.ReplaceTUN(c, r.Networks, r.Quotas, op.Change.Principal, op.Change.Expected, q.Members, q.Target, descriptors)
	if err != nil || r.Quotas.ValidateNetworks(next) != nil {
		if err == nil {
			err = ErrCatalog
		}
		return r.Networks, nil, err
	}
	writes, err := p.networkTransitionWrites(s, authority, next, q.Target.Tenant, q.Target.Name, len(q.Target.Members) != 0)
	return next, writes, err
}
