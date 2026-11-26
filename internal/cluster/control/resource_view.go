// SPDX-License-Identifier: Apache-2.0

package control

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
)

type ResourceEntry struct {
	DNS         *DNSPolicyView `json:",omitempty"`
	Key         string
	Limit       *tenancy.NodeLimit   `json:",omitempty"`
	Network     *tenancy.Network     `json:",omitempty"`
	Route       *tenancy.Route       `json:",omitempty"`
	Change      *NetworkChangeStatus `json:",omitempty"`
	Reservation *tenancy.Reservation `json:",omitempty"`
}

// Public current-candidate metadata. The full retained proof/previous-target
// history stays in the existing checkpoint, not in each paginated reply.
type NetworkChangeStatus struct {
	ID                                   string
	Generation, Revision, TargetRevision uint64
	Phase                                tenancy.ChangePhase
	MetadataOnly                         bool `json:",omitempty"`
	Target                               tenancy.Network
	Native                               string
}

// ResourcePage filters before pagination and never exposes another tenant's
// resources. Global limits are policy, not a listing of other tenants' usage.
func (r Resources) Page(c access.Catalog, actor, tenant, after string, authorities ...services.Authority) ([]ResourceEntry, string, error) {
	if tenant == "" {
		if !c.SystemAllowed(actor) {
			return nil, "", access.ErrDenied
		}
	} else if c.Authorize(actor, tenant, access.Read, "") != nil {
		return nil, "", access.ErrDenied
	}
	var entries []ResourceEntry
	if len(authorities) > 1 || len(authorities) == 1 && authorities[0].Cluster() != r.Networks.Cluster() {
		return nil, "", access.ErrInvalid
	}
	allowed := func(scope string) bool { return tenant == "" || scope == tenant }
	for _, limit := range r.Quotas.Limits() {
		if !allowed(limit.Tenant) {
			continue
		}
		v := limit
		entries = append(entries, ResourceEntry{Key: "limit/" + limit.Tenant + "/" + limit.Node, Limit: &v})
	}
	for _, network := range r.Networks.VisibleNetworks(c, actor) {
		if !allowed(network.Tenant) {
			continue
		}
		v := network
		entry := ResourceEntry{Key: "network/" + v.Tenant + "/" + v.ID, Network: &v}
		if change, ok := r.Networks.Change(v.Tenant, v.ID); ok {
			entry.Change = &NetworkChangeStatus{ID: change.ID, Generation: change.Generation, Revision: change.Revision, TargetRevision: change.TargetRevision, Phase: change.Phase, Target: change.Target, Native: tenancy.CandidateNativeID(change), MetadataOnly: change.MetadataOnly}
		}
		entries = append(entries, entry)
	}
	for _, route := range r.Networks.VisibleRoutes(c, actor) {
		if tenant != "" && route.Source.Tenant != tenant && route.Destination.Tenant != tenant {
			continue
		}
		v := route
		entries = append(entries, ResourceEntry{Key: "route/" + v.Source.Tenant + "/" + v.ID, Route: &v})
	}
	for _, reservation := range r.Quotas.Reservations() {
		if !allowed(reservation.Tenant) {
			continue
		}
		v := reservation
		entries = append(entries, ResourceEntry{Key: "reservation/" + v.Key, Reservation: &v})
	}
	slices.SortFunc(entries, func(a, b ResourceEntry) int { return strings.Compare(a.Key, b.Key) })
	var page []ResourceEntry
	for _, entry := range entries {
		if entry.Key <= after {
			continue
		}
		if len(page) == 8 {
			return page, page[len(page)-1].Key, nil
		}
		page = append(page, entry)
	}
	return page, "", nil
}

// PlanningResources is the SAME committed reservation/network view consumed by
// the existing Blueprint core. Adapter features/native readiness are left unset
// until their real consumers connect; no observation can enlarge these quotas.
func (p Policy) PlanningResources(s state.State, actor, tenant string) (deployment.PlanningContext, error) {
	projection, err := p.ProjectResources(s)
	if err != nil {
		return deployment.PlanningContext{}, err
	}
	return p.planningResources(s, actor, tenant, projection)
}
func (p Policy) planningResources(s state.State, actor, tenant string, projection ResourceProjection) (deployment.PlanningContext, error) {
	c, err := p.Catalog(s)
	if err != nil || c.Authorize(actor, tenant, access.Read, "") != nil {
		return deployment.PlanningContext{}, access.ErrDenied
	}
	d, err := p.Members(s)
	if err != nil {
		return deployment.PlanningContext{}, err
	}
	r := projection.Resources
	result := deployment.PlanningContext{Addresses: projection.AddressSources, Cluster: p.Cluster, Actor: actor, Tenant: tenant, Networks: r.Networks, Nodes: map[string]deployment.PlanningNode{}, Current: s.Objects(""), Reserved: map[string]workload.Resources{}}
	result.Planned = projection.MoveHolds
	result.HostPorts = projection.HostPorts
	for _, e := range d.Entries {
		if !membership.FullMember(e) || c.Authorize(actor, tenant, access.Read, e.Peer.ID) != nil {
			continue
		}
		global, ok := r.Quotas.Limit("", e.Peer.ID)
		scoped, grant := r.Quotas.Limit(tenant, e.Peer.ID)
		key, _ := identity.ParseKey(e.CurrentPeer().Key)
		if !ok || !grant || global.Owner != key || scoped.Owner != key {
			continue
		}
		all, err := r.Quotas.Usage("", e.Peer.ID)
		if err != nil {
			return result, err
		}
		own, err := r.Quotas.Usage(tenant, e.Peer.ID)
		if err != nil {
			return result, err
		}
		heldAll, err := projection.moveUsage("", e.Peer.ID)
		if err != nil {
			return result, err
		}
		heldOwn, err := projection.moveUsage(tenant, e.Peer.ID)
		if err != nil {
			return result, err
		}
		all, err = addDemand(all, heldAll)
		if err != nil {
			return result, err
		}
		own, err = addDemand(own, heldOwn)
		if err != nil {
			return result, err
		}
		host, _, _ := net.SplitHostPort(e.Peer.Endpoint)
		if ip, err := netip.ParseAddr(host); err == nil {
			host = ip.String()
		} else {
			host = ""
		}
		// Charge other tenants before publishing this tenant's feasible capacity.
		capacity := workload.Resources{CPU: min(scoped.Capacity.CPU, global.Capacity.CPU-(all.CPU-own.CPU)), Memory: min(scoped.Capacity.Memory, global.Capacity.Memory-(all.Memory-own.Memory))}
		result.Nodes[e.Peer.ID] = deployment.PlanningNode{ResourceKeys: lifecycle.OwnIdentityTransitions(e.Keys), Key: key, Generation: e.Revision, Revision: r.Revision, Underlay: host, Voter: e.Peer.Voter, Capacity: capacity, Used: own, Draining: !d.WorkKey(key) || d.Cordon(e.Peer.ID).Enabled}
	}
	for _, v := range r.Quotas.Reservations() {
		if v.Tenant == tenant {
			result.Reserved[v.Key] = v.Need
		}
	}
	return result, nil
}
