// SPDX-License-Identifier: Apache-2.0

package control

import (
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

type ResourceEntry struct {
	DNS     *DNSPolicyView `json:",omitempty"`
	Key     string
	Limit   *tenancy.NodeLimit `json:",omitempty"`
	Network *tenancy.Network   `json:",omitempty"`
	// Route is a cross-tenant route. On a tenant's page the other side's
	// prefix is left out (the zero prefix): a tenant sees the peer network
	// only by name (RouteNames).
	Route      *tenancy.Route `json:",omitempty"`
	RouteNames *RouteNames    `json:",omitempty"`
	// Bridge is a virtual bridge (key "bridge/<A tenant>/<ID>"). Both sides'
	// tenants see it; it names the peer network, never its addresses.
	Bridge      *tenancy.VirtualBridge `json:",omitempty"`
	Change      *NetworkChangeStatus   `json:",omitempty"`
	Reservation *tenancy.Reservation   `json:",omitempty"`
	// System is the system network setting (key "system"). A tenant's page
	// carries only its range; the every-tenant page (tenant "") also its
	// users. Its members are Network rows of tenant "".
	System *tenancy.SystemPolicy `json:",omitempty"`
}

// RouteNames are the logical names of a route's two member networks (the
// member ID for a plain network; empty once the member is gone).
type RouteNames struct{ Source, Destination string }

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
	visible := r.Networks.VisibleNetworks(c, actor)
	if tenant == "" {
		// The system network has no tenant, so no tenant grant shows it;
		// the every-tenant page (system administrators) lists its members.
		visible = append(visible, r.Networks.SystemMembers()...)
	}
	for _, network := range visible {
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
		if tenant != "" && v.Source.Tenant != tenant {
			v.Source.Prefix = netip.Prefix{}
		}
		if tenant != "" && v.Destination.Tenant != tenant {
			v.Destination.Prefix = netip.Prefix{}
		}
		names := RouteNames{Source: r.Networks.LogicalName(v.Source.Tenant, v.Source.Network), Destination: r.Networks.LogicalName(v.Destination.Tenant, v.Destination.Network)}
		entries = append(entries, ResourceEntry{Key: "route/" + v.Source.Tenant + "/" + v.ID, Route: &v, RouteNames: &names})
	}
	for _, bridge := range r.Networks.VisibleBridges(c, actor) {
		if tenant != "" && bridge.A.Tenant != tenant && bridge.B.Tenant != tenant {
			continue
		}
		v := bridge
		entries = append(entries, ResourceEntry{Key: "bridge/" + v.A.Tenant + "/" + v.ID, Bridge: &v})
	}
	for _, reservation := range r.Quotas.Reservations() {
		if !allowed(reservation.Tenant) {
			continue
		}
		v := reservation
		entries = append(entries, ResourceEntry{Key: "reservation/" + v.Key, Reservation: &v})
	}
	// Every page has the system row (the fixed range no tenant network may
	// overlap); only the every-tenant page names the servers using it.
	v := r.Networks.SystemPolicy()
	if tenant != "" {
		v.Users = nil
	}
	entries = append(entries, ResourceEntry{Key: "system", System: &v})
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
