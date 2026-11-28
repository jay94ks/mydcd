// SPDX-License-Identifier: Apache-2.0

package control

import (
	"cmp"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"net/netip"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/network"
)

// Listener and serving budgets are projected from original committed sources,
// including Drain until signed Gone, and pending immutable move artifacts.
// Endpoint comparisons share the real listener overlap policy; pending demand
// has no fake Listener generation or second reservation journal.
func (p Policy) projectIngress(s state.State, result *ResourceProjection, checked ...Apps) error {
	if len(checked) > 1 {
		return ErrCatalog
	}
	type usage struct{ instances, listeners, requests, connections, buffers int }
	type listenerUse struct {
		key      string
		endpoint network.Listener
	}
	type servingDemand struct {
		scope deployment.AppScope
		owner [32]byte
		usage usage
	}
	var users access.Catalog
	var apps Apps

	var err error
	users, err = p.Catalog(s)
	if err != nil {
		return err
	}
	if len(checked) == 1 {
		apps = checked[0]
	} else {
		apps, err = p.readOnlyApps(s)
		if err != nil {
			return err
		}
	}

	type sharedRoute struct{ key, tenant string }
	sharedRoutes := map[string]sharedRoute{}
	used := map[string]usage{}
	groups := map[string]servingDemand{}
	ports := map[string][]listenerUse{}
	nodeListeners := map[string]int{}
	admit := func(key string, scope deployment.AppScope, node string, owner [32]byte, d deployment.IngressDeclaration) error {
		groupKey := node + "/" + key
		prior, found := groups[groupKey]
		if found && (prior.scope != scope || prior.owner != owner) {
			return ErrCatalog
		}
		var endpoints []network.Listener
		shared := false
		for _, l := range d.Listeners {
			if l.Shared != "" {
				shared = true
				for _, route := range deployment.IngressRoutes(d) {
					gateway := route.Gateway
					if gateway == "" {
						gateway = "local"
					}
					for _, kind := range []string{"external", "local"} {
						if gateway != "both" && gateway != kind {
							continue
						}
						pattern := node + "/" + l.Shared + "/" + kind + "/" + route.Host + "/" + route.Prefix
						// Apps of one tenant may serve a host+prefix together
						// (`app deploy --force`); another tenant never.
						if prior, ok := sharedRoutes[pattern]; ok && prior.key != key && prior.tenant != scope.Tenant {
							return ErrCatalog
						}
						sharedRoutes[pattern] = sharedRoute{key, scope.Tenant}
					}
				}
				continue
			}

			a, err := netip.ParseAddrPort(l.Address)
			if err != nil || a.Port() == 0 || a.Addr().Is4In6() || a.Addr().Zone() != "" || a.Addr().IsMulticast() {
				return ErrCatalog
			}
			for _, proto := range []uint8{6, 17} {
				if proto == 17 && !l.HTTP3 {
					continue
				}
				endpoint := network.Listener{Address: a.Addr(), Port: a.Port(), Protocol: proto}
				for _, prior := range ports[node] {
					if prior.key != key && network.ListenerConflict(prior.endpoint, endpoint) {
						return ErrCatalog
					}
				}
				for _, prior := range endpoints {
					if network.ListenerConflict(prior, endpoint) {
						return ErrCatalog
					}
				}
				endpoints = append(endpoints, endpoint)
			}
		}
		if len(endpoints) == 0 && !shared {
			return ErrCatalog
		}
		// The same accepted app resource is cold-replaced, never concurrently
		// started. Hold its old and future endpoints, charging peak capacity in
		// every dimension. Other apps cannot reuse either endpoint meanwhile.
		peak := usage{1, max(prior.usage.listeners, len(endpoints)), max(prior.usage.requests, d.Runtime.MaxRequests), max(prior.usage.connections, d.Runtime.MaxConnections), max(prior.usage.buffers, d.Runtime.BufferBytes)}
		delta := usage{peak.instances - prior.usage.instances, peak.listeners - prior.usage.listeners, peak.requests - prior.usage.requests, peak.connections - prior.usage.connections, peak.buffers - prior.usage.buffers}
		if delta.listeners > 256-nodeListeners[node] {
			return ErrCatalog
		}
		for _, tenant := range []string{"", scope.Tenant} {
			lim, ok := result.Resources.Quotas.Limit(tenant, node)
			if !ok || !result.Resources.Quotas.SameOwner(node, lim.Owner, owner) {
				return ErrCatalog
			}
			id := tenant + "/" + node
			u := used[id]
			want, ceiling := []int{delta.instances, delta.listeners, delta.requests, delta.connections, delta.buffers}, []int{lim.MaxIngressInstances, lim.MaxIngressListeners, lim.MaxIngressRequests, lim.MaxIngressConnections, lim.IngressBufferBytes}
			current := []int{u.instances, u.listeners, u.requests, u.connections, u.buffers}
			for i, n := range want {
				if n < 0 || current[i] > ceiling[i] || n > ceiling[i]-current[i] {
					return ErrCatalog
				}
				current[i] += n
			}
			used[id] = usage{current[0], current[1], current[2], current[3], current[4]}
		}
		for _, endpoint := range endpoints {
			ports[node] = append(ports[node], listenerUse{key: key, endpoint: endpoint})
		}
		groups[groupKey] = servingDemand{scope: scope, owner: owner, usage: peak}
		nodeListeners[node] += delta.listeners
		return nil
	}
	objects := s.Objects("")
	for _, key := range desired.Sorted(result.Goals) {
		g := result.Goals[key]
		if g.Goal.Kind != "ingress" {
			continue
		}
		spec, err := deployment.ResolveIngress(p.Cluster, key, objects[key], objects)
		if err != nil {
			return err
		}
		if spec.DynamicBackends {
			spec.BindingRevision = s.Index()
			members, err := p.Members(s)
			if err != nil {
				return err
			}
			var apps Apps
			if len(checked) == 1 {
				apps = checked[0]
			} else {
				apps, err = p.readOnlyApps(s)
				if err != nil {
					return err
				}
			}
			entry := apps.entries[appKey(g.Goal.Tenant, g.Goal.App)]
			for service := range spec.Services {
				for at := range spec.Services[service].Backends {
					backend := &spec.Services[service].Backends[at]
					goal := result.Goals[backend.Task].Goal
					backend.Suspended = !members.WorkKey(p.currentResourceKey(s, goal.Owner, true))
					if _, bound := apps.Binding(deployment.ObjectRef{Key: backend.Task, Generation: backend.Generation, Revision: backend.Revision}); !bound {
						backend.Suspended = true
					}
					if wave, active := entry.Inventory.Retirement(); active && wave.KeepExecution && !wave.Preserves(backend.Task) {
						backend.Draining = true
					}
				}
			}
		}
		entry, exists := apps.entries[appKey(g.Goal.Tenant, g.Goal.App)]
		if exists {
			user, ok := users.User(entry.Origin.Session.User)
			spec.SystemWildcard = ok && user.SystemAdmin
		}
		g.Ingress = &spec
		result.Goals[key] = g
		if spec.Lifecycle.Released() {
			continue
		}
		var declaration deployment.IngressDeclaration
		if json.Unmarshal(g.Goal.Config, &declaration) != nil {
			return ErrCatalog
		}
		if err := admit(key, deployment.AppScope{Cluster: g.Goal.Cluster, Tenant: g.Goal.Tenant, App: g.Goal.App, Deployment: g.Goal.Deployment}, g.Goal.Node, g.Goal.Owner, declaration); err != nil {
			return err
		}
	}
	for _, held := range result.MoveHolds {
		if held.Demand.Ingress == nil {
			continue
		}
		if err := admit(held.Demand.Key, deployment.AppScope{Cluster: held.Scope.Cluster, Tenant: held.Scope.Tenant, App: held.Scope.App, Deployment: held.Scope.Deployment}, held.Demand.Node, held.Demand.Owner, *held.Demand.Ingress); err != nil {
			return err
		}
	}
	return nil
}

// Consumer IDs are derived from their original desired edges. Current Goals
// and their pending cold replacements share an edge only for the same native
// source, tenant, node and owner; no running/native generation is synthesized.
type networkConsumerUsage struct {
	tenant, node string
	owner        [32]byte
	consumers    map[string]bool
	base         int
}

func networkConsumerUsageProjection(p ResourceProjection) (map[string]networkConsumerUsage, error) {
	groups := map[deployment.AppScope][]deployment.Step{}
	for _, key := range desired.Sorted(p.Goals) {
		g := p.Goals[key].Goal
		if g.Lifecycle != nil && g.Lifecycle.Released() {
			continue
		}
		scope := deployment.AppScope{Cluster: g.Cluster, Tenant: g.Tenant, App: g.App, Deployment: g.Deployment}
		step := deployment.Step{Key: key, Kind: g.Kind, Node: g.Node, Owner: g.Owner, Goal: g.Config}
		for _, dep := range g.Dependencies {
			step.Dependencies = append(step.Dependencies, deployment.Dependency{Key: dep.Key})
		}
		if len(g.Follow) != 0 {
			step.Identity = append([]string(nil), g.Follow...)
			for _, task := range g.Follow {
				step.Dependencies = append(step.Dependencies, deployment.Dependency{Key: task, Condition: deployment.Healthy})
			}
		}
		groups[scope] = append(groups[scope], step)
	}
	out := map[string]networkConsumerUsage{}
	add := func(d deployment.NetworkConsumerDemand) error {
		u, found := out[d.Source]
		if found && (u.tenant != d.Tenant || u.node != d.Node || u.owner != d.Owner) {
			return ErrCatalog
		}
		if !found {
			u = networkConsumerUsage{tenant: d.Tenant, node: d.Node, owner: d.Owner, consumers: map[string]bool{}}
		}
		u.consumers[d.Consumer] = true
		out[d.Source] = u
		return nil
	}
	for scope, steps := range groups {
		demands, err := deployment.NetworkConsumers(scope, steps)
		if err != nil {
			return nil, err
		}
		for _, d := range demands {
			if err := add(d); err != nil {
				return nil, err
			}
		}
	}
	for _, d := range p.MoveConsumers {
		if err := add(d); err != nil {
			return nil, err
		}
	}
	for _, demand := range p.RouteConsumers {
		if err := add(demand); err != nil {
			return nil, err
		}
	}
	for key, source := range p.ManagedSources {
		if source.Tunnel != nil && !source.Tunnel.Lifecycle.Released() {
			if err := add(deployment.NetworkConsumerDemand{Source: key, Consumer: key + "/packet-plane", Tenant: source.Network.Tenant, Node: source.Network.Node, Owner: source.Network.Owner}); err != nil {
				return nil, err
			}
		}
	}
	for key, count := range p.ManagedDNSConsumers {
		source, found := p.ManagedSources[key]
		if !found || count < 0 {
			return nil, ErrCatalog
		}
		u, exists := out[key]
		if exists && (u.tenant != source.Network.Tenant || u.node != source.Network.Node || u.owner != source.Network.Owner) {
			return nil, ErrCatalog
		}
		if !exists {
			u = networkConsumerUsage{tenant: source.Network.Tenant, node: source.Network.Node, owner: source.Network.Owner, consumers: map[string]bool{}}
		}
		u.base = count
		out[key] = u
	}
	return out, nil
}

// These are projected desired edges, not local pin receipts. Each source's
// distinct edges contribute to the SAME node/global and tenant totals.
func admitConsumerUsage(p ResourceProjection, used map[string]networkConsumerUsage, tenant, node string, owner [32]byte) error {
	global, gok := p.Resources.Quotas.Limit("", node)
	scoped, sok := p.Resources.Quotas.Limit(tenant, node)
	if !gok || !sok || tenant == "" || node == "" || !p.Resources.Quotas.SameOwner(node, global.Owner, owner) || !p.Resources.Quotas.SameOwner(node, scoped.Owner, owner) {
		return ErrCatalog
	}
	total, own := 0, 0
	for _, u := range used {
		if u.node != node {
			continue
		}
		if !p.Resources.Quotas.SameOwner(node, u.owner, owner) || u.base < 0 || u.base > global.MaxConsumers-total || len(u.consumers) > global.MaxConsumers-total-u.base {
			return ErrCatalog
		}
		count := u.base + len(u.consumers)
		total += count
		if u.tenant == tenant {
			if count > scoped.MaxConsumers-own {
				return ErrCatalog
			}
			own += count
		}
	}
	return nil
}

func admitIngressConsumers(p ResourceProjection, target deployment.GoalResources) error {
	used, err := networkConsumerUsageProjection(p)
	if err != nil {
		return err
	}
	return admitConsumerUsage(p, used, target.Goal.Tenant, target.Goal.Node, target.Goal.Owner)
}

// Ordinary policy changes can stop new effects while retaining old native
// references. An accepted move additionally reserves its future edges, so new
// competitors or a quota shrink cannot consume that prepared target capacity.
func admitMoveConsumers(p ResourceProjection) error {
	if len(p.MoveConsumers) == 0 {
		return nil
	}
	used, err := networkConsumerUsageProjection(p)
	if err != nil {
		return err
	}
	for _, d := range p.MoveConsumers {
		if err := admitConsumerUsage(p, used, d.Tenant, d.Node, d.Owner); err != nil {
			return err
		}
	}
	return nil
}

// admitIngressDeclaration checks what an app ingress may claim beyond its
// tenant's domains (admitTenantIngressHosts): cluster app route hosts stay
// protected and only a system administrator routes "*". It is checked again
// at native permit time, so a revoked admin keeps no "*" route.
func (p Policy) admitIngressDeclaration(s state.State, tenant, actor string, d deployment.IngressDeclaration) error {
	if err := p.admitClusterAppRouteClaims(s, d); err != nil {
		return err
	}
	shared := false
	for _, listener := range d.Listeners {
		shared = shared || listener.Shared != ""
	}
	if !shared {
		return nil
	}
	users, err := p.Catalog(s)
	if err != nil {
		return err
	}
	u, ok := users.User(actor)
	if !ok || !u.Enabled {
		return access.ErrDenied
	}
	for _, route := range deployment.IngressRoutes(d) {
		if route.Host == "*" && !u.SystemAdmin {
			return access.ErrDenied
		}
	}
	return nil
}
func (p Policy) admitIngressBlueprint(s state.State, b deployment.Blueprint) error {
	var others []ingressRouteUse
	loaded := false
	for _, step := range b.Steps() {
		if step.Kind != "ingress" {
			continue
		}
		var d deployment.IngressDeclaration
		if json.Unmarshal(step.Goal, &d) != nil {
			return ErrCatalog
		}
		if err := p.admitIngressDeclaration(s, b.Scope().Tenant, b.Scope().Actor, d); err != nil {
			return err
		}
		if !loaded {
			var err error
			if others, err = p.ingressRouteUses(s); err != nil {
				return err
			}
			loaded = true
		}
		if err := p.admitTenantIngressHosts(s, b.Scope().Tenant, d, others); err != nil {
			return err
		}
	}
	return nil
}

// ingressRouteUse is one host+prefix an accepted app serves on a server's
// shared listener and gateway.
type ingressRouteUse struct {
	Tenant, App                           string
	Node, Listener, Gateway, Host, Prefix string
}

func ingressRouteUsesOf(tenant, app, node string, d deployment.IngressDeclaration) []ingressRouteUse {
	var out []ingressRouteUse
	for _, l := range d.Listeners {
		if l.Shared == "" {
			continue
		}
		for _, r := range deployment.IngressRoutes(d) {
			gateway := cmp.Or(r.Gateway, "local")
			for _, kind := range []string{"external", "local"} {
				if gateway == "both" || gateway == kind {
					out = append(out, ingressRouteUse{tenant, app, cmp.Or(d.Node, node), l.Shared, kind, strings.ToLower(r.Host), r.Prefix})
				}
			}
		}
	}
	return out
}

// ingressRouteUses lists the routes of every accepted app ingress, draining
// ones included (they still serve until gone).
func (p Policy) ingressRouteUses(s state.State) ([]ingressRouteUse, error) {
	projection, err := p.ProjectResources(s)
	if err != nil {
		return nil, err
	}
	var out []ingressRouteUse
	for _, g := range projection.Goals {
		if g.Goal.Kind != "ingress" {
			continue
		}
		var d deployment.IngressDeclaration
		if json.Unmarshal(g.Goal.Config, &d) != nil {
			return nil, ErrCatalog
		}
		out = append(out, ingressRouteUsesOf(g.Goal.Tenant, g.Goal.App, g.Goal.Node, d)...)
	}
	return out, nil
}

// admitIngressRouteOverlap stops a plan whose new route uses a host+prefix
// that another app of the same tenant serves on that server and gateway.
// `app deploy --force` skips it, and both apps then serve the route (the
// gateway rotates requests across them). Routes this app already serves are
// not new, so a forced share survives the app's later deploys and CD syncs.
func (p Policy) admitIngressRouteOverlap(s state.State, b deployment.Blueprint) error {
	var mine []ingressRouteUse
	for _, step := range b.Steps() {
		if step.Kind != "ingress" {
			continue
		}
		var d deployment.IngressDeclaration
		if json.Unmarshal(step.Goal, &d) != nil {
			return ErrCatalog
		}
		mine = append(mine, ingressRouteUsesOf(b.Scope().Tenant, b.Scope().App, step.Node, d)...)
	}
	if len(mine) == 0 {
		return nil
	}
	others, err := p.ingressRouteUses(s)
	if err != nil {
		return err
	}
	return ingressRouteOverlap(b.Scope().Tenant, b.Scope().App, mine, others)
}

func ingressRouteOverlap(tenant, app string, mine, others []ingressRouteUse) error {
	key := func(u ingressRouteUse) ingressRouteUse { u.Tenant, u.App = "", ""; return u }
	held := map[ingressRouteUse]bool{}
	for _, o := range others {
		if o.Tenant == tenant && o.App == app {
			held[key(o)] = true
		}
	}
	for _, m := range mine {
		if held[key(m)] {
			continue
		}
		for _, o := range others {
			if o.Tenant == m.Tenant && o.App != m.App && key(o) == key(m) {
				return &deployment.InputError{Code: "INGRESS_ROUTE_TAKEN", Path: "x-sfc.ingress." + m.Host + m.Prefix + " (" + o.App + ")"}
			}
		}
	}
	return nil
}
