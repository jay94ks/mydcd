// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"math"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
)

// A cluster app's ingress routes (devel/design/cluster-apps.md 3.2) are a cluster
// setting next to the ingress management book, not an app: a system
// administrator puts them with `sfcli app deploy` of a cluster-app/NAME file and
// takes them away with `sfcli app down cluster-app/NAME`. A removed record keeps
// its last routes, so the ingress node drains exactly those listeners.
type ClusterAppRouteRecord struct {
	App      string
	Revision uint64
	Removed  bool `json:",omitempty"`
	Ingress  deployment.IngressDeclaration
	Origin   UserOperation
}

// ClusterAppRouteChange is put-cluster-app-route's payload.
type ClusterAppRouteChange struct {
	App     string
	Ingress deployment.IngressDeclaration
}

// ClusterAppRouteSelection is remove-cluster-app-route's payload.
type ClusterAppRouteSelection struct{ App string }

func clusterAppRouteAction(action string) bool {
	return action == "put-cluster-app-route" || action == "remove-cluster-app-route"
}

func validClusterAppRouteRecords(b IngressManagement) bool {
	seen := map[string]bool{}
	for _, r := range b.ClusterAppRoutes {
		_, routable := deployment.ClusterAppName(deployment.ClusterAppPrefix + r.App)
		if !routable || seen[r.App] || r.Revision == 0 || deployment.ValidateClusterAppIngress(r.Ingress) != nil || r.Origin.VerifyOriginal(b.Cluster) != nil || r.Origin.Change.Expected+1 != r.Revision || r.Removed != (r.Origin.Change.Action == "remove-cluster-app-route") {
			return false
		}
		switch r.Origin.Change.Action {
		case "put-cluster-app-route":
			var q ClusterAppRouteChange
			if canonical(r.Origin.Change.Payload, &q) != nil || q.App != r.App || !buildJSONEqual(q.Ingress, r.Ingress) {
				return false
			}
		case "remove-cluster-app-route":
			var q ClusterAppRouteSelection
			if canonical(r.Origin.Change.Payload, &q) != nil || q.App != r.App {
				return false
			}
		default:
			return false
		}
		seen[r.App] = true
	}
	return true
}

// ClusterAppRoute is app's current routes (found false: none, or removed).
func (b IngressManagement) ClusterAppRoute(app string) (ClusterAppRouteRecord, bool) {
	for _, r := range b.ClusterAppRoutes {
		if r.App == app {
			return r, !r.Removed
		}
	}
	return ClusterAppRouteRecord{}, false
}

// clusterAppRouteRevision is the record's revision whether or not removed
// (the Expected of the next put).
func (b IngressManagement) clusterAppRouteRevision(app string) uint64 {
	for _, r := range b.ClusterAppRoutes {
		if r.App == app {
			return r.Revision
		}
	}
	return 0
}

func (p Policy) authorizeClusterAppRoute(c access.Catalog, op UserOperation) error {
	switch op.Change.Action {
	case "put-cluster-app-route":
		var q ClusterAppRouteChange
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		if _, routable := deployment.ClusterAppName(deployment.ClusterAppPrefix + q.App); !routable || deployment.ValidateClusterAppIngress(q.Ingress) != nil {
			return access.ErrInvalid
		}
	case "remove-cluster-app-route":
		var q ClusterAppRouteSelection
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		if _, routable := deployment.ClusterAppName(deployment.ClusterAppPrefix + q.App); !routable {
			return access.ErrInvalid
		}
	default:
		return access.ErrInvalid
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
}

func (p Policy) reduceClusterAppRoute(s state.State, book *IngressManagement, op UserOperation) state.Code {
	at := -1
	for i, r := range book.ClusterAppRoutes {
		if r.App == clusterAppRouteApp(op) {
			at = i
		}
	}
	var current ClusterAppRouteRecord
	if at >= 0 {
		current = book.ClusterAppRoutes[at]
	}
	if current.Revision != op.Change.Expected || current.Revision == math.MaxUint64 {
		return state.ConditionFailed
	}
	next := ClusterAppRouteRecord{App: clusterAppRouteApp(op), Revision: current.Revision + 1, Origin: op}
	switch op.Change.Action {
	case "put-cluster-app-route":
		var q ClusterAppRouteChange
		if canonical(op.Change.Payload, &q) != nil {
			return state.Invalid
		}
		if !p.clusterAppRouteFree(s, q.Ingress) || !p.clusterAppHostsOnClusterDomains(s, q.Ingress) {
			return state.ConditionFailed
		}
		next.Ingress = q.Ingress
	case "remove-cluster-app-route":
		if at < 0 || current.Removed {
			return state.ConditionFailed
		}
		next.Ingress, next.Removed = current.Ingress, true
	}
	book.ClusterAppRoutes = slices.Clone(book.ClusterAppRoutes)
	if at < 0 {
		if len(book.ClusterAppRoutes) >= len(deployment.ClusterAppRoutable) {
			return state.ConditionFailed
		}
		book.ClusterAppRoutes = append(book.ClusterAppRoutes, next)
	} else {
		book.ClusterAppRoutes[at] = next
	}
	return state.Applied
}

func clusterAppRouteApp(op UserOperation) string {
	var q ClusterAppRouteSelection
	_ = json.Unmarshal(op.Change.Payload, &q)
	return q.App
}

// ingressClaim is one host that a route serves on a server's listener and
// gateway. Two owners cannot claim the same one, whatever their prefixes:
// ingress picks the longest prefix of a host, so another app's /api under
// the web UI's / would take its logins. Wildcard hosts need no rule here
// because ingress matches an exact host first.
type ingressClaim struct {
	Node, Listener, Gateway, Host string
}

func ingressClaims(d deployment.IngressDeclaration) []ingressClaim {
	var out []ingressClaim
	for _, l := range d.Listeners {
		listener := l.Shared
		if listener == "" {
			listener = l.Address
		}
		for _, r := range deployment.IngressRoutes(d) {
			gateway := r.Gateway
			if gateway == "" {
				gateway = "local"
			}
			for _, kind := range []string{"external", "local"} {
				if gateway == "both" || gateway == kind {
					out = append(out, ingressClaim{Node: d.Node, Listener: listener, Gateway: kind, Host: r.Host})
				}
			}
		}
	}
	return out
}

func claimsOverlap(a, b []ingressClaim) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// clusterAppRouteFree: no workspace app's ingress claims any of d's hosts
// on the same server, listener and gateway.
func (p Policy) clusterAppRouteFree(s state.State, d deployment.IngressDeclaration) bool {
	projection, err := p.ProjectResources(s)
	if err != nil {
		return false
	}
	mine := ingressClaims(d)
	for _, g := range projection.Goals {
		if g.Goal.Kind != "ingress" || g.Ingress != nil && g.Ingress.Lifecycle.Drain {
			continue
		}
		var theirs deployment.IngressDeclaration
		if json.Unmarshal(g.Goal.Config, &theirs) != nil || claimsOverlap(mine, ingressClaims(theirs)) {
			return false
		}
	}
	return true
}

// admitClusterAppRouteClaims refuses a workspace app ingress that claims a
// cluster app route's host (the other direction of clusterAppRouteFree).
func (p Policy) admitClusterAppRouteClaims(s state.State, d deployment.IngressDeclaration) error {
	book, err := p.IngressManagement(s)
	if err != nil {
		return err
	}
	mine := ingressClaims(d)
	for _, r := range book.ClusterAppRoutes {
		if !r.Removed && claimsOverlap(mine, ingressClaims(r.Ingress)) {
			return access.ErrDenied
		}
	}
	return nil
}

// ClusterAppHostPolicy is the ingress host policy for cluster app routes (tenant
// deployment.ClusterAppTenant): exactly the hosts the routes put, on the
// gateways they name.
func (b IngressManagement) ClusterAppHostPolicy() ingress.HostPolicy {
	var p ingress.HostPolicy
	for _, r := range b.ClusterAppRoutes {
		if r.Removed {
			continue
		}
		for _, c := range ingressClaims(r.Ingress) {
			if c.Gateway == "external" {
				p.ExternalHosts = append(p.ExternalHosts, c.Host)
			} else {
				p.LocalHosts = append(p.LocalHosts, c.Host)
			}
		}
	}
	slices.Sort(p.ExternalHosts)
	slices.Sort(p.LocalHosts)
	p.ExternalHosts, p.LocalHosts = slices.Compact(p.ExternalHosts), slices.Compact(p.LocalHosts)
	p.ExternalAllowed = len(p.ExternalHosts) > 0
	return p
}

// ClusterAppRouteView is one cluster app's routes as `sfcli app diff` reads them
// (IngressQuery Part "cluster-app-routes", system administrators).
type ClusterAppRouteView struct {
	App      string
	Revision uint64
	Removed  bool `json:",omitempty"`
	Ingress  deployment.IngressDeclaration
}

func (b IngressManagement) clusterAppRouteViews() []ClusterAppRouteView {
	out := []ClusterAppRouteView{}
	for _, r := range b.ClusterAppRoutes {
		out = append(out, ClusterAppRouteView{App: r.App, Revision: r.Revision, Removed: r.Removed, Ingress: r.Ingress})
	}
	return out
}
