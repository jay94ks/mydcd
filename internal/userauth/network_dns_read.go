// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"time"
)

// resourceDNSRead fills each managed network row's DNS state and checks the
// page against a fresh quorum view; it returns "ok" or a refusal code.
func (s Service) resourceDNSRead(ctx context.Context, view cluster.View, session access.Session, rows []control.ResourceEntry) string {
	targets := map[int]control.NetworkDNSTarget{}
	for i := range rows {
		row := &rows[i]
		if row.Network == nil {
			continue
		}
		dns, target, err := s.Policy.NetworkDNSView(view.State, *row.Network)
		if err != nil {
			return "unavailable"
		}
		row.DNS = dns
		if dns != nil {
			targets[i] = target
		}
	}
	if s.DNSObserver == nil || len(targets) == 0 {
		return "ok"
	}
	// One finite diagnostic budget and one post-I/O quorum/authority check for
	// the whole page. A missing owner does not consume the user's entire RPC
	// deadline or suppress the unchanged desired DNS policy.
	observeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	for i := range rows {
		target, ok := targets[i]
		if !ok {
			continue
		}
		dns := rows[i].DNS
		if observeCtx.Err() != nil {
			dns.State = "unreachable"
			continue
		}
		native, err := s.DNSObserver(observeCtx, target)
		if err == nil {
			dns.Ready = native.Ready
			dns.State = native.State
			dns.Resolvers = native.Resolvers
		} else {
			dns.State = "unreachable"
		}
	}
	cancel()
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return "unavailable"
	}
	policy, err := s.Policy.Current(latest.State)
	if err != nil {
		return "unavailable"
	}
	c, err := policy.Catalog(latest.State)
	if err != nil {
		return "unavailable"
	}
	resources, err := policy.Resources(latest.State)
	if err != nil {
		return "unavailable"
	}
	for i := range rows {
		target, ok := targets[i]
		if !ok {
			continue
		}
		row := &rows[i]
		// This is the logical resource page's Read authority, not permission
		// to place/start workloads on that node. Withdrawing AllowedNodes
		// preserves existing network metadata and its cleanup visibility.
		if c.AuthorizeSession(session, policy.Cluster, policy.Issuer(session.Issuer), time.Now().Unix(), row.Network.Tenant, access.Read, "") != nil {
			return "denied"
		}
		n, ok := resources.Networks.Network(row.Network.Tenant, row.Network.ID)
		if !ok || n.Generation != row.Network.Generation || n.Revision != row.Network.Revision || n.Owner != row.Network.Owner {
			return "conflict"
		}
		current, currentTarget, err := policy.NetworkDNSView(latest.State, n)
		if err != nil || current == nil || currentTarget != target {
			return "conflict"
		}
	}
	return "ok"
}
