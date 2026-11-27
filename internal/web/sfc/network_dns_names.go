// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"github.com/jay94ks/seafield/internal/access"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/userauth"
)

// NetworkDNSNames is control.NetworkDNSNames: the names a network's managed
// DNS answers, with the app service and reserved address of each.
type NetworkDNSNames = control.NetworkDNSNames

// NetworkDNSName is control.NetworkDNSName (one registered name).
type NetworkDNSName = control.NetworkDNSName

func (c *realConn) NetworkDNSNames(ctx context.Context, tenant, network string) (NetworkDNSNames, error) {
	const m = "network-dns-names"
	return realCall(ctx, c, m, func(u userauth.Client, s access.Session) (NetworkDNSNames, error) {
		return u.NetworkDNSNames(ctx, c.peer, s, userauth.NetworkDNSNamesQuery{Tenant: tenant, Network: network})
	})
}

// The fake keeps no tasks or address reservations, so a managed network's
// name list is empty there; its hand records are all served.
func (c *fakeConn) NetworkDNSNames(ctx context.Context, tenant, network string) (NetworkDNSNames, error) {
	user, err := c.lockSession(ctx, "network-dns-names")
	if err != nil {
		return NetworkDNSNames{}, err
	}
	defer c.unlock()
	if !c.f.w.canRead(user, tenant) {
		return NetworkDNSNames{}, fail("network-dns-names", CodeDenied, "")
	}
	out := NetworkDNSNames{Names: []control.NetworkDNSName{}, Records: []control.NetworkDNSRecord{}}
	for _, e := range c.f.w.resources {
		if e.Tenant == tenant && e.Network != nil && e.Network.Name == network && e.Network.DNS != nil {
			out.Managed, out.Revision = true, e.Network.DNS.Revision
			out.Zone, _ = services.Domain(e.Network.DNS.Zone)
			for _, r := range e.Network.DNS.Policy.Records {
				out.Records = append(out.Records, control.NetworkDNSRecord{Name: r.Name, Type: r.Type, Value: r.Value, TTL: r.TTL, Served: true})
			}
		}
	}
	return out, nil
}
