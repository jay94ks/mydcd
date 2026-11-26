// SPDX-License-Identifier: Apache-2.0

package mydc

import "github.com/jay94ks/mydcd/internal/cluster/control"

// RouteEndpoints: REQ-38 (mock) `route-endpoints` for a destination tenant:
// the endpoints (network name, server, pool ID) that tenant offers for
// propose-route. No addresses, owner keys or generations: mydcd pins them
// when the proposal is applied. Name follows REQUEST.md REQ-38 and may
// change when mydcd publishes it. Real since REQ-38: the rows are
// PublicRead("route-endpoints") (control.PublicRouteEndpoint); this type
// stays as the fake's internal shape.
type RouteEndpoints struct {
	Tenant    string
	Endpoints []control.RouteEndpoint // put one as RouteProposal.Destination
}
