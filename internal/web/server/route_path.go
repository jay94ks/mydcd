// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/url"
	"strings"
)

// Screen API routes the web daemon sends in process for someone (incident
// actions, CD webhooks). They are registered patterns
// (TestInProcessRoutesRegistered); routePath fills them.
const (
	routeTaskRestart      = "POST /api/v1/t/{t}/apps/{app}/task/restart"
	routeAppCDPause       = "POST /api/v1/t/{t}/apps/{app}/cd/pause"
	routeAppCDApprove     = "POST /api/v1/t/{t}/apps/{app}/cd/candidate/approve"
	routeAppCDReject      = "POST /api/v1/t/{t}/apps/{app}/cd/candidate/reject"
	routeAppCDApproverAdd = "POST /api/v1/t/{t}/apps/{app}/cd/approvers"
	routeAppCDApproverDel = "DELETE /api/v1/t/{t}/apps/{app}/cd/approvers"
	routeAppsDeploy       = "POST /api/v1/t/{t}/apps/deploy"
	routeNodeCordon       = "POST /api/v1/nodes/{node}/cordon"
	routeNodeImagePrune   = "POST /api/v1/nodes/{node}/image-prune"
	routeTunnelReconnect  = "POST /api/v1/t/{t}/networks/{name}/tunnels/reconnect"
)

var inProcessRoutes = []string{
	routeTaskRestart, routeAppCDPause, routeAppCDApprove, routeAppCDReject, routeAppCDApproverAdd, routeAppCDApproverDel,
	routeAppsDeploy, routeNodeCordon, routeNodeImagePrune, routeTunnelReconnect,
}

// routePath splits a route pattern into its method and a path with each
// {param} replaced by its path-escaped value; kv is param, value, ….
// A param left without a value is a bug and panics.
func routePath(pattern string, kv ...string) (method, path string) {
	method, path, _ = strings.Cut(pattern, " ")
	for i := 0; i+1 < len(kv); i += 2 {
		path = strings.ReplaceAll(path, "{"+kv[i]+"}", url.PathEscape(kv[i+1]))
	}
	if strings.Contains(path, "{") {
		panic(fmt.Sprintf("routePath %s: missing values", pattern))
	}
	return method, path
}
