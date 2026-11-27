// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"fmt"
	"slices"
)

// Observed kinds a test can add (blocked/unblocked come from the actions).
var ingressEventKinds = []string{EventIngressBackendsEmpty, EventIngressBackendsRestored, EventIngressListenerDown, EventIngressListenerUp,
	EventIngressCertMissing, EventIngressSourceRejected, EventCertExpiring, EventCertExpired}

// AddIngressEvent puts one REQ-22 G ingress fault event on the event stream
// and returns its cursor. A route event names tenant (and app) and a
// RouteID; a gateway or server event leaves tenant "" (system admin only).
// Target is tenant/app/route for a route event, node/gateway otherwise.
func (f *Fake) AddIngressEvent(kind, node, tenant, app string, ie IngressEvent) string {
	if !slices.Contains(ingressEventKinds, kind) {
		panic("sfcli fake: not an ingress event kind: " + kind)
	}
	if ie.Gateway != GatewayExternal && ie.Gateway != GatewayLocal {
		panic("sfcli fake: ingress event gateway is external or local")
	}
	if (tenant == "") != (ie.RouteID == "") {
		panic(fmt.Sprintf("sfcli fake: %s: a route event has tenant and RouteID, a gateway event neither", kind))
	}
	switch kind {
	case EventIngressListenerDown, EventIngressListenerUp:
		if tenant != "" {
			panic("sfcli fake: listener events are node·gateway scope")
		}
	case EventIngressSourceRejected:
		if tenant != "" || ie.Value != 100 {
			panic("sfcli fake: source-rejected-spike is node·gateway scope with Value 100")
		}
	case EventCertExpiring:
		if ie.Value <= 0 || ie.Host == "" {
			panic("sfcli fake: cert-expiring needs Host and Value (seconds left)")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	e := FixtureEvent{Time: f.now().Unix(), Scope: "node", Node: node, Kind: kind, Target: node + "/" + ie.Gateway, Ingress: &ie}
	if tenant != "" {
		e.Scope, e.Tenant, e.App, e.Target = "tenant", tenant, app, tenant+"/"+app+"/"+ie.RouteID
		if app != "" {
			e.Scope = "app"
		}
	}
	e.Detail = ingressEventDetail(kind, ie)
	return f.w.addEvent(e)
}

func ingressEventDetail(kind string, ie IngressEvent) string {
	switch {
	case ie.Metric != "" && ie.Threshold != 0:
		return fmt.Sprintf("%s %g (threshold %g)", ie.Metric, ie.Value, ie.Threshold)
	case kind == EventIngressSourceRejected:
		return fmt.Sprintf("%g rejected in one second", ie.Value)
	case ie.Host != "":
		return ie.Host + ie.Prefix
	case ie.Listener != "":
		return ie.Listener
	}
	return kind
}
