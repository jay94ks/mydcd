// SPDX-License-Identifier: Apache-2.0

package mydc

// REQ-22 G ingress events on the REQ-10 event stream (docs/reference/
// ingress-management.md "이벤트", events.md). Route events carry Tenant (and
// App) and are read with the tenant's Read; gateway and server events have
// no Tenant and only the system administrator (events "") sees them.
// FixtureEvent.Time is the source observation time. The real Target strings are
// Node, Gateway, Tenant, App, RouteID, Host, Prefix and the integer
// Detail.Value; here they are FixtureEvent.Node/Tenant/App and FixtureEvent.Ingress.
const (
	EventIngressBlocked          = "ingress-blocked"
	EventIngressUnblocked        = "ingress-unblocked"
	EventIngressBackendsEmpty    = "ingress-backends-empty"
	EventIngressBackendsRestored = "ingress-backends-restored"
	EventIngressListenerDown     = "ingress-listener-down" // node·gateway, system admin
	EventIngressListenerUp       = "ingress-listener-up"
	EventIngressCertMissing      = "ingress-certificate-missing"
	EventIngressSourceRejected   = "ingress-source-rejected-spike" // Value 100, node·gateway
	EventCertExpiring            = "cert-expiring"                 // Value: seconds left
	EventCertExpired             = "cert-expired"
	// No 5xx-ratio or p95 event: the web computes those from the
	// `ingresses` metrics Part.
)

// IngressEvent: FixtureEvent.Ingress of the ingress events.
type IngressEvent struct {
	Gateway string // external / local ("" for a block that names none)
	RouteID string `json:",omitempty"`
	Host    string `json:",omitempty"`
	Prefix  string `json:",omitempty"`
	// Value: the real Detail.Value (source-rejected-spike 100; cert-expiring
	// seconds left).
	Value float64 `json:",omitempty"`
	// Not from mydcd: Listener (old mock, still in daemon webhook bodies),
	// Metric / Threshold (the daemon's own web-computed samples).
	Listener  string  `json:",omitempty"`
	Metric    string  `json:",omitempty"`
	Threshold float64 `json:",omitempty"`
}
