// SPDX-License-Identifier: Apache-2.0

package mydc

// REQ-22 ingress. The contract is QueryIngresses and the
// control/ingress-management actions (fake_ingress_real.go). The types below
// are the fake's seed (fixture Ingresses / IngressGateways) and the old
// gateway / balance / drain mocks without a mydcd counterpart
// (ingress_config.go), kept until the screens are decided.

const (
	ActionIngressBlock       = "ingress-block"
	ActionIngressUnblock     = "ingress-unblock"
	ActionIngressBlockExtend = "ingress-block-extend"
)

// Gateways.
const (
	GatewayExternal     = "external"
	GatewayLocal        = "local"
	GatewayBoth         = "both"
	GatewayUnclassified = "unclassified"
)

// IngressInstance is one app's ingress instance on one server.
type IngressInstance struct {
	Tenant, App, Node string
	Generation        uint64
	Ready, Draining   bool
	// DrainStartedAt / DrainUntil: drain-ingress; the
	// requests still open are cut at DrainUntil. Cleared by undrain.
	DrainStartedAt int64  `json:",omitempty"`
	DrainUntil     int64  `json:",omitempty"`
	Error          string `json:",omitempty"`
	Listeners      []IngressListener
	Routes         []IngressRoute
	Backends       []IngressBackend
	Blocks         []string // active block IDs that apply here
	ObservedAt     int64
}

type IngressListener struct {
	ID, Address string
	Gateway     string // external / local / unclassified
	Shared      bool   // the server's shared listener
	Protocols   []string
	// TLS: serves HTTPS with the store certificate linked to each SNI host.
	TLS, HTTP3 bool
	State      string // listening / failed / closed
}

type IngressRoute struct {
	ID, Host, Prefix, Service string
	Gateway                   string
	Balance                   IngressBalance
	BalanceRevision           uint64 `json:",omitempty"` // REQ-22 F (mock)
	Blocked                   bool
}

// IngressBalance: REQ-22 F. Set from app.yaml or with set-ingress-balance
// ; BalanceRevision on the route is its Expected.
type IngressBalance struct {
	Method           string // round-robin / least-request / hash / random
	Key              string `json:",omitempty"` // hash: source-ip / cookie:NAME / header:NAME
	Locality         string `json:",omitempty"` // same-node
	SlowStartSeconds int    `json:",omitempty"`
	Retry            int    `json:",omitempty"`
	// Capacity: concurrent requests per backend (0 = no limit). Weights:
	// backend task or group → 1..1024. Match: first matching condition picks
	// a backend group (F4); Fallback when the group has none: default / 503.
	Capacity int            `json:",omitempty"`
	Weights  map[string]int `json:",omitempty"`
	Match    []IngressMatch `json:",omitempty"`
	Fallback string         `json:",omitempty"`
}

type IngressBackend struct {
	Service, Task, Node, Network, Address string
	Port, Weight                          int
	Generation                            uint64
	Healthy                               bool
	LastCheckAt                           int64
	Blocked                               bool
}

type IngressGateway struct {
	Kind            string // external / local
	Addresses       []string
	Ports           []int
	AllowedSources  []string `json:",omitempty"` // local only
	Enabled         bool
	State           string // up / down
	RejectedSources uint64 // local: connections cut before TLS/HTTP
}

type IngressMetricSet struct {
	Window              string // 1m / 5m / 1h
	RatePerSec          float64
	C2xx, C3xx, C4xx    uint64
	C5xx, Blocked       uint64
	P50MS, P95MS, P99MS float64
	Connections         int
	BytesIn, BytesOut   uint64
	ProxyFailures       map[string]uint64 `json:",omitempty"` // connect / timeout / reset / no-backend
	NoMatch             uint64            `json:",omitempty"` // instance: requests no app matched
}
