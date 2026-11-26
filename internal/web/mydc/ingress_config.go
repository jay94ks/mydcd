// SPDX-License-Identifier: Apache-2.0

package mydc

// REQ-62~65 actions: gateway settings, balance changes, instance drain.
// Payloads are mydcd's control types (fake_ingress_operations_real.go);
// the change history is `ingresses` Part history.

const (
	ActionSetNodeGateways   = "set-node-gateways"
	ActionSetIngressBalance = "set-ingress-balance"
	ActionDrainIngress      = "drain-ingress"
	ActionUndrainIngress    = "undrain-ingress"
)

// IngressMatch: one REQ-22 F4 condition. Kind header / cookie / query
// (Name, Op equals / prefix / present, Value), method (Value), source (Value
// = CIDR) or percent (Percent 1..100 of the remaining requests, hashed).
type IngressMatch struct {
	Kind    string
	Name    string `json:",omitempty"`
	Op      string `json:",omitempty"`
	Value   string `json:",omitempty"`
	Percent int    `json:",omitempty"`
	Group   string // backend group: a service label key=value
}
