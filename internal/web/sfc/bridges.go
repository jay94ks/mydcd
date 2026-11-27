// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"github.com/jay94ks/seafield/internal/tenancy"
)

const (
	ActionCreateVirtualBridge  = "create-virtual-bridge"
	ActionApproveVirtualBridge = "approve-virtual-bridge"
	ActionCloseVirtualBridge   = "close-virtual-bridge"
)

// Bridge is a virtual bridge row (sfcd resources bridge/<owner>/<id>,
// devel/design/virtual-bridge.md). A is the creating side. Both sides'
// tenants see it; a side is named by tenant and network name only.
type Bridge struct {
	Kind                 string // always "bridge"
	Owner, Name          string
	A, B                 BridgeEnd
	Direction            string // both / a-to-b / b-to-a
	Protocol             string // all / tcp / udp
	Ports                []RoutePorts
	Phase                string // pending / open / closing
	Approvals            []RouteApproval
	Generation, Revision uint64
	Raw                  tenancy.VirtualBridge `json:"-"`
}
type BridgeEnd struct{ Tenant, Network string }

// BridgeView converts a sfcd bridge row.
func BridgeView(b tenancy.VirtualBridge) Bridge {
	v := Bridge{Kind: "bridge", Owner: b.A.Tenant, Name: b.ID, A: BridgeEnd{b.A.Tenant, b.A.Network}, B: BridgeEnd{b.B.Tenant, b.B.Network},
		Direction: string(b.Direction), Protocol: "all", Ports: []RoutePorts{}, Phase: string(b.Phase), Approvals: []RouteApproval{},
		Generation: b.Generation, Revision: b.Revision, Raw: b}
	switch b.Protocol {
	case 6:
		v.Protocol = "tcp"
	case 17:
		v.Protocol = "udp"
	}
	for _, p := range b.Ports {
		v.Ports = append(v.Ports, RoutePorts{p.First, p.Last})
	}
	for _, a := range b.Approvals {
		v.Approvals = append(v.Approvals, RouteApproval{a.Tenant, a.User})
	}
	return v
}
