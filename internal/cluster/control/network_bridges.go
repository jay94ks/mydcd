// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// BridgeProposal is create-virtual-bridge (devel/design/virtual-bridge.md).
// A is the creating side; Expected is the networks revision.
type BridgeProposal struct {
	ID        string
	A, B      tenancy.BridgeEnd
	Direction tenancy.BridgeDirection `json:",omitempty"`
	Protocol  uint8                   `json:",omitempty"`
	Ports     []tenancy.Ports         `json:",omitempty"`
}

// BridgeSelection is approve-virtual-bridge / close-virtual-bridge. Tenant is
// the acting side, Owner the creating side (A) whose namespace holds ID.
// Expected is the bridge revision.
type BridgeSelection struct {
	Tenant, Owner, ID string
}

func (p Policy) authorizeBridgeChange(c access.Catalog, op UserOperation) error {
	if op.Change.Action == "create-virtual-bridge" {
		var v BridgeProposal
		if canonical(op.Change.Payload, &v) != nil {
			return access.ErrInvalid
		}
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, v.A.Tenant, access.ManageNetwork, "")
	}
	var v BridgeSelection
	if canonical(op.Change.Payload, &v) != nil {
		return access.ErrInvalid
	}
	if op.Change.Action == "close-virtual-bridge" {
		return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, v.Tenant, access.ManageNetwork)
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, v.Tenant, access.ManageNetwork, "")
}

// changeBridge applies the three bridge actions. None has a native effect
// yet: an open bridge carries no packets until the packet plan follows it.
func (p Policy) changeBridge(c access.Catalog, r Resources, op UserOperation) (tenancy.Networks, error) {
	change := op.Change
	if change.Action == "create-virtual-bridge" {
		var v BridgeProposal
		if canonical(change.Payload, &v) != nil {
			return r.Networks, access.ErrInvalid
		}
		return r.Networks.CreateBridge(c, change.Principal, change.Expected, tenancy.VirtualBridge{ID: v.ID, A: v.A, B: v.B, Direction: v.Direction, Protocol: v.Protocol, Ports: v.Ports})
	}
	var v BridgeSelection
	if canonical(change.Payload, &v) != nil {
		return r.Networks, access.ErrInvalid
	}
	if change.Action == "approve-virtual-bridge" {
		return r.Networks.ApproveBridge(c, change.Principal, v.Tenant, v.Owner, v.ID, change.Expected)
	}
	return r.Networks.CloseBridge(c, change.Principal, v.Tenant, v.Owner, v.ID, change.Expected)
}

// bridgeRefusalCode gives a bridge refusal its own result reason.
func bridgeRefusalCode(err error) (state.Code, bool) {
	switch {
	case errors.Is(err, tenancy.ErrBridgeExists):
		return state.BridgeExists, true
	case errors.Is(err, tenancy.ErrPeerClosed):
		return state.BridgePeerClosed, true
	case errors.Is(err, tenancy.ErrNetworkChanging):
		return state.NetworkChanging, true
	case errors.Is(err, tenancy.ErrBridgeAttached):
		return state.BridgeAttached, true
	}
	return 0, false
}
