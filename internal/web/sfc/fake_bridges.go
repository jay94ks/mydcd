// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Virtual bridges with the real payload types and the tenancy.Networks rules
// the web can see: create (A's manager, Expected = networks revision) opens a
// same-tenant bridge at once, or waits for B's manager when B's network has
// bridge-inbound on; approve (B's manager, Expected = bridge revision) opens
// it; close from either side removes a pending one and makes an open one
// closing. The fake does not model the servers' closed reports.

// bridgeRefused is a refusal with its own result reason (bridge-exists,
// peer-closed, network-changing).
type bridgeRefused struct{ code state.Code }

func (e bridgeRefused) Error() string { return state.RejectionReason(e.code) }

func (w *world) bridgeEntries(tenant string) []control.ResourceEntry {
	var out []control.ResourceEntry
	for _, b := range w.bridges {
		if tenant != "" && b.A.Tenant != tenant && b.B.Tenant != tenant {
			continue
		}
		v := b
		out = append(out, control.ResourceEntry{Key: "bridge/" + b.A.Tenant + "/" + b.ID, Bridge: &v})
	}
	return out
}

// bridgeNetwork is a bridge side's TUN network row; changing is true while
// a member drains or has a change.
func (w *world) bridgeNetwork(e tenancy.BridgeEnd) (n *Network, changing bool) {
	i, row := w.networkRow(e.Tenant, e.Network)
	if i < 0 || row.Kind != "tun" {
		return nil, false
	}
	for _, m := range row.Members {
		changing = changing || m.Draining || activeChange(m.Change)
	}
	return row, changing
}

// bridgeEndpoints: the tenant's TUN networks with bridge-inbound on and no
// member changing, by name (PublicRead "bridge-endpoints").
func (c *fakeConn) bridgeEndpoints(tenant string) []string {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	w := c.f.w
	out := []string{}
	for _, r := range w.resources {
		if r.Tenant != tenant || r.Network == nil || r.Network.Kind != "tun" || !slices.Contains(r.Network.Toggles, tenancy.ToggleBridgeInbound) {
			continue
		}
		if _, changing := w.bridgeNetwork(tenancy.BridgeEnd{Tenant: tenant, Network: r.Network.Name}); !changing {
			out = append(out, r.Network.Name)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (c *fakeConn) applyBridge(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	if ch.Action == ActionCreateVirtualBridge {
		var q control.BridgeProposal
		if decodePayload(ch.Payload, &q) != nil || q.ID == "" || q.A == q.B || q.Protocol != 0 && q.Protocol != 6 && q.Protocol != 17 || q.Protocol == 0 && len(q.Ports) != 0 {
			return errors.New("payload")
		}
		if q.Direction == "" {
			q.Direction = tenancy.BridgeBoth
		}
		if !w.canManage(actor, q.A.Tenant) || q.A.Tenant == q.B.Tenant && !w.canManage(actor, q.B.Tenant) {
			return errForbidden
		}
		a, aChanging := w.bridgeNetwork(q.A)
		b, bChanging := w.bridgeNetwork(q.B)
		if a == nil || b == nil || ch.Expected != w.netRev || slices.ContainsFunc(w.bridges, func(x tenancy.VirtualBridge) bool { return x.A.Tenant == q.A.Tenant && x.ID == q.ID }) {
			return errCAS
		}
		if slices.ContainsFunc(w.bridges, func(x tenancy.VirtualBridge) bool { return x.A == q.A && x.B == q.B || x.A == q.B && x.B == q.A }) {
			return bridgeRefused{state.BridgeExists}
		}
		if aChanging || bChanging {
			return bridgeRefused{state.NetworkChanging}
		}
		if q.A.Tenant != q.B.Tenant && !slices.Contains(b.Toggles, tenancy.ToggleBridgeInbound) {
			return bridgeRefused{state.BridgePeerClosed}
		}
		v := tenancy.VirtualBridge{ID: q.ID, Generation: next, Revision: next, A: q.A, B: q.B, Direction: q.Direction, Protocol: q.Protocol, Ports: slices.Clone(q.Ports),
			Phase: tenancy.BridgePending, Approvals: []tenancy.Approval{{Tenant: q.A.Tenant, User: actor, PolicyRevision: 1}}}
		if q.A.Tenant == q.B.Tenant {
			v.Phase = tenancy.BridgeOpen
		}
		w.bridges = append(w.bridges, v)
		w.netRev = next
		return nil
	}
	var q control.BridgeSelection
	if decodePayload(ch.Payload, &q) != nil {
		return errors.New("payload")
	}
	i := slices.IndexFunc(w.bridges, func(b tenancy.VirtualBridge) bool { return b.A.Tenant == q.Owner && b.ID == q.ID })
	if i < 0 || w.bridges[i].Revision != ch.Expected {
		return errCAS
	}
	b := w.bridges[i]
	if q.Tenant != b.A.Tenant && q.Tenant != b.B.Tenant || !w.canManage(actor, q.Tenant) {
		return errForbidden
	}
	if ch.Action == ActionCloseVirtualBridge {
		switch b.Phase {
		case tenancy.BridgeClosing:
			return errCAS
		case tenancy.BridgePending:
			w.bridges = slices.Delete(w.bridges, i, i+1)
		default:
			b.Phase, b.Revision = tenancy.BridgeClosing, next
			w.bridges[i] = b
		}
		w.netRev = next
		return nil
	}
	if b.Phase != tenancy.BridgePending || q.Tenant != b.B.Tenant {
		return errCAS
	}
	peer, changing := w.bridgeNetwork(b.B)
	if _, aChanging := w.bridgeNetwork(b.A); changing || aChanging {
		return bridgeRefused{state.NetworkChanging}
	}
	if peer == nil || !slices.Contains(peer.Toggles, tenancy.ToggleBridgeInbound) {
		return bridgeRefused{state.BridgePeerClosed}
	}
	b.Approvals = append(slices.Clone(b.Approvals), tenancy.Approval{Tenant: q.Tenant, User: actor, PolicyRevision: 1})
	b.Phase, b.Revision = tenancy.BridgeOpen, next
	w.bridges[i] = b
	w.netRev = next
	return nil
}
