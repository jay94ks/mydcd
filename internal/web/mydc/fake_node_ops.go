// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"errors"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// REQ-11 in the fake. Cordon is FixtureMember.Cordoned. Tunnel reconnect is the
// real RQ4 node-pair job (fake_tunnel_reconnect_real.go). Each
// server's image cache holds the images of its tasks plus two unused
// fixture images (Fake.AddNodeImage adds more).

func (w *world) memberIndex(node string) int {
	return slices.IndexFunc(w.members, func(m FixtureMember) bool { return m.ID == node })
}

// cordonCheck: a service placed on a cordoned server where it has no task
// yet.
func (w *world) cordonCheck(tenant string, d appDoc) error {
	have := map[string]bool{}
	if a := w.apps[tenant+"/"+d.Name]; a != nil {
		for _, t := range a.tasks {
			have[t.Service+"@"+t.Node] = true
		}
	}
	for _, svc := range sortedKeys(d.Services) {
		for _, n := range d.Services[svc].XMydc.Nodes {
			if i := w.memberIndex(n); i >= 0 && w.members[i].Cordoned && !have[svc+"@"+n] {
				return &inputError{code: InputNodeCordoned, detail: svc + " → " + n}
			}
		}
	}
	return nil
}

func (c *fakeConn) applyNodeOps(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	now := c.f.now().Unix()
	switch ch.Action {
	case ActionCordonNode, ActionUncordonNode:
		var q NodeCordon
		if ch.Action == ActionCordonNode {
			if decodePayload(ch.Payload, &q) != nil || !q.Valid() {
				return errors.New("payload")
			}
		} else {
			var sel control.NodeSelection
			if decodePayload(ch.Payload, &sel) != nil || sel.ID == "" {
				return errors.New("payload")
			}
			q.ID = sel.ID
		}
		if !w.admin(actor) {
			return errForbidden
		}
		i := w.memberIndex(q.ID)
		if i < 0 {
			return errors.New("unknown node")
		}
		m := &w.members[i]
		if ch.Expected != m.Revision || m.Cordoned == (ch.Action == ActionCordonNode) {
			return errCAS
		}
		m.Cordoned, m.CordonReason, m.Revision = ch.Action == ActionCordonNode, q.Reason, next
		m.CordonedBy, m.CordonedAt = "", nil
		if m.Cordoned {
			at := c.f.now().UTC().Truncate(time.Second)
			m.CordonedBy, m.CordonedAt = w.username(actor), &at
		}
		kind := "node-uncordoned"
		if m.Cordoned {
			kind = "node-cordoned"
		}
		w.addEvent(FixtureEvent{Time: now, Scope: "node", Node: q.ID, Kind: kind, Target: q.ID, Detail: q.Reason})
		return nil

	case ActionReconnectTunnel:
		return c.applyTunnelReconnect(op, actor)

	case ActionPruneNodeImages:
		return c.applyImagePrune(op, actor, now)
	}
	return errors.New("action")
}

// tunnelEvent: REQ-54, one tenant-scoped event per node pair and TUN
// network (mydcd: Target{Tenant, Network, Node, PairID}). Node is the
// reporting server (fake: the pair's second node).
func tunnelEvent(kind, tenant, network, from, to string, at int64) FixtureEvent {
	if from > to {
		from, to = to, from
	}
	detail := "AUTHENTICATED_LINK_UP"
	if kind == "tunnel-down" {
		detail = "AUTHENTICATED_LINK_DOWN"
	}
	pair := from + "/" + to
	return FixtureEvent{Time: at, Scope: "tenant", Tenant: tenant, Network: network, Node: to, PairID: pair, Kind: kind, Target: pair, Detail: detail}
}
