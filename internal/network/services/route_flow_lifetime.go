// SPDX-License-Identifier: Apache-2.0

package services

import "github.com/jay94ks/mydcd/internal/network"

func (t RouteTuple) Transport() network.TransportPacket {
	return network.TransportPacket{Source: t.Source.Address, Destination: t.Destination.Address, SourcePort: t.SourcePort, DestinationPort: t.DestinationPort, Protocol: t.Protocol}
}

// Flows returns original handles in journal order, without granting packet or
// native authority. Pending handshakes and closing lifetimes remain visible.
func (m RouteRuntime) Flows() []RouteFlow {
	flows := make([]RouteFlow, 0, len(m.flows))
	for _, pin := range m.pins.Active {
		if f, ok := m.flows[pin.Token]; ok {
			flows = append(flows, RouteFlow{m.consumer.ID, f.Pin, f.Tuple})
		}
	}
	return flows
}

func (m RouteRuntime) FlowLifetime(h RouteFlow) (tracked, closing, exists bool) {
	f, ok := m.flow(h)
	return f.Tracked, f.Closing, ok
}

// TrackFlow records the adapter's positive native conntrack observation. It is
// not inferred from a packet, missing rows, time or a peer receipt.
// The actual owner persists this candidate with the original source pin.
func (m RouteRuntime) TrackFlow(h RouteFlow) (RouteRuntime, error) {
	f, ok := m.flow(h)
	if !ok || f.Closing || f.Boot != m.boot || !m.nativeReady() || m.consumer.Route.Side != m.consumer.Route.Policy.Source.Tenant {
		return m, ErrLease
	}
	q := m.clone()
	f = q.flows[f.Pin.Token]
	f.Tracked = true
	q.flows[f.Pin.Token] = f
	return q, nil
}

// BeginFlowClose is monotonic and retains the original pin/tuple/receipts. The
// caller establishes native disappearance (source) or the original source's
// close request (destination) before persisting/publishing this candidate.
func (m RouteRuntime) BeginFlowClose(h RouteFlow) (RouteRuntime, error) {
	f, ok := m.flow(h)
	if !ok || m.consumer.Route.Side == m.consumer.Route.Policy.Source.Tenant && !f.Tracked || m.consumer.Route.Side != m.consumer.Route.Policy.Source.Tenant && f.Remote == nil {
		return m, ErrLease
	}
	q := m.clone()
	f = q.flows[f.Pin.Token]
	f.Closing = true
	q.flows[f.Pin.Token] = f
	return q, nil
}

// ObserveConntrack consumes one COMPLETE, positively verified native census.
// nil is never an empty census. Destination rows may not start source expiry;
// no observer/elapsed time changes an original boot's authority or pin.
func (m RouteRuntime) ObserveConntrack(census map[network.TransportPacket]bool) (RouteRuntime, bool, error) {
	if census == nil || !m.nativeReady() || m.consumer.Route.Side != m.consumer.Route.Policy.Source.Tenant {
		return m, false, ErrLease
	}
	q := m.clone()
	changed := false
	for token, f := range q.flows {
		if f.Closing {
			continue
		}
		if census[f.Tuple.Transport()] {
			if f.Tracked || f.Boot != m.boot {
				continue
			}
			f.Tracked = true
		} else {
			if !f.Tracked {
				continue
			}
			f.Closing = true
		}
		q.flows[token] = f
		changed = true
	}
	return q, changed, nil
}
