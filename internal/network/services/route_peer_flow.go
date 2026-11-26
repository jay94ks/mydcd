// SPDX-License-Identifier: Apache-2.0

package services

import (
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// Tokens belong to the single frozen opposite ReferenceNeed, not a node-wide
// namespace. Adjacent retired tokens compact without forgetting delayed claims.
type routePinRange struct{ First, Last uint64 }

func validRoutePinRanges(ranges []routePinRange) bool {
	if len(ranges) > maxRecords {
		return false
	}
	for i, p := range ranges {
		if p.First == 0 || p.Last < p.First || i > 0 && (p.First <= ranges[i-1].Last || p.First-ranges[i-1].Last == 1) {
			return false
		}
	}
	return true
}

func closedRoutePin(ranges []routePinRange, token uint64) bool {
	i, found := slices.BinarySearchFunc(ranges, token, func(p routePinRange, token uint64) int {
		if p.Last < token {
			return -1
		}
		if p.First > token {
			return 1
		}
		return 0
	})
	return found && i < len(ranges)
}

func closeRoutePin(ranges []routePinRange, token uint64) []routePinRange {
	return closeRoutePins(ranges, []uint64{token})
}

func closeRoutePins(ranges []routePinRange, tokens []uint64) []routePinRange {
	all := make([]routePinRange, 0, len(ranges)+len(tokens))
	all = append(all, ranges...)
	for _, token := range tokens {
		all = append(all, routePinRange{token, token})
	}
	slices.SortFunc(all, func(a, b routePinRange) int {
		if a.First < b.First {
			return -1
		}
		if a.First > b.First {
			return 1
		}
		return 0
	})
	out := all[:0]
	for _, p := range all {
		if len(out) == 0 {
			out = append(out, p)
			continue
		}
		last := &out[len(out)-1]
		if p.First <= last.Last || p.First-last.Last == 1 {
			last.Last = max(last.Last, p.Last)
		} else {
			out = append(out, p)
		}
	}
	return out
}

// AcceptPeerFlow plans the destination pin and the immutable source receipt
// in ONE candidate. The owner syncs it once, then publishes its destination
// receipt. Duplicate/unknown delivery resolves the same original pin.
func (m RouteRuntime) AcceptPeerFlow(c access.Catalog, n tenancy.Networks, a Authority, peer RouteNativeProof, receipt RouteFlowReceipt, tuple RouteTuple, now Clock) (RouteRuntime, RouteFlow, error) {
	if m.consumer.Route == nil || m.consumer.Route.Side == m.consumer.Route.Policy.Source.Tenant || closedRoutePin(m.closedPeers, receipt.Pin.Token) {
		return m, RouteFlow{}, ErrLease
	}
	if flow, exists := m.OriginalFlow(tuple); exists {
		candidate, err := m.RecordPeerFlow(c, n, a, flow, receipt, now)
		return candidate, flow, err
	}
	// One source pin cannot authorize two tuple/endpoint incarnations.
	for _, f := range m.flows {
		if f.Remote != nil && f.Remote.Pin == receipt.Pin {
			return m, RouteFlow{}, ErrLease
		}
	}
	q, flow, err := m.BorrowFlow(c, n, a, peer, receipt.Boot, tuple, now)
	if err != nil {
		return m, RouteFlow{}, err
	}
	q, err = q.RecordPeerFlow(c, n, a, flow, receipt, now)
	if err != nil {
		return m, RouteFlow{}, err
	}
	return q, flow, nil
}
