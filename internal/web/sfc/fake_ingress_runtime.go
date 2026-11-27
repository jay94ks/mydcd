// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/ingress"
)

// Fake-only knobs for the REQ-22 owner Runtime (docs/reference/
// ingress-management.md). Runtime.BlockRevision is the block book revision
// the owner installed and IngressPage.BlockRevision the committed book
// target (not RootRevision, the root CAS); an unblock is installed on a
// server when Runtime.BlockRevision >= the page's BlockRevision. By default
// every owner installs at once.

type heldBlocks struct {
	revision uint64
	blocks   []control.IngressBlockRecord
}

// HoldIngressBlocks freezes node's installed block policy (hold true): its
// Runtime.BlockRevision and Runtime.Blocks stay as they are now, and a new
// block shows Applied=false there, until hold false installs the current
// book. Tests an unblock that is committed but not yet installed.
func (f *Fake) HoldIngressBlocks(node string, hold bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	if !hold {
		delete(w.ireal.held, node)
		return
	}
	if w.ireal.held == nil {
		w.ireal.held = map[string]heldBlocks{}
	}
	if _, ok := w.ireal.held[node]; !ok {
		w.ireal.held[node] = heldBlocks{revision: w.ireal.revision, blocks: slices.Clone(w.ireal.blocks)}
	}
}

// SetIngressRouteMetric replaces the Runtime.Metrics.Routes row of route in
// the tenant/app/node mapping (ID stays the route). A zero Metric puts the
// generated row back.
func (f *Fake) SetIngressRouteMetric(tenant, app, node, route string, m ingress.Metric) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	k := ingressRealKey(IngressInstance{Tenant: tenant, App: app, Node: node}) + "\x00" + route
	if isZeroMetric(m) {
		delete(w.ireal.routeMetrics, k)
		return
	}
	if w.ireal.routeMetrics == nil {
		w.ireal.routeMetrics = map[string]ingress.Metric{}
	}
	m.ID = route
	w.ireal.routeMetrics[k] = m
}

func isZeroMetric(m ingress.Metric) bool {
	m.ID = ""
	return m.OpenConnections == 0 && m.Requests == 0 && m.Blocked == 0 && m.ReceivedBytes == 0 && m.SentBytes == 0 && m.Rate == 0 &&
		m.Responses == [4]uint64{} && m.P50MS == 0 && m.P95MS == 0 && m.P99MS == 0 && len(m.Failures) == 0
}

// installedBlocks: the owner's installed revision and block records.
func (w *world) installedBlocks(node string) (uint64, []control.IngressBlockRecord, bool) {
	if h, ok := w.ireal.held[node]; ok {
		return h.revision, h.blocks, true
	}
	return w.ireal.revision, w.ireal.blocks, false
}

// blockInstalled: whether node's owner has installed block id.
func (w *world) blockInstalled(id, node string) bool {
	h, ok := w.ireal.held[node]
	return !ok || slices.ContainsFunc(h.blocks, func(r control.IngressBlockRecord) bool { return r.Block.ID == id && !r.Removed })
}

// countIngressListeners: sfcd's node summary counts a shared listener
// once per node however many visible apps borrow it.
func countIngressListeners(node string, listeners []ingress.Listener, seen map[string]bool) int {
	n := 0
	for _, l := range listeners {
		id := node + "\x00direct\x00" + l.Address
		if l.Shared != "" {
			id = node + "\x00shared\x00" + l.Shared
		}
		if !seen[id] {
			seen[id] = true
			n++
		}
	}
	return n
}
