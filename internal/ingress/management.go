// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
)

// Block is independent from app Desired. Its lifetime is the original
// replicated management record; callers supply time for expiry evaluation.
type Block struct {
	ID, Scope, Tenant, App, Node, Key, Gateway    string
	Route, Host, Prefix, Service, Backend, Source string
	Apps                                          []string `json:",omitempty"`
	Response                                      string
	CutExisting                                   bool
	ExpiresAt, CreatedAt                          uint64
	Reason, Actor                                 string
}

func (b Block) Valid() bool {
	if !lifecycle.ValidID(b.ID) || !lifecycle.ValidID(b.Actor) || b.CreatedAt == 0 || b.CreatedAt > math.MaxInt64 || b.ExpiresAt > math.MaxInt64 || len(b.Reason) > 512 || strings.ContainsAny(b.Reason, "\x00\r\n") || b.ExpiresAt != 0 && b.ExpiresAt <= b.CreatedAt || b.Response != "503" && b.Response != "403" && b.Response != "reset" || len(b.Apps) > 128 {
		return false
	}
	if len(b.Key) > 512 || len(b.Host) > 253 || len(b.Prefix) > 2048 || len(b.Route) > 128 || len(b.Service) > 128 || len(b.Backend) > 512 {
		return false
	}
	for _, id := range []string{b.Tenant, b.App, b.Node} {
		if id != "" && !lifecycle.ValidID(id) {
			return false
		}
	}
	if b.Gateway != "" && b.Gateway != "external" && b.Gateway != "local" && b.Gateway != "both" {
		return false
	}
	if b.Scope != "node" && b.Scope != "gateway" && b.Scope != "host" && b.Tenant == "" {
		return false
	}
	switch b.Scope {
	case "gateway":
		return (b.Gateway == "external" || b.Gateway == "local") && b.Tenant == "" && b.App == "" && b.Key == "" && b.Host == "" && b.Prefix == "" && b.Route == "" && b.Service == "" && b.Backend == "" && b.Source == "" && len(b.Apps) == 0
	case "node":
		return b.Node != "" && b.Tenant == "" && b.App == "" && b.Key == "" && b.Host == "" && b.Prefix == "" && b.Route == "" && b.Service == "" && b.Backend == "" && b.Source == "" && len(b.Apps) == 0
	case "tenant":
		return b.Tenant != "" && b.App == "" && b.Key == "" && b.Host == "" && b.Prefix == "" && b.Route == "" && b.Service == "" && b.Backend == "" && b.Source == "" && len(b.Apps) == 0
	case "instance":
		return b.App != "" && b.Key != "" && b.Route == "" && b.Host == "" && b.Prefix == "" && b.Service == "" && b.Backend == "" && b.Source == "" && len(b.Apps) == 0
	case "backend":
		return b.App != "" && b.Key != "" && b.Service != "" && b.Backend != "" && b.Route == "" && b.Host == "" && b.Prefix == "" && b.Source == "" && len(b.Apps) == 0
	case "route":
		_, err := NewTable([]Route{{ID: b.Route, Host: b.Host, Prefix: b.Prefix, Service: "target"}})
		return b.App != "" && b.Key != "" && err == nil && b.Service == "" && b.Backend == "" && b.Source == "" && len(b.Apps) == 0
	case "host":
		_, err := NewTable([]Route{{ID: "target", Host: b.Host, Prefix: "/", Service: "target"}})
		return err == nil && b.App == "" && b.Key == "" && b.Route == "" && b.Prefix == "" && b.Service == "" && b.Backend == "" && b.Source == "" && len(b.Apps) == 0
	case "source":
		if b.App != "" || b.Key != "" || b.Route != "" || b.Host != "" || b.Prefix != "" || b.Service != "" || b.Backend != "" {
			return false
		}
		prefix, err := netip.ParsePrefix(b.Source)
		if err != nil || prefix != prefix.Masked() || prefix.String() != b.Source || prefix.Bits() == 0 || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return false
		}
		for i, app := range b.Apps {
			if !lifecycle.ValidID(app) || slices.Contains(b.Apps[:i], app) {
				return false
			}
		}
		return true
	}
	return false
}
func (b Block) Active(now uint64) bool {
	return now >= b.CreatedAt && (b.ExpiresAt == 0 || now < b.ExpiresAt)
}

type RequestTarget struct {
	Tenant, App, Node, Key, Gateway string
	Route                           Route
	Service, Backend                string
	Source                          netip.Addr
}

// Matches evaluates the selected route, never falls back to a shorter route.
func (b Block) Matches(t RequestTarget, now uint64) bool {
	if !b.Active(now) || b.Node != "" && b.Node != t.Node || b.Scope != "node" && b.Scope != "gateway" && !(b.Scope == "host" && b.Tenant == "") && b.Tenant != t.Tenant {
		return false
	}
	if b.Gateway != "" && b.Gateway != "both" && b.Gateway != t.Gateway {
		return false
	}
	switch b.Scope {
	case "node", "tenant", "gateway":
		return true
	case "instance":
		return b.Key == t.Key && b.App == t.App
	case "route":
		return b.Key == t.Key && b.App == t.App && b.Host == t.Route.Host && b.Prefix == t.Route.Prefix
	case "host":
		return b.Host == t.Route.Host
	case "backend":
		return b.Key == t.Key && b.App == t.App && b.Service == t.Service && b.Backend == t.Backend
	case "source":
		p, err := netip.ParsePrefix(b.Source)
		return err == nil && t.Source.IsValid() && p.Contains(t.Source.Unmap()) && (len(b.Apps) == 0 || slices.Contains(b.Apps, t.App))
	}
	return false
}

type BlockApplication struct {
	ID, Node                   string
	Applied                    bool
	AppliedAt, BlockedRequests uint64
	Error                      string `json:",omitempty"`
}

type BackendSnapshot struct {
	ID, Task, Node, Network, Address string
	Port                             uint16
	Weight                           int
	Generation                       uint64
	Healthy, Draining                bool
	ObservedAt                       uint64
}
type ListenerSnapshot struct {
	ID, Address, Gateway string
	TLS, HTTP3           bool
	State                string
}
type InstanceSnapshot struct {
	ControlRevision                              uint64 `json:",omitempty"`
	DrainRevision, DrainStartedAt, DrainDeadline uint64 `json:",omitempty"`
	Generation, Revision, ObservedAt             uint64
	BlockRevision                                uint64
	Ready, Draining                              bool
	Error                                        string `json:",omitempty"`
	Connections, Requests                        int
	Listeners                                    []ListenerSnapshot
	Certificates                                 []CertificateObservation `json:",omitempty"`
	Backends                                     []BackendSnapshot
	Metrics                                      Metrics
	Blocks                                       []BlockApplication
}

// Management holds node-local instrumentation and an atomically replaced
// replicated block view. No metric or request sample is written to Raft.
type Management struct {
	mu       sync.Mutex
	revision uint64
	blocks   []Block
	applied  map[string]BlockApplication
	metrics  map[string]*requestMetrics
}

func NewManagement() *Management {
	return &Management{applied: map[string]BlockApplication{}, metrics: map[string]*requestMetrics{}}
}
func (m *Management) UpdateBlocks(revision uint64, node string, blocks []Block, now uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if revision < m.revision || node == "" || len(blocks) > 4096 {
		return ErrRoute
	}
	seen := map[string]bool{}
	for _, b := range blocks {
		if !b.Valid() || seen[b.ID] {
			return ErrRoute
		}
		seen[b.ID] = true
	}
	if revision == m.revision && !slices.EqualFunc(blocks, m.blocks, func(a, b Block) bool { return EqualBlock(a, b) }) {
		return ErrRoute
	}
	for _, b := range blocks {
		a := m.applied[b.ID]
		if a.ID == "" {
			a.Error = "PENDING"
		}
		a.ID, a.Node = b.ID, node
		m.applied[b.ID] = a
	}
	for id := range m.applied {
		if !seen[id] {
			delete(m.applied, id)
		}
	}
	m.revision, m.blocks = revision, cloneBlocks(blocks)
	return nil
}
func EqualBlock(a, b Block) bool {
	apps := slices.Equal(a.Apps, b.Apps)
	a.Apps, b.Apps = nil, nil
	return apps && a.ID == b.ID && a.Scope == b.Scope && a.Gateway == b.Gateway && a.Tenant == b.Tenant && a.App == b.App && a.Node == b.Node && a.Key == b.Key && a.Route == b.Route && a.Host == b.Host && a.Prefix == b.Prefix && a.Service == b.Service && a.Backend == b.Backend && a.Source == b.Source && a.Response == b.Response && a.CutExisting == b.CutExisting && a.ExpiresAt == b.ExpiresAt && a.CreatedAt == b.CreatedAt && a.Reason == b.Reason && a.Actor == b.Actor
}
func cloneBlocks(in []Block) []Block {
	out := slices.Clone(in)
	for i := range out {
		out[i].Apps = slices.Clone(out[i].Apps)
	}
	return out
}
func (m *Management) Match(t RequestTarget, now uint64) (Block, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.blocks {
		if b.Matches(t, now) {
			return b, true
		}
	}
	return Block{}, false
}
func (m *Management) CountBlock(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.applied[id]
	if ok {
		a.BlockedRequests++
		m.applied[id] = a
	}
}
func (m *Management) ReportApplication(id string, applied bool, now uint64, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.applied[id]
	if !ok {
		return
	}
	if a.Applied != applied || a.Error != code {
		a.AppliedAt = now
	}
	a.Applied, a.Error = applied, code
	m.applied[id] = a
}
func (m *Management) Applications() []BlockApplication {
	_, out := m.BlockSnapshot()
	return out
}

// BlockSnapshot pairs the installed policy revision with its application facts.
// An absent ID alone cannot prove an unblock when the desired view is newer.
func (m *Management) BlockSnapshot() (uint64, []BlockApplication) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []BlockApplication
	for _, a := range m.applied {
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b BlockApplication) int { return strings.Compare(a.ID, b.ID) })
	return m.revision, out
}
