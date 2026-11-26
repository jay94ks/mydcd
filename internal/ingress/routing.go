// SPDX-License-Identifier: Apache-2.0

// Package ingress contains routing and backend selection, independent of HTTP
// servers. Existing streams retain their original backend lease through Drain.
package ingress

import (
	"errors"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"sort"
	"strings"
)

var ErrRoute = errors.New("invalid or unmatched route/backend")

type Route struct {
	BalanceRevision           uint64   `json:",omitempty"`
	OriginalBalance           *Balance `json:",omitempty"`
	ID, Host, Prefix, Service string
	Gateway                   string   `json:",omitempty"`
	Balance                   *Balance `json:",omitempty"`
}

func host(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return "", false
			}
		}
	}
	return s, true
}
func validPath(s string) bool {
	for i := range s {
		if s[i] < 32 || s[i] == 127 {
			return false
		}
	}
	if s == "" || s[0] != '/' || strings.ContainsAny(s, "%\\?#\x00\r\n") || strings.Contains(s, "//") {
		return false
	}
	for _, v := range strings.Split(s, "/") {
		if v == "." || v == ".." {
			return false
		}
	}
	return true
}

type compiledRoute struct {
	Route
	rank   int
	suffix string
}
type Table struct{ routes []compiledRoute }

func NewTable(routes []Route) (Table, error) {
	t := Table{}
	ids := map[string]bool{}
	patterns := map[string]bool{}
	for _, r := range routes {
		if r.ID == "" || r.Service == "" || ids[r.ID] || !validPath(r.Prefix) || r.Prefix != "/" && strings.HasSuffix(r.Prefix, "/") {
			return Table{}, ErrRoute
		}
		ids[r.ID] = true
		c := compiledRoute{Route: r}
		switch {
		case r.Host == "*":
			c.rank = 0
		case strings.HasPrefix(r.Host, "*."):
			h, ok := host(r.Host[2:])
			if !ok {
				return Table{}, ErrRoute
			}
			c.Host = "*." + h
			c.suffix = "." + h
			c.rank = 1
		default:
			h, ok := host(r.Host)
			if !ok {
				return Table{}, ErrRoute
			}
			c.Host = h
			c.rank = 2
		}
		key := c.Host + "\x00" + r.Prefix
		if patterns[key] {
			return Table{}, ErrRoute
		}
		patterns[key] = true
		t.routes = append(t.routes, c)
	}
	sort.Slice(t.routes, func(i, j int) bool {
		a, b := t.routes[i], t.routes[j]
		if a.rank != b.rank {
			return a.rank > b.rank
		}
		if len(a.suffix) != len(b.suffix) {
			return len(a.suffix) > len(b.suffix)
		}
		if len(a.Prefix) != len(b.Prefix) {
			return len(a.Prefix) > len(b.Prefix)
		}
		return a.ID < b.ID
	})
	return t, nil
}

func routeTable(routes []Route, gateway string) (Table, error) {
	selected := []Route{}
	for _, r := range routes {
		if gatewayIncludes(r.Gateway, gateway) {
			selected = append(selected, r)
		}
	}
	return NewTable(selected)
}

// Match uses an already separated ASCII host and decoded path. Adapters must
// reject encoded separator ambiguity before calling, and forward that same path.
func (t Table) Match(name, path string) (Route, error) {
	h, ok := host(name)
	if !ok || !validPath(path) {
		return Route{}, ErrRoute
	}
	for _, r := range t.routes {
		match := r.rank == 0 || r.rank == 2 && h == r.Host || r.rank == 1 && strings.HasSuffix(h, r.suffix)
		if match && (r.Prefix == "/" || path == r.Prefix || strings.HasPrefix(path, r.Prefix+"/")) {
			return r.Route, nil
		}
	}
	return Route{}, ErrRoute
}

func (t Table) Host(name string) (Route, error) {
	h, ok := host(name)
	if !ok {
		return Route{}, ErrRoute
	}
	for _, r := range t.routes {
		if r.rank == 0 || r.rank == 2 && h == r.Host || r.rank == 1 && strings.HasSuffix(h, r.suffix) {
			return r.Route, nil
		}
	}
	return Route{}, ErrRoute
}

type Backend struct {
	ID                string
	Generation        uint64
	Weight, Capacity  int
	Healthy, Draining bool
	ObservedAt        uint64
}
type BackendLease struct {
	Backend string
	Lease   reconcile.Lease
}
type backendState struct {
	spec         Backend
	leases       *reconcile.Leases
	current      int64
	healthySince uint64
}
type Balancer struct {
	backends map[string]*backendState
	floors   map[string]uint64
	ticket   uint64
	maxAge   uint64
}

func NewBalancer(maxAge uint64) (*Balancer, error) {
	if maxAge == 0 {
		return nil, ErrRoute
	}
	return &Balancer{backends: map[string]*backendState{}, floors: map[string]uint64{}, maxAge: maxAge}, nil
}

// ObserveHealth distinguishes an actual health response from an unobserved
// timeout. The caller supplies the observation; no clock or I/O lives here.
func (b *Balancer) ObserveHealth(s Backend, observed bool) error {
	if !observed {
		s.Healthy = false
		if prior, ok := b.backends[s.ID]; ok && prior.spec.Generation == s.Generation {
			s.Healthy, s.ObservedAt = prior.spec.Healthy, prior.spec.ObservedAt
		} else {
			s.ObservedAt = 0
		}
	}
	return b.Update(s)
}

// Update never changes an in-use backend's generation/capacity. First Drain,
// settle all users, remove it, then introduce the new generation explicitly.
func (b *Balancer) Update(s Backend) error {
	if s.ID == "" || s.Generation == 0 || s.Weight <= 0 || s.Weight > 1024 || s.Capacity <= 0 {
		return ErrRoute
	}
	old, ok := b.backends[s.ID]
	if ok {
		if old.spec.Generation != s.Generation || old.spec.Capacity != s.Capacity || s.ObservedAt < old.spec.ObservedAt || old.spec.Draining && !s.Draining {
			return ErrRoute
		}
		if !old.spec.Healthy && s.Healthy {
			old.healthySince = s.ObservedAt
		}
		old.spec = s
		if s.Draining {
			old.leases.Drain()
		}
		return nil
	}
	if s.Generation <= b.floors[s.ID] || len(b.backends) >= 1024 {
		return ErrRoute
	}
	l, err := reconcile.NewLeases(s.Generation, s.Capacity)
	if err != nil {
		return err
	}
	if s.Draining {
		l.Drain()
	}
	b.backends[s.ID] = &backendState{spec: s, leases: l, healthySince: s.ObservedAt}
	b.floors[s.ID] = s.Generation
	return nil
}
func (b *Balancer) Acquire(now uint64) (BackendLease, error) {
	return b.AcquireWith(now, Balance{}, Selection{})
}
func (b *Balancer) Release(l BackendLease) error {
	s, ok := b.backends[l.Backend]
	if !ok {
		return ErrRoute
	}
	return s.leases.Release(l.Lease)
}
func (b *Balancer) Remove(id string, generation uint64) error {
	s, ok := b.backends[id]
	if !ok || s.spec.Generation != generation || !s.leases.CanRetire() {
		return ErrRoute
	}
	delete(b.backends, id)
	return nil
}

type BackendRecord struct {
	Spec         Backend
	Pins         reconcile.LeaseJournal
	Current      int64  `json:",omitempty"`
	HealthySince uint64 `json:",omitempty"`
}
type BalanceJournal struct {
	Schema         uint8
	MaxAge, Ticket uint64
	Backends       []BackendRecord
	Floors         map[string]uint64
}

func (b *Balancer) Checkpoint() BalanceJournal {
	j := BalanceJournal{Schema: 1, MaxAge: b.maxAge, Ticket: b.ticket, Floors: map[string]uint64{}}
	for _, v := range b.backends {
		j.Backends = append(j.Backends, BackendRecord{Spec: v.spec, Pins: v.leases.Checkpoint(), Current: v.current, HealthySince: v.healthySince})
	}
	sort.Slice(j.Backends, func(i, k int) bool { return j.Backends[i].Spec.ID < j.Backends[k].Spec.ID })
	for k, v := range b.floors {
		j.Floors[k] = v
	}
	return j
}
func RestoreBalancer(j BalanceJournal) (*Balancer, error) {
	b, err := NewBalancer(j.MaxAge)
	if err != nil || j.Schema != 1 {
		return nil, ErrRoute
	}
	b.ticket = j.Ticket
	for _, r := range j.Backends {
		if _, ok := b.backends[r.Spec.ID]; ok {
			return nil, ErrRoute
		}
		if err := b.Update(r.Spec); err != nil {
			return nil, err
		}
		pins, err := reconcile.RestoreLeases(r.Pins)
		if err != nil || r.Pins.Generation != r.Spec.Generation || r.Pins.Capacity != r.Spec.Capacity || r.Pins.Draining != r.Spec.Draining {
			return nil, ErrRoute
		}
		b.backends[r.Spec.ID].leases = pins
		b.backends[r.Spec.ID].current, b.backends[r.Spec.ID].healthySince = r.Current, r.HealthySince
	}
	for id, floor := range j.Floors {
		if id == "" || floor == 0 || b.floors[id] > floor {
			return nil, ErrRoute
		}
		b.floors[id] = floor
	}
	for id := range b.backends {
		if j.Floors[id] != b.backends[id].spec.Generation {
			return nil, ErrRoute
		}
	}
	return b, nil
}
