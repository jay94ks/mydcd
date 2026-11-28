// SPDX-License-Identifier: Apache-2.0

// Package ingress contains routing and backend selection, independent of HTTP
// servers. Existing streams retain their original backend lease through Drain.
package ingress

import (
	"errors"
	"github.com/jay94ks/seafield/internal/reconcile"
	"sort"
	"strconv"
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
	// retiring holds older generations of a backend ID that were drained
	// when their successor took the ID (a same-node surge): they are never
	// selected and only settle their pins. Keyed by retireKey.
	retiring map[string]*backendState
	floors   map[string]uint64
	ticket   uint64
	maxAge   uint64
}

func NewBalancer(maxAge uint64) (*Balancer, error) {
	if maxAge == 0 {
		return nil, ErrRoute
	}
	return &Balancer{backends: map[string]*backendState{}, retiring: map[string]*backendState{}, floors: map[string]uint64{}, maxAge: maxAge}, nil
}

func retireKey(id string, generation uint64) string {
	return id + "\x00" + strconv.FormatUint(generation, 10)
}

// entry is the serving or retiring state of one exact backend generation.
func (b *Balancer) entry(id string, generation uint64) (*backendState, bool) {
	if s, ok := b.backends[id]; ok && s.spec.Generation == generation {
		return s, true
	}
	s, ok := b.retiring[retireKey(id, generation)]
	return s, ok
}

// ObserveHealth distinguishes an actual health response from an unobserved
// timeout. The caller supplies the observation; no clock or I/O lives here.
func (b *Balancer) ObserveHealth(s Backend, observed bool) error {
	if !observed {
		s.Healthy = false
		if prior, ok := b.entry(s.ID, s.Generation); ok {
			s.Healthy, s.ObservedAt = prior.spec.Healthy, prior.spec.ObservedAt
		} else {
			s.ObservedAt = 0
		}
	}
	return b.Update(s)
}

// Update never changes an in-use backend's generation/capacity. A newer
// generation may take an ID only once the current one is Draining: the old one
// then retires beside it and settles its own pins (a same-node surge), so the
// ID keeps serving. Otherwise first Drain, settle, remove, then introduce.
func (b *Balancer) Update(s Backend) error {
	if s.ID == "" || s.Generation == 0 || s.Weight <= 0 || s.Weight > 1024 || s.Capacity <= 0 {
		return ErrRoute
	}
	if r, ok := b.retiring[retireKey(s.ID, s.Generation)]; ok {
		if r.spec.Capacity != s.Capacity || s.ObservedAt < r.spec.ObservedAt || !s.Draining {
			return ErrRoute
		}
		r.spec = s
		return nil
	}
	old, ok := b.backends[s.ID]
	if ok && old.spec.Generation < s.Generation && old.spec.Draining && s.Generation > b.floors[s.ID] {
		if len(b.backends)+len(b.retiring) >= 1024 {
			return ErrRoute
		}
		b.retiring[retireKey(s.ID, old.spec.Generation)] = old
		delete(b.backends, s.ID)
		ok = false
	}
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
	if s.Generation <= b.floors[s.ID] || len(b.backends)+len(b.retiring) >= 1024 {
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
	s, ok := b.entry(l.Backend, l.Lease.Generation)
	if !ok {
		return ErrRoute
	}
	return s.leases.Release(l.Lease)
}
func (b *Balancer) Remove(id string, generation uint64) error {
	s, ok := b.entry(id, generation)
	if !ok || !s.leases.CanRetire() {
		return ErrRoute
	}
	if b.backends[id] == s {
		delete(b.backends, id)
	} else {
		delete(b.retiring, retireKey(id, generation))
	}
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
	for _, states := range []map[string]*backendState{b.backends, b.retiring} {
		for _, v := range states {
			j.Backends = append(j.Backends, BackendRecord{Spec: v.spec, Pins: v.leases.Checkpoint(), Current: v.current, HealthySince: v.healthySince})
		}
	}
	// Older generations of one ID first, so Restore replays each succession.
	sort.Slice(j.Backends, func(i, k int) bool {
		a, c := j.Backends[i].Spec, j.Backends[k].Spec
		return a.ID < c.ID || a.ID == c.ID && a.Generation < c.Generation
	})
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
	for at, r := range j.Backends {
		if at > 0 {
			prior := j.Backends[at-1].Spec
			if prior.ID == r.Spec.ID && (prior.Generation >= r.Spec.Generation || !prior.Draining) {
				return nil, ErrRoute
			}
		}
		if err := b.Update(r.Spec); err != nil {
			return nil, err
		}
		pins, err := reconcile.RestoreLeases(r.Pins)
		if err != nil || r.Pins.Generation != r.Spec.Generation || r.Pins.Capacity != r.Spec.Capacity || r.Pins.Draining != r.Spec.Draining {
			return nil, ErrRoute
		}
		restored, _ := b.entry(r.Spec.ID, r.Spec.Generation)
		restored.leases = pins
		restored.current, restored.healthySince = r.Current, r.HealthySince
	}
	for id, floor := range j.Floors {
		if id == "" || floor == 0 || b.floors[id] > floor {
			return nil, ErrRoute
		}
		b.floors[id] = floor
	}
	for id, v := range b.backends {
		// A retiring generation whose successor was already removed.
		if v.spec.Draining && v.spec.Generation < j.Floors[id] {
			b.retiring[retireKey(id, v.spec.Generation)] = v
			delete(b.backends, id)
		}
	}
	for id := range b.backends {
		if j.Floors[id] != b.backends[id].spec.Generation {
			return nil, ErrRoute
		}
	}
	for _, r := range b.retiring {
		if j.Floors[r.spec.ID] <= r.spec.Generation {
			return nil, ErrRoute
		}
	}
	return b, nil
}
