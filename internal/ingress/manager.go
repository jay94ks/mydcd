// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/storage"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Dependencies owns the actual Network reference. Acquire is idempotent for
// this stable consumer, Release settles precisely that original generation.
type Dependencies interface {
	Acquire(context.Context, BackendSpec, string) error
	Release(context.Context, BackendSpec, string) error
}
type instanceRecord struct {
	Update               *backendUpdate `json:",omitempty"`
	Schema               uint8
	Revision, Generation uint64
	Spec                 Spec
	Balances             map[string]BalanceJournal
	Gone                 bool
	Native               string `json:",omitempty"`
}
type Observation struct {
	Backends              []BackendObservation `json:",omitempty"`
	DrainedBackends       []BackendObservation `json:",omitempty"`
	Revision, Generation  uint64
	Ready, Draining, Gone bool
	Started               bool `json:",omitempty"`
	Requests              int
	Listeners             map[string]string
	Error                 string
	ProxyFailures         uint64                   `json:",omitempty"`
	LastProxyFailure      string                   `json:",omitempty"`
	LastProxyFailureMS    int64                    `json:",omitempty"`
	HealthFailures        uint64                   `json:",omitempty"`
	LastHealthFailure     string                   `json:",omitempty"`
	LastHealthFailureMS   int64                    `json:",omitempty"`
	Certificates          []CertificateObservation `json:",omitempty"`
}
type BackendObservation struct {
	Task                 string
	Generation, Revision uint64
}
type Manager struct {
	controls                []RuntimeControl
	controlRevision         uint64
	controlsInitialized     bool
	gatewaySerial           sync.Mutex
	gatewayRetirements      []*sharedGateway
	gatewayConfiguration    GatewayConfiguration
	gatewayClusterAddresses []netip.Addr
	gatewayRevision         uint64
	gatewayError            string
	mu                      sync.Mutex
	db                      *storage.DB
	ctx                     context.Context
	deps                    Dependencies
	instances               map[string]*instance
	closed                  bool
	certMu                  sync.Mutex
	certLoadMu              sync.Mutex
	certificateSource       CertificateSource
	certificateCache        map[string]certificateState
	gatewayMu               sync.Mutex
	gateways                map[string]*sharedGateway
	hostPolicies            map[string]HostPolicy
	gatewayClasses          map[netip.Addr]string
	management              *Management
	node                    string
	eventMu                 sync.Mutex
	eventSink               func(Event)
	acme                    atomic.Pointer[acmeForward]
	enroll                  atomic.Pointer[nodeEnroll]
}

func Open(ctx context.Context, path string, deps Dependencies) (*Manager, error) {
	if ctx == nil || deps == nil {
		return nil, ErrRoute
	}
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	m := &Manager{db: db, ctx: ctx, deps: deps, instances: map[string]*instance{}, management: NewManagement(), gateways: map[string]*sharedGateway{}, hostPolicies: map[string]HostPolicy{}}
	rows, err := db.Scan("instance/")
	if err == nil {
		for key, b := range rows {
			var r instanceRecord
			if err = json.Unmarshal(b, &r); err != nil {
				break
			}
			if r.Schema != 1 || r.Revision == 0 || r.Generation == 0 {
				err = ErrRoute
				break
			}
			if _, err = DecodeSpec(marshal(r.Spec)); err != nil {
				break
			}
			if len(r.Balances) != len(r.Spec.Services) {
				err = ErrRoute
				break
			}
			if err = validateRecord(r); err != nil {
				break
			}
			// The exclusive module DB plus process-owned listeners proves every
			// prior request socket is gone. Preserve floors, settle only its pins.
			for _, svc := range r.Spec.Services {
				j, ok := r.Balances[svc.ID]
				if !ok {
					err = ErrRoute
					break
				}
				var bal *Balancer
				bal, err = RestoreBalancer(j)
				if err != nil {
					break
				}
				for _, br := range j.Backends {
					for _, pin := range br.Pins.Active {
						if err = bal.Release(BackendLease{Backend: br.Spec.ID, Lease: pin}); err != nil {
							break
						}
					}
					if err != nil {
						break
					}
					v := br.Spec
					v.Healthy = false
					if err = bal.Update(v); err != nil {
						break
					}
				}
				if err != nil {
					break
				}
				r.Balances[svc.ID] = bal.Checkpoint()
			}
			if err != nil {
				break
			}
			name := strings.TrimPrefix(key, "instance/")
			if name == "" {
				err = ErrRoute
				break
			}
			i := newInstance(m, name, r)
			if err = i.save(r); err != nil {
				break
			}
			m.instances[name] = i
		}
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return m, nil
}
func validateRecord(r instanceRecord) error {
	if err := validateBackendUpdate(r); err != nil {
		return err
	}
	for _, svc := range r.Spec.Services {
		j, ok := r.Balances[svc.ID]
		if !ok || len(j.Backends) != len(svc.Backends) || j.MaxAge != uint64(r.Spec.HealthIntervalMS*3+r.Spec.DialTimeoutMS+r.Spec.ResponseHeaderTimeoutMS) {
			return ErrRoute
		}
		if _, err := RestoreBalancer(j); err != nil {
			return err
		}
		for _, v := range j.Backends {
			b, ok := backendByID(Spec{Services: []Service{svc}}, v.Spec.ID, v.Spec.Generation)
			if !ok || v.Spec.Weight != b.Weight || v.Spec.Capacity != b.Capacity || v.Spec.Draining != backendDraining(r, b) || r.Gone && len(v.Pins.Active) != 0 {
				return ErrRoute
			}
		}
	}
	if r.Gone && !r.Spec.Lifecycle.Drain {
		return ErrRoute
	}
	return nil
}
func marshal(v any) string { b, _ := json.Marshal(v); return string(b) }
func nativeSpec(s Spec) string {
	s.Lifecycle.Proof = nil
	s.Lifecycle.Drain = false
	s.Lifecycle.Nonce = [16]byte{}
	s.Tenant, s.App = "", ""
	s.SystemWildcard = false // derived route authority, not a physical listener setting
	s.Routes = nil           // route-only changes atomically replace the table, not sockets
	s.Services = append([]Service(nil), s.Services...)
	for at := range s.Services {
		s.Services[at].Balance = nil
		s.Services[at].Backends = append([]BackendSpec(nil), s.Services[at].Backends...)
		for b := range s.Services[at].Backends {
			s.Services[at].Backends[b].Node = ""
			s.Services[at].Backends[b].Labels = nil
			s.Services[at].Backends[b].Version = ""
		}
	}
	if s.DynamicBackends {
		s.BindingRevision = 0
		s.Services = append([]Service(nil), s.Services...)
		for at := range s.Services {
			s.Services[at].Backends = nil
		}
	}
	return marshal(s)
}
func consumer(key string, generation uint64, backend string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s", key, generation, backend)))
	return fmt.Sprintf("ingress/%x", h[:])
}
func newRecord(revision, generation uint64, s Spec) (instanceRecord, error) {
	r := instanceRecord{Schema: 1, Revision: revision, Generation: generation, Spec: s, Balances: map[string]BalanceJournal{}}
	for _, svc := range s.Services {
		b, _ := NewBalancer(uint64(s.HealthIntervalMS*3 + s.DialTimeoutMS + s.ResponseHeaderTimeoutMS))
		// An older surge generation enters first so its successor can take the ID.
		ordered := slices.Clone(svc.Backends)
		slices.SortStableFunc(ordered, func(a, b BackendSpec) int { return cmp.Compare(a.Generation, b.Generation) })
		for _, v := range ordered {
			if err := b.Update(Backend{ID: v.ID, Generation: v.Generation, Weight: v.Weight, Capacity: v.Capacity, Draining: s.Lifecycle.Drain || v.Draining}); err != nil {
				return r, err
			}
		}
		r.Balances[svc.ID] = b.Checkpoint()
	}
	return r, nil
}

// Reconcile consumes one immutable committed source. Inactive/absent sources
// cannot silently abandon a live listener or a reference from an older source.
func (m *Manager) Reconcile(ctx context.Context, key string, revision, generation uint64, s *Spec) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || key == "" || len(key) > 512 || revision == 0 || generation == 0 {
		return ErrRoute
	}
	i := m.instances[key]
	fresh := false
	if s == nil {
		if i == nil {
			return nil
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if !i.record.Gone {
			return ErrRoute
		}
		if m.management != nil {
			m.management.ForgetMetrics(key)
		}
		return nil
	}
	canonical, err := DecodeSpec(marshal(*s))
	if err != nil {
		return err
	}
	s = &canonical
	if i != nil {
		i.mu.Lock()
		old := i.record
		handoff := generation == old.Generation && m.canHandoffLocked(i, *s)
		dynamic := s.DynamicBackends && old.Spec.DynamicBackends && generation == old.Generation && nativeSpec(*s) == nativeSpec(old.Spec) && !old.Spec.Lifecycle.Drain && !s.Lifecycle.Drain
		annotations := generation == old.Generation && annotationSpec(*s) == annotationSpec(old.Spec)
		if revision < old.Revision || generation < old.Generation || revision == old.Revision && marshal(*s) != marshal(old.Spec) && !dynamic && !annotations || generation == old.Generation && (!handoff && nativeSpec(*s) != nativeSpec(old.Spec) || old.Spec.Lifecycle.Drain && !s.Lifecycle.Drain) || generation > old.Generation && !old.Gone {
			i.mu.Unlock()
			return ErrRoute
		}
		i.mu.Unlock()
		if dynamic {
			if err := m.reconcileBackends(ctx, i, revision, generation, *s); err != nil {
				return err
			}
			i.mu.Lock()
			pending := i.record.Update != nil
			i.mu.Unlock()
			if pending {
				return nil // unchanged peers and original request leases continue
			}
		}
		if generation > old.Generation {
			i = newInstance(m, key, instanceRecord{})
			fresh = true
		}
	}
	if i == nil {
		i = newInstance(m, key, instanceRecord{})
		fresh = true
	}
	i.mu.Lock()
	if i.record.Schema == 0 {
		r, err := newRecord(revision, generation, *s)
		if err != nil {
			i.mu.Unlock()
			return err
		}
		if err = i.save(r); err != nil {
			i.mu.Unlock()
			return err
		}
		if fresh {
			m.instances[key] = i
		}
	} else if revision != i.record.Revision || annotationSpec(*s) == annotationSpec(i.record.Spec) && marshal(*s) != marshal(i.record.Spec) {
		original := i.record.Spec
		handoff := generation == i.record.Generation && m.canHandoffLocked(i, *s)
		r := i.copyRecord()
		r.Revision = revision
		if s.DynamicBackends && s.Lifecycle.Drain {
			r.Spec.Lifecycle = s.Lifecycle
			r.Spec.BindingRevision = max(r.Spec.BindingRevision, s.BindingRevision)
		} else {
			r.Spec = *s
		}
		if s.Lifecycle.Drain {
			for name, j := range r.Balances {
				b, _ := RestoreBalancer(j)
				for _, br := range j.Backends {
					v := br.Spec
					v.Draining = true
					if err := b.Update(v); err != nil {
						i.mu.Unlock()
						return err
					}
				}
				r.Balances[name] = b.Checkpoint()
			}
		}
		if err := i.save(r); err != nil {
			i.mu.Unlock()
			return err
		}
		if handoff {
			if err := m.handoffLocked(i, original); err != nil {
				i.failed = err
				i.mu.Unlock()
				return err
			}
		}
		i.table, _ = routeTable(r.Spec.Routes, "local")
	}
	err = i.retryReturns()
	if i.record.Gone {
		i.mu.Unlock()
		return nil
	}
	drain := i.record.Spec.Lifecycle.Drain
	actual := i.record.Spec
	active := i.requests()
	i.mu.Unlock()
	if err != nil {
		return err
	}
	if drain {
		if active != 0 {
			return nil
		}
		if err = i.stop(); err != nil {
			return err
		}
		for _, svc := range actual.Services {
			for _, b := range svc.Backends {
				if err = m.deps.Release(ctx, b, backendConsumer(key, generation, actual, b)); err != nil {
					return err
				}
			}
		}
		if err = m.returnPendingBackends(ctx, i); err != nil {
			return err
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		r := i.copyRecord()
		r.Gone = true
		r.Update = nil
		if err := i.save(r); err != nil {
			return err
		}
		if m.management != nil {
			m.management.ForgetMetrics(key)
		}
		return nil
	}
	for _, svc := range s.Services {
		for _, b := range svc.Backends {
			if err = m.deps.Acquire(ctx, b, backendConsumer(key, generation, *s, b)); err != nil {
				return err
			}
		}
	}
	return i.start()
}
func (m *Manager) Observe(key string) (Observation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.instances[key]
	if m.closed || i == nil {
		return Observation{}, ErrRoute
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	o := Observation{Revision: i.record.Revision, Generation: i.record.Generation, Draining: i.record.Spec.Lifecycle.Drain, Gone: i.record.Gone, Requests: i.requests(), Listeners: map[string]string{}}
	o.Started = i.started
	o.ProxyFailures, o.LastProxyFailure, o.LastProxyFailureMS = i.proxyFailures, i.lastProxyFailure, i.lastProxyFailureMS
	o.HealthFailures, o.LastHealthFailure, o.LastHealthFailureMS = i.healthFailures, i.lastHealthFailure, i.lastHealthFailureMS
	for k, v := range i.addresses {
		o.Listeners[k] = v
	}
	o.Draining = o.Draining || i.controlDraining.Load()
	o.Ready = i.started && !o.Draining && i.failed == nil
	now := uint64(time.Now().UnixMilli())
	type taskEvidence struct {
		row                   BackendObservation
		available, allDrained bool
	}
	// One row per Task generation: during a same-node surge the successor
	// serves while the older generation of the same Task drains.
	tasks := map[BackendObservation]taskEvidence{}
	for _, j := range i.record.Balances {
		healthy := false
		for _, b := range j.Backends {
			declared, exists := backendByID(i.record.Spec, b.Spec.ID, b.Spec.Generation)
			available := exists && !declared.Suspended && b.Spec.Healthy && !b.Spec.Draining && b.Spec.ObservedAt <= now && now-b.Spec.ObservedAt <= j.MaxAge
			healthy = healthy || available
			if exists && i.record.Spec.DynamicBackends {
				row := BackendObservation{Task: declared.Task, Generation: declared.Generation, Revision: declared.Revision}
				prior, known := tasks[row]
				if !known {
					prior = taskEvidence{row: row, allDrained: true}
				}
				prior.available = prior.available || available
				prior.allDrained = prior.allDrained && i.started && i.failed == nil && b.Spec.Draining && len(b.Pins.Active) == 0
				tasks[row] = prior
			}
		}
		o.Ready = o.Ready && healthy
	}
	for _, evidence := range tasks {
		if evidence.available {
			o.Backends = append(o.Backends, evidence.row)
		}
		if evidence.allDrained {
			o.DrainedBackends = append(o.DrainedBackends, evidence.row)
		}
	}
	byTask := func(a, b BackendObservation) int {
		if d := strings.Compare(a.Task, b.Task); d != 0 {
			return d
		}
		return cmp.Compare(a.Generation, b.Generation)
	}
	slices.SortFunc(o.Backends, byTask)
	slices.SortFunc(o.DrainedBackends, byTask)
	if i.failed != nil {
		o.Error = i.failed.Error()
	}
	if failure := m.sharedFailure(key, i.record.Spec); failure != "" {
		o.Error = failure
		o.Ready = false
	}
	o.Certificates = m.certificateObservations(i.record.Spec)
	return o, nil
}
func (m *Manager) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.instances))
	for k := range m.instances {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var err error
	for _, i := range m.instances {
		err = errors.Join(err, i.stop())
	}
	m.gatewayMu.Lock()
	gateways := append([]*sharedGateway(nil), m.gatewayRetirements...)
	for _, g := range m.gateways {
		gateways = append(gateways, g)
	}
	m.gatewayMu.Unlock()
	for _, g := range gateways {
		g.stop()
	}
	return errors.Join(err, m.db.Close())
}

// Endpoint is one transport port the ingress on this node listens on.
type Endpoint struct {
	Proto string // tcp or udp
	Port  uint16
}

// ListenEndpoints is every port this node's ingress listens on or is about
// to: the shared gateways and each instance's own listeners, UDP too for
// HTTP/3. The node firewall keeps them open.
func (m *Manager) ListenEndpoints() []Endpoint {
	out := []Endpoint{}
	add := func(l Listener) {
		a, err := netip.ParseAddrPort(l.Address)
		if l.Shared != "" || err != nil || a.Port() == 0 {
			return
		}
		out = append(out, Endpoint{Proto: "tcp", Port: a.Port()})
		if l.HTTP3 {
			out = append(out, Endpoint{Proto: "udp", Port: a.Port()})
		}
	}
	m.gatewayMu.Lock()
	for _, g := range m.gateways {
		add(g.definition)
	}
	m.gatewayMu.Unlock()
	m.mu.Lock()
	for _, i := range m.instances {
		i.mu.Lock()
		if !i.record.Gone {
			for _, l := range i.record.Spec.Listeners {
				add(l)
			}
		}
		i.mu.Unlock()
	}
	m.mu.Unlock()
	return out
}
