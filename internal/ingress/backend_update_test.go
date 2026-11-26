// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
)

// Only native network effects are fake. The update journal, original request
// leases, balancer and DB writes are the same implementations used by Manager.
type backendTestDependencies struct {
	held     map[string]BackendSpec
	unknown  bool
	returned []string
}

func (d *backendTestDependencies) Acquire(_ context.Context, b BackendSpec, id string) error {
	if old, exists := d.held[id]; exists && !sameBackend(old, b) {
		return ErrRoute
	}
	d.held[id] = b
	if d.unknown {
		d.unknown = false
		return errors.New("fake lost native reply after acquire")
	}
	return nil
}
func (d *backendTestDependencies) Release(_ context.Context, b BackendSpec, id string) error {
	if old, exists := d.held[id]; exists && !sameBackend(old, b) {
		return ErrRoute
	}
	delete(d.held, id)
	d.returned = append(d.returned, id)
	return nil
}

func backendUpdateSpec() Spec {
	return Spec{Schema: 1, Owner: "owner", DynamicBackends: true, BindingRevision: 10,
		Listeners: []Listener{{ID: "http", Address: "127.0.0.1:18080"}}, Routes: []Route{{ID: "route", Host: "app.test", Prefix: "/", Service: "web"}},
		MaxRequests: 2, MaxConnections: 8, MaxHeaderBytes: 4096, MaxBodyBytes: 1 << 20, BufferBytes: 128 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 1000, ResponseHeaderTimeoutMS: 2000, HealthIntervalMS: 100,
		Services: []Service{{ID: "web", Backends: []BackendSpec{
			{ID: "a", Task: "workload/task/tenant/app/web/node-a/r1", Generation: 2, Revision: 2, Address: netip.MustParseAddr("10.0.1.2"), Network: "app", Port: 8080, Weight: 1, Capacity: 2, HealthPath: "/ready"},
			{ID: "b", Task: "workload/task/tenant/app/web/node-b/r1", Generation: 2, Revision: 2, Address: netip.MustParseAddr("10.0.2.2"), Network: "app", Port: 8080, Weight: 1, Capacity: 2, HealthPath: "/ready"},
		}}}}
}

func TestBackendUpdateKeepsOtherRequestsAndReturnsSupersededUnknownAcquire(t *testing.T) {
	ctx := context.Background()
	deps := &backendTestDependencies{held: map[string]BackendSpec{}}
	m, err := Open(ctx, filepath.Join(t.TempDir(), "ingress.db"), deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	spec := backendUpdateSpec()
	if _, err := DecodeSpec(marshal(spec)); err != nil {
		t.Fatal(err)
	}
	r, err := newRecord(8, 7, spec)
	if err != nil {
		t.Fatal(err)
	}
	balancer, _ := RestoreBalancer(r.Balances["web"])
	for _, backend := range spec.Services[0].Backends {
		if err := balancer.Update(Backend{ID: backend.ID, Generation: 2, Weight: 1, Capacity: 2, Healthy: true, ObservedAt: 100}); err != nil {
			t.Fatal(err)
		}
		_ = deps.Acquire(ctx, backend, backendConsumer("listener", 7, spec, backend))
	}
	first, _ := balancer.Acquire(100)
	second, _ := balancer.Acquire(100)
	if first.Backend != "a" || second.Backend != "b" {
		t.Fatal("fixture request ownership")
	}
	r.Balances["web"] = balancer.Checkpoint()
	i := newInstance(m, "listener", r)
	m.instances["listener"] = i
	if err := i.save(r); err != nil {
		t.Fatal(err)
	}
	target := backendUpdateSpec()
	target.BindingRevision = 20
	target.Services[0].Backends[0].Generation, target.Services[0].Backends[0].Revision = 3, 3
	if err := m.reconcileBackends(ctx, i, 8, 7, target); err != nil {
		t.Fatal(err)
	}
	if i.record.Update == nil || len(deps.returned) != 0 || i.record.Spec.Services[0].Backends[0].Generation != 2 {
		t.Fatal("in-flight request lost its original network source")
	}
	active, _ := RestoreBalancer(i.record.Balances["web"])
	next, err := active.Acquire(100)
	if err != nil || next.Backend != "b" {
		t.Fatal("draining one backend disabled its healthy peer", err)
	}
	_ = active.Release(next)
	r = i.copyRecord()
	r.Balances["web"] = active.Checkpoint()
	if err := i.save(r); err != nil {
		t.Fatal(err)
	}
	// The socket already finished, but its exact journal return was deferred
	// by a failed local write. Pending backend updates must retry this return.
	i.returns["completed-original"] = completedRequest{service: "web", pin: first}
	deps.unknown = true
	if err := m.reconcileBackends(ctx, i, 8, 7, target); err == nil {
		t.Fatal("lost acquire reply was reported as success")
	}
	third := backendUpdateSpec()
	third.BindingRevision = 30
	third.Services[0].Backends[0].Generation, third.Services[0].Backends[0].Revision = 4, 4
	if err := m.reconcileBackends(ctx, i, 8, 7, third); err != nil {
		t.Fatal(err)
	}
	if i.record.Update != nil || i.record.Generation != 7 || i.record.Revision != 8 || i.record.Spec.BindingRevision != 30 {
		t.Fatal("backend update replaced the listener source")
	}
	if len(deps.held) != 2 {
		t.Fatal("superseded unknown pin leaked or healthy original pin disappeared", len(deps.held))
	}
	if _, held := deps.held[backendConsumer("listener", 7, target, target.Services[0].Backends[0])]; held {
		t.Fatal("unknown superseded acquire was not positively returned")
	}
	active, _ = RestoreBalancer(i.record.Balances["web"])
	if err := active.Release(second); err != nil {
		t.Fatal("unchanged peer's original request was lost", err)
	}
	r = i.copyRecord()
	r.Balances["web"] = active.Checkpoint()
	if err := validateRecord(r); err != nil {
		t.Fatal("new native record cannot recover", err)
	}
	if err := i.save(r); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcileBackends(ctx, i, 8, 7, target); err == nil {
		t.Fatal("stale backend view restored a superseded generation")
	}
}

func TestBackendUpdateRejectsDrainedResurrectionAndRecoversUnknownNewGeneration(t *testing.T) {
	for _, supersede := range []bool{false, true} {
		name := "retry-original-pending-target"
		if supersede {
			name = "supersede-unknown-target"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			deps := &backendTestDependencies{held: map[string]BackendSpec{}}
			path := filepath.Join(t.TempDir(), "ingress.db")
			m, err := Open(ctx, path, deps)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := m.Close(); err != nil {
					t.Error(err)
				}
			})
			spec := backendUpdateSpec()
			r, err := newRecord(8, 7, spec)
			if err != nil {
				t.Fatal(err)
			}
			i := newInstance(m, "listener", r)
			m.instances[i.key] = i
			if err := i.save(r); err != nil {
				t.Fatal(err)
			}
			for _, b := range spec.Services[0].Backends {
				if err := deps.Acquire(ctx, b, backendConsumer(i.key, 7, spec, b)); err != nil {
					t.Fatal(err)
				}
			}
			target := backendUpdateSpec()
			target.BindingRevision = 20
			target.Services[0].Backends[0].Generation, target.Services[0].Backends[0].Revision = 3, 3
			deps.unknown = true
			if err := m.reconcileBackends(ctx, i, 8, 7, target); err == nil {
				t.Fatal("lost acquire was accepted")
			}
			conflict := backendUpdateSpec()
			conflict.BindingRevision = 20
			if err := m.reconcileBackends(ctx, i, 8, 7, conflict); err == nil {
				t.Fatal("same committed ordinal changed its pending target")
			}
			restored := backendUpdateSpec()
			restored.BindingRevision = 30
			if err := m.reconcileBackends(ctx, i, 8, 7, restored); !errors.Is(err, ErrRoute) {
				t.Fatal("a drained generation was resurrected", err)
			}
			if i.record.Update == nil || i.record.Update.Target.BindingRevision != 20 || len(i.record.Update.Released) != 1 || deps.unknown {
				t.Fatal("refused resurrection changed the original pending target/Return")
			}
			if err := m.Close(); err != nil {
				t.Fatal(err)
			}
			m, err = Open(ctx, path, deps)
			if err != nil {
				t.Fatal("pending update cannot recover", err)
			}
			i = m.instances["listener"]
			restored = target
			if supersede {
				restored.BindingRevision = 40
				restored.Services[0].Backends[0].Generation, restored.Services[0].Backends[0].Revision = 4, 4
			}
			if err := m.reconcileBackends(ctx, i, 8, 7, restored); err != nil {
				t.Fatal(err)
			}
			if i.record.Update != nil || len(deps.held) != 2 {
				t.Fatal("recovery leaked or omitted an exact native pin")
			}
			for _, b := range restored.Services[0].Backends {
				if held, ok := deps.held[backendConsumer(i.key, 7, restored, b)]; !ok || !sameBackend(held, b) {
					t.Fatal("published backend lacks its original consumer", b.ID)
				}
			}
			if err := validateRecord(i.record); err != nil {
				t.Fatal(err)
			}
		})
	}
}
