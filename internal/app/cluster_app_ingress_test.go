// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/storage"
)

type clusterAppIngressDeps struct {
	mu       sync.Mutex
	acquired []string
}

func (d *clusterAppIngressDeps) Acquire(_ context.Context, b ingress.BackendSpec, _ string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.acquired = append(d.acquired, b.Address.String())
	return nil
}
func (d *clusterAppIngressDeps) Release(context.Context, ingress.BackendSpec, string) error {
	return nil
}

func freeListenerAddress(t *testing.T) string {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func clusterAppRouteRecord(t *testing.T, revision uint64, removed bool) control.ClusterAppRouteRecord {
	d := deployment.IngressDeclaration{
		Node:      "node-a",
		Runtime:   deployment.IngressRuntime{MaxRequests: 8, MaxConnections: 32, MaxHeaderBytes: 16384, MaxBodyBytes: 1 << 20, BufferBytes: 512 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 2000, ResponseHeaderTimeoutMS: 5000, HealthIntervalMS: 1000},
		Listeners: []deployment.ListenerDeclaration{{Address: freeListenerAddress(t)}},
		Routes:    []deployment.IngressRouteDeclaration{{ID: "ui", Host: "sfc.example.com"}},
	}
	if err := deployment.ValidateClusterAppIngress(d); err != nil {
		t.Fatal(err)
	}
	return control.ClusterAppRouteRecord{App: "web", Revision: revision, Removed: removed, Ingress: d}
}

// One record revision is one generation; an endpoint move only updates the
// backend; a changed or removed record drains before anything new starts.
func TestClusterAppRoutesServeTheirRecord(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps := &clusterAppIngressDeps{}
	m, err := ingress.Open(ctx, filepath.Join(t.TempDir(), "runtime.db"), deps)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	r := &Runtime{ingress: m, owner: "owner"}
	key := clusterAppIngressPrefix + "web"
	pass := func(rec control.ClusterAppRouteRecord, on bool, backend *deployment.ClusterAppBackend, binding uint64) {
		t.Helper()
		if err := r.reconcileClusterAppRoute(ctx, "web", rec, on, backend, binding); err != nil {
			t.Fatal(err)
		}
	}
	observe := func() ingress.Observation {
		t.Helper()
		o, err := m.Observe(key)
		if err != nil {
			t.Fatal(err)
		}
		return o
	}
	untilGone := func(rec control.ClusterAppRouteRecord, on bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); !observe().Gone; time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("drain never ended")
			}
			pass(rec, on, nil, 1)
		}
	}

	pass(control.ClusterAppRouteRecord{}, false, nil, 1)
	if slices.Contains(m.Keys(), key) {
		t.Fatal("no record started listeners")
	}
	first := clusterAppRouteRecord(t, 1, false)
	pass(first, false, nil, 1) // another server's routes
	if slices.Contains(m.Keys(), key) {
		t.Fatal("another server's routes started here")
	}
	pass(first, true, nil, 1) // no endpoint yet: listeners stand, 502
	if o := observe(); o.Generation != 1 || o.Draining || o.Gone {
		t.Fatalf("first: %+v", o)
	}
	pass(first, true, &deployment.ClusterAppBackend{Node: "node-a", Address: netip.MustParseAddr("10.254.0.9")}, 2)
	if o := observe(); o.Generation != 1 || o.Draining || len(deps.acquired) == 0 || slices.ContainsFunc(deps.acquired, func(a string) bool { return a != "10.254.0.9" }) {
		t.Fatalf("endpoint is a backend update, not a new generation: %+v %v", o, deps.acquired)
	}

	second := clusterAppRouteRecord(t, 2, false)
	pass(second, true, nil, 2)
	if o := observe(); o.Generation != 1 || !o.Draining {
		t.Fatalf("a changed record drains the old generation first: %+v", o)
	}
	untilGone(second, true)
	pass(second, true, nil, 2)
	if o := observe(); o.Generation != 2 || o.Draining || o.Gone {
		t.Fatalf("second: %+v", o)
	}

	removed := second
	removed.Revision, removed.Removed = 3, true
	pass(removed, false, nil, 2)
	untilGone(removed, false)
	pass(removed, false, nil, 2)
	if o := observe(); o.Generation != 2 || !o.Gone {
		t.Fatalf("removed: %+v", o)
	}
}

// An observation from a cluster app route has no workspace: it is recorded as
// the server's own event instead of being refused for its tenant.
func TestClusterAppIngressEventsBelongToTheServer(t *testing.T) {
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	db, err := storage.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store, err := eventlog.Open(db, [32]byte{92}, "node-a", self)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{events: store}
	now := uint64(time.Now().UnixMilli())
	r.ingressEvent(ingress.Event{Kind: "cert-expiring", Node: "node-a", Tenant: deployment.ClusterAppTenant, App: deployment.ClusterAppPrefix + "web", RouteID: "ui", Host: "sfc.example.com", Prefix: "/", Gateway: "local", ObservedAt: now})
	if r.moduleError != nil {
		t.Fatal(r.moduleError)
	}
	batch, err := store.Export(0, now+1)
	if err != nil || len(batch.Records) != 1 {
		t.Fatal(err, len(batch.Records))
	}
	if e := batch.Records[0].Event; e.Scope != "node" || e.Target.Tenant != "" || e.Target.App != "" || e.Target.Host != "sfc.example.com" {
		t.Fatalf("event: %+v", e)
	}
}

func TestClusterAppIngressKeysAreNotAppIngress(t *testing.T) {
	if !clusterAppIngressKey(clusterAppIngressPrefix+"web") || clusterAppIngressKey("tenant/shop/ingress/web") {
		t.Fatal("prefix")
	}
}
