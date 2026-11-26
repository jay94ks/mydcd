// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestRealBoundaryIngressFailedJournalNotPublished(t *testing.T) {
	deps := boundaryDependencies{}
	m, err := Open(context.Background(), filepath.Join(t.TempDir(), "journal.db"), deps)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.db.Close(); err != nil {
		t.Fatal(err)
	}
	s := Spec{Schema: 1, Owner: "owner", Listeners: []Listener{{ID: "http", Address: "127.0.0.1:18080"}}, Routes: []Route{{ID: "r", Host: "*", Prefix: "/", Service: "api"}}, Services: []Service{{ID: "api", Backends: []BackendSpec{{ID: "a", Task: "workload/task/a", Network: "net", Generation: 1, Address: netip.MustParseAddr("127.0.0.1"), Port: 18081, Weight: 1, Capacity: 1, HealthPath: "/health"}}}}, MaxRequests: 1, MaxConnections: 1, MaxHeaderBytes: 1024, BufferBytes: 64 << 10, MaxBodyBytes: 1024, RequestTimeoutMS: 1000, DialTimeoutMS: 100, ResponseHeaderTimeoutMS: 100, HealthIntervalMS: 100}
	if err = m.Reconcile(context.Background(), "ingress/app/a", 1, 1, &s); err == nil {
		t.Fatal("closed DB accepted Desired")
	}
	if len(m.Keys()) != 0 || len(deps) != 0 {
		t.Fatal("failed sync published instance or native dependency", m.Keys(), deps)
	}
	// A failed replacement preserves the old terminal generation as well.
	old := newInstance(m, "ingress/app/a", instanceRecord{Schema: 1, Revision: 1, Generation: 1, Gone: true})
	m.instances[old.key] = old
	if err = m.Reconcile(context.Background(), old.key, 2, 2, &s); err == nil {
		t.Fatal("closed DB accepted replacement")
	}
	if m.instances[old.key] != old || old.record.Generation != 1 {
		t.Fatal("replacement published before sync")
	}
}
