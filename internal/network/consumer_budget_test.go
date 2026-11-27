// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

// Actual original DBs and product admission code; current permission/native
// Driver are injected. No actual quorum, TUN, netlink or Engine Ready claim.

func addAdmissionBridge(t *testing.T, m *Manager, key, prefix string) {
	t.Helper()
	p := pool("pool", prefix)
	s := BridgeSpec{Schema: 1, Network: p.Network, Owner: p.Owner, MTU: p.MTU, Pools: []Pool{p}}
	if err := m.Desired(key, 1, 1, &s, 8); err != nil {
		t.Fatal(err)
	}
	if err := m.journal.Step(t.Context(), key, admissionBridgeDriver{}); err != nil {
		t.Fatal(err)
	}
}

func TestNodeConsumerBudgetSerializesTheLastSlotAcrossDistinctBridges(t *testing.T) {
	m := admissionManager(t, func(context.Context, string, reconcile.Desired) (ConsumerBudget, error) {
		return admissionTestBudget(1), nil
	})
	addAdmissionBridge(t, m, "other", "10.9.0.0/24")
	start, done := make(chan struct{}), make(chan error, 2)
	for _, key := range []string{"bridge", "other"} {
		go func() { <-start; _, err := m.borrow(t.Context(), key, "same-local-consumer-name", 1); done <- err }()
	}
	close(start)
	success := 0
	for range 2 {
		if err := <-done; err == nil {
			success++
		} else if !errors.Is(err, reconcile.ErrLease) {
			t.Fatal(err)
		}
	}
	a, _ := m.View("bridge")
	b, _ := m.View("other")
	if success != 1 || len(a.Consumers)+len(b.Consumers) != 1 {
		t.Fatal("per-Bridge cap bypassed the node total", success, a, b)
	}
}

func TestNodeConsumerBudgetSeparatesTenantLimitAndSharedNodeLimit(t *testing.T) {
	m := admissionManager(t, func(_ context.Context, key string, _ reconcile.Desired) (ConsumerBudget, error) {
		b := admissionTestBudget(3)
		if key == "bridge" {
			b.TenantMaxConsumers = 1
		} else {
			b.Scope.Tenant = "second"
		}
		return b, nil
	})
	addAdmissionBridge(t, m, "second", "10.9.0.0/24")
	pin, err := m.borrow(t.Context(), "bridge", "first-one", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.borrow(t.Context(), "bridge", "first-excess", 1); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("tenant exceeded its own budget", err)
	}
	for _, id := range []string{"second-one", "second-two"} {
		if _, err := m.borrow(t.Context(), "second", id, 1); err != nil {
			t.Fatal("other tenant's unused budget was charged to first", err)
		}
	}
	if _, err := m.borrow(t.Context(), "second", "second-three", 1); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("other tenant bypassed full node budget", err)
	}
	if err := m.journal.Return("bridge", "first-one", pin); err != nil {
		t.Fatal(err)
	}
	if _, err := m.borrow(t.Context(), "second", "second-three", 1); err != nil {
		t.Fatal("exact original return did not release node capacity", err)
	}
}

func TestNodeConsumerBudgetIncludesTUNPinsAndRemainsSharedAfterBothDBsReopen(t *testing.T) {
	current := func(context.Context, string, reconcile.Desired) (ConsumerBudget, error) {
		return admissionTestBudget(2), nil
	}
	bridgePath, tunnelPath := filepath.Join(t.TempDir(), "bridge.db"), filepath.Join(t.TempDir(), "tun.db")
	m, err := OpenManagerWithAdmission(bridgePath, nil, current)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if m != nil {
			_ = m.Close()
		}
	}()
	addAdmissionBridge(t, m, "bridge", "10.8.0.0/24")
	tm, err := OpenTunnelManagerWithAdmission(tunnelPath, "node", m)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if tm != nil {
			_ = tm.Close()
		}
	}()
	s := TunnelSpec{Schema: 1, Owner: "node", Network: "overlay", MTU: 1280, RouteMetric: 100, Routes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	if err := tm.Desired("tun", 1, 1, &s, 8); err != nil {
		t.Fatal(err)
	}
	if err := tm.journal.Step(t.Context(), "tun", admissionBridgeDriver{}); err != nil {
		t.Fatal(err)
	}
	bridge, err := m.borrow(t.Context(), "bridge", "app", 1)
	if err != nil {
		t.Fatal(err)
	}
	tun, err := tm.borrow(t.Context(), "tun", "packet-plane", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tm.borrow(t.Context(), "tun", "ingress/extra", 1); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("TUN dependency bypassed Bridge/TUN total", err)
	}
	if err := tm.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = OpenManagerWithAdmission(bridgePath, nil, current)
	if err != nil {
		t.Fatal(err)
	}
	tm, err = OpenTunnelManagerWithAdmission(tunnelPath, "node", m)
	if err != nil {
		t.Fatal(err)
	}
	if original, err := tm.borrow(t.Context(), "tun", "packet-plane", 1); err != nil || original != tun {
		t.Fatal("TUN original pin recreated after reopen", original, err)
	}
	if _, err := m.borrow(t.Context(), "bridge", "extra", 1); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("reopen reset aggregate usage", err)
	}
	if err := m.journal.Return("bridge", "app", bridge); err != nil {
		t.Fatal(err)
	}
	if _, err := tm.borrow(t.Context(), "tun", "ingress/extra", 1); err != nil {
		t.Fatal("original Bridge return not reflected in TUN admission", err)
	}
}

func TestUnknownLegacyConsumerScopeNeverCountsAsZeroOrInheritsNewAuthority(t *testing.T) {
	deny := true
	denied := errors.New("unmapped/revoked original source")
	m := admissionManager(t, func(_ context.Context, key string, _ reconcile.Desired) (ConsumerBudget, error) {
		if key == "bridge" && deny {
			return ConsumerBudget{}, denied
		}
		return admissionTestBudget(3), nil
	})
	legacy, err := m.journal.Borrow("bridge", "legacy-original", 1)
	if err != nil {
		t.Fatal(err)
	}
	addAdmissionBridge(t, m, "other", "10.9.0.0/24")
	if _, err := m.borrow(t.Context(), "other", "new", 1); !errors.Is(err, denied) {
		t.Fatal("unknown original scope was ignored/adopted", err)
	}
	r, _ := m.View("bridge")
	if r.Scope != (reconcile.ConsumerScope{}) || r.Consumers["legacy-original"] != legacy {
		t.Fatal("denial altered legacy ownership")
	}
	if same, err := m.borrow(t.Context(), "bridge", "legacy-original", 1); err != nil || same != legacy {
		t.Fatal("unknown scope blocked original recovery", same, err)
	}
	deny = false // the exact original source has a current explicit shared scope
	if _, err := m.borrow(t.Context(), "other", "new", 1); err != nil {
		t.Fatal(err)
	}
	r, _ = m.View("bridge")
	if r.Scope != admissionTestBudget(3).Scope || r.Consumers["legacy-original"] != legacy {
		t.Fatal("known-source metadata binding replaced original pin", r)
	}
	deny = true
	if _, err := m.borrow(t.Context(), "other", "last", 1); err != nil {
		t.Fatal("current revocation erased already-bound original scope", err)
	}
	if _, err := m.journal.Borrow("bridge", "legacy-bypass", 1); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("unscoped fresh borrow bypassed established budget scope", err)
	}
}

func TestConsumerBudgetRejectsForeignScopeAndAllowsGlobalShrinkBelowOldTenantLimit(t *testing.T) {
	b := admissionTestBudget(4)
	b.NodeMaxConsumers = 2 // retained tenant policy can exceed a later global shrink
	if !b.Valid() || admitConsumerCounts([]consumerCount{{b.Scope, 1}}, b) != nil {
		t.Fatal("global shrink incorrectly invalidated remaining allowed capacity")
	}
	if !errors.Is(admitConsumerCounts([]consumerCount{{b.Scope, 2}}, b), reconcile.ErrLease) {
		t.Fatal("global shrink did not block excess")
	}
	for _, change := range []func(*reconcile.ConsumerScope){func(s *reconcile.ConsumerScope) { s.Node = "another" }, func(s *reconcile.ConsumerScope) { s.Owner = "foreign" }, func(s *reconcile.ConsumerScope) { s.Tenant = "" }} {
		s := b.Scope
		change(&s)
		if admitConsumerCounts([]consumerCount{{s, 1}}, b) == nil {
			t.Fatal("foreign/corrupt original scope counted as local", s)
		}
	}
}
