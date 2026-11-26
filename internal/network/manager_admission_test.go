// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Fake native facts ONLY. Actual DB and the same product Manager.borrow core;
// these tests never use Acquire to claim kernel/Engine readiness.
type admissionBridgeDriver struct{}

func (admissionBridgeDriver) Execute(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectApplied, nil
}
func (admissionBridgeDriver) Recover(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectApplied, nil
}

func admissionTestBudget(capacity int) ConsumerBudget {
	return ConsumerBudget{Scope: reconcile.ConsumerScope{Tenant: "first", Node: "node-a", Owner: "node"}, NodeMaxConsumers: capacity, TenantMaxConsumers: capacity}
}

func admissionManager(t *testing.T, current ConsumerAdmission) *Manager {
	t.Helper()
	m, err := OpenManagerWithAdmission(filepath.Join(t.TempDir(), "network.db"), nil, current)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	p := pool("pool", "10.8.0.0/24")
	s := BridgeSpec{Schema: 1, Network: p.Network, Owner: p.Owner, MTU: p.MTU, Pools: []Pool{p}}
	if err := m.Desired("bridge", 1, 1, &s, 8); err != nil {
		t.Fatal(err)
	}
	if err := m.journal.Step(t.Context(), "bridge", admissionBridgeDriver{}); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManagerEveryFreshConsumerUsesCurrentCapacityButOriginalPinSurvivesRevocation(t *testing.T) {
	var calls atomic.Int32
	denied := false
	permissionError := errors.New("current quorum/revocation denial")
	m := admissionManager(t, func(context.Context, string, reconcile.Desired) (ConsumerBudget, error) {
		calls.Add(1)
		if denied {
			return ConsumerBudget{}, permissionError
		}
		return admissionTestBudget(1), nil
	})
	type result struct {
		consumer string
		pin      reconcile.Lease
		err      error
	}
	start, results := make(chan struct{}), make(chan result, 2)
	for _, consumer := range []string{"dns/one", "dhcp/two"} {
		go func() {
			<-start
			pin, err := m.borrow(t.Context(), "bridge", consumer, 1)
			results <- result{consumer, pin, err}
		}()
	}
	close(start)
	var original result
	success := 0
	for range 2 {
		r := <-results
		if r.err == nil {
			original, success = r, success+1
		} else if !errors.Is(r.err, reconcile.ErrLease) {
			t.Fatal(r.err)
		}
	}
	if success != 1 || calls.Load() != 2 {
		t.Fatal("fresh consumer bypassed shared admission", success, calls.Load())
	}
	denied = true
	if pin, err := m.borrow(t.Context(), "bridge", original.consumer, 1); err != nil || pin != original.pin || calls.Load() != 2 {
		t.Fatal("original pin required a new grant or changed identity", pin, err)
	}
	if _, err := m.borrow(t.Context(), "bridge", "workload/new", 1); !errors.Is(err, permissionError) {
		t.Fatal("fresh caller bypassed current permission", err)
	}
	r, err := m.View("bridge")
	if err != nil || len(r.Consumers) != 1 || r.Capacity != 1 || r.Pins.Next != original.pin.Token {
		t.Fatal("denial changed original pin/floor", r, err)
	}
	if err := m.journal.Return("bridge", original.consumer, original.pin); err != nil {
		t.Fatal("revocation blocked local original return", err)
	}
}

func TestManagerCurrentLookupCannotBorrowARevisedSource(t *testing.T) {
	var m *Manager
	m = admissionManager(t, func(_ context.Context, key string, d reconcile.Desired) (ConsumerBudget, error) {
		d.Revision++ // shared desired changes while the original lookup is in flight
		return admissionTestBudget(1), m.journal.Desired(key, d, 8)
	})
	if _, err := m.borrow(t.Context(), "bridge", "late", 1); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("delayed permission acquired a changed source", err)
	}
	r, err := m.View("bridge")
	if err != nil || len(r.Consumers) != 0 || r.Pins.Next != 0 || r.State.Desired.Revision != 2 {
		t.Fatal("late answer changed pin history", r, err)
	}
}

func TestManagerCanceledAdmissionQueueDoesNotRequestAnotherPermission(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	m := admissionManager(t, func(context.Context, string, reconcile.Desired) (ConsumerBudget, error) {
		calls.Add(1)
		close(entered)
		<-release
		return admissionTestBudget(1), nil
	})
	first := make(chan error, 1)
	go func() {
		_, err := m.borrow(t.Context(), "bridge", "first", 1)
		first <- err
	}()
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	second := make(chan error, 1)
	go func() {
		_, err := m.borrow(ctx, "bridge", "canceled", 1)
		second <- err
	}()
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatal("canceled queued admission requested a fresh grant", err, calls.Load())
	}
}

func TestManagerOriginalConsumerLookupDoesNotWaitForAnotherQuorumCall(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	m := admissionManager(t, func(context.Context, string, reconcile.Desired) (ConsumerBudget, error) {
		if calls.Add(1) == 2 {
			close(entered)
			<-release
		}
		return admissionTestBudget(2), nil
	})
	original, err := m.borrow(t.Context(), "bridge", "original", 1)
	if err != nil {
		t.Fatal(err)
	}
	fresh := make(chan error, 1)
	go func() {
		_, err := m.borrow(t.Context(), "bridge", "fresh", 1)
		fresh <- err
	}()
	<-entered
	recovered := make(chan error, 1)
	go func() {
		pin, err := m.borrow(t.Context(), "bridge", "original", 1)
		if err == nil && pin != original {
			err = errors.New("original pin changed")
		}
		recovered <- err
	}()
	select {
	case err := <-recovered:
		close(release)
		freshErr := <-fresh
		if err != nil || freshErr != nil || calls.Load() != 2 {
			t.Fatal("original recovery requested another grant", err, freshErr)
		}
	case <-time.After(time.Second):
		close(release)
		<-fresh
		<-recovered
		t.Fatal("original pin recovery waited for an unrelated fresh quorum request")
	}
}
