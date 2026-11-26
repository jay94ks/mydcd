// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/network/services"
)

func TestDNSPolicyCacheExactCommittedViewAndName(t *testing.T) {
	ctx := context.Background()
	base := dnsPolicyView{engine: &cluster.Engine{}, index: 10, epoch: 1, raftIndex: 20, term: 2, local: true}
	name := dnsPolicyName{"tenant", "network"}
	for _, field := range []string{"engine", "cluster", "owner", "index", "epoch", "raft-index", "term", "local", "tenant", "id"} {
		t.Run(field, func(t *testing.T) {
			var c dnsPolicyCache
			calls := 0
			resolve := func() (services.DNSOwnerPolicy, error) {
				calls++
				return services.DNSOwnerPolicy{Config: services.DNSConfig{Source: uint64(calls)}}, nil
			}
			p, err := c.current(ctx, base, name, resolve)
			if err != nil || p.Config.Source != 1 {
				t.Fatal("initial resolution", p, err)
			}
			if _, err = c.current(ctx, base, name, resolve); err != nil || calls != 1 {
				t.Fatal("same committed view was reinterpreted", calls, err)
			}
			changed, other := base, name
			switch field {
			case "engine":
				changed.engine = &cluster.Engine{}
			case "cluster":
				changed.cluster[0]++
			case "owner":
				changed.owner[0]++
			case "index":
				changed.index++
			case "epoch":
				changed.epoch++
			case "raft-index":
				changed.raftIndex++
			case "term":
				changed.term++
			case "local":
				changed.local = false
			case "tenant":
				other.tenant = "other"
			case "id":
				other.id = "other"
			}
			p, err = c.current(ctx, changed, other, resolve)
			if err != nil || calls != 2 || p.Config.Source != 2 {
				t.Fatal("another authority view/name reused cached material", calls, err)
			}
		})
	}
}

func TestDNSPolicyCacheNoFallbackAfterRevocationOrCancellation(t *testing.T) {
	var c dnsPolicyCache
	ctx := context.Background()
	view, name := dnsPolicyView{index: 1}, dnsPolicyName{"tenant", "dns"}
	resolve := func() (services.DNSOwnerPolicy, error) {
		return services.DNSOwnerPolicy{Config: services.DNSConfig{Source: 1}}, nil
	}
	if _, err := c.current(ctx, view, name, resolve); err != nil {
		t.Fatal(err)
	}
	view.index++
	denied := errors.New("current committed source/permission revoked")
	for range 2 {
		p, err := c.current(ctx, view, name, func() (services.DNSOwnerPolicy, error) { return services.DNSOwnerPolicy{}, denied })
		if !errors.Is(err, denied) || p.Config.Source != 0 || len(c.entries) != 0 {
			t.Fatal("revocation/error was replaced by old successful material", p, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.current(cancelled, view, name, resolve); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read was answered", err)
	}
	if _, err := c.current(ctx, view, name, resolve); err != nil {
		t.Fatal(err)
	}
	if _, err := c.current(cancelled, view, name, resolve); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled cache hit was answered", err)
	}
	view.index++
	during, stop := context.WithCancel(ctx)
	if _, err := c.current(during, view, name, func() (services.DNSOwnerPolicy, error) {
		stop()
		return resolve()
	}); !errors.Is(err, context.Canceled) || len(c.entries) != 0 {
		t.Fatal("cancelled resolver result was published", err)
	}
}

func TestDNSPolicyCacheOwnedSlicesAndBoundedEntries(t *testing.T) {
	var c dnsPolicyCache
	ctx := context.Background()
	view, name := dnsPolicyView{index: 1}, dnsPolicyName{"tenant", "dns"}
	original := services.DNSOwnerPolicy{Config: services.DNSConfig{
		Members: []string{"node"}, Names: []services.DNSName{{Name: "service"}}, Leases: []services.DNSLeaseName{{Name: "client"}},
		Upstreams: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53")},
	}, ProtectedZones: []string{"tenant.test"}}
	calls := 0
	resolve := func() (services.DNSOwnerPolicy, error) { calls++; return original, nil }
	p, err := c.current(ctx, view, name, resolve)
	if err != nil {
		t.Fatal(err)
	}
	p.Config.Members[0], p.Config.Names[0].Name, p.Config.Leases[0].Name, p.ProtectedZones[0] = "bad", "bad", "bad", "bad"
	p.Config.Upstreams[0] = netip.MustParseAddrPort("192.0.2.2:53")
	q, err := c.current(ctx, view, name, resolve)
	if err != nil || calls != 1 || q.Config.Members[0] != "node" || q.Config.Names[0].Name != "service" || q.Config.Leases[0].Name != "client" || q.ProtectedZones[0] != "tenant.test" || q.Config.Upstreams[0] != netip.MustParseAddrPort("192.0.2.1:53") || original.Config.Members[0] != "node" {
		t.Fatal("a caller mutated cached or resolver-owned policy", q, err)
	}
	original.Config.Members[0] = "resolver-mutated"
	if q, err := c.current(ctx, view, name, resolve); err != nil || q.Config.Members[0] != "node" {
		t.Fatal("resolver-owned slice changed a published policy", q, err)
	}
	for i := range maxDNSPolicyCacheEntries + 2 {
		if _, err := c.current(ctx, view, dnsPolicyName{"tenant", fmt.Sprint(i)}, resolve); err != nil {
			t.Fatal("cache bound rejected a valid uncached query", err)
		}
	}
	if len(c.entries) != maxDNSPolicyCacheEntries {
		t.Fatal("unbounded policy retention", len(c.entries))
	}
}

func TestDNSPolicyCacheCoalescesConcurrentCurrentReads(t *testing.T) {
	var c dnsPolicyCache
	var calls atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			p, err := c.current(context.Background(), dnsPolicyView{index: 1}, dnsPolicyName{"tenant", "dns"}, func() (services.DNSOwnerPolicy, error) {
				calls.Add(1)
				return services.DNSOwnerPolicy{Config: services.DNSConfig{Source: 7}}, nil
			})
			if err != nil || p.Config.Source != 7 {
				t.Error("concurrent policy read", p, err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent queries repeated the same full validation", calls.Load())
	}
}

func TestDNSPolicyCacheOlderViewCannotReplaceCurrent(t *testing.T) {
	var c dnsPolicyCache
	ctx := context.Background()
	current := dnsPolicyView{engine: &cluster.Engine{}, index: 10, raftIndex: 20}
	name := dnsPolicyName{"tenant", "dns"}
	resolve := func(source uint64) func() (services.DNSOwnerPolicy, error) {
		return func() (services.DNSOwnerPolicy, error) {
			return services.DNSOwnerPolicy{Config: services.DNSConfig{Source: source}}, nil
		}
	}
	if _, err := c.current(ctx, current, name, resolve(7)); err != nil {
		t.Fatal(err)
	}
	old := current
	old.index, old.raftIndex = 9, 19
	if p, err := c.current(ctx, old, name, resolve(6)); err != nil || p.Config.Source != 6 || c.view != current {
		t.Fatal("old builder borrowed or replaced newer material", p, err)
	}
	if p, err := c.current(ctx, current, name, resolve(99)); err != nil || p.Config.Source != 7 {
		t.Fatal("newer view was evicted by an old read", p, err)
	}
}

// Observe the first successful Err check before canceling. This makes the
// old mutex-held resolver's failure deterministic rather than canceling before
// the waiter enters current at all.
type dnsWaitContext struct {
	context.Context
	checked chan struct{}
	once    sync.Once
}

func (c *dnsWaitContext) Err() error {
	err := c.Context.Err()
	c.once.Do(func() { close(c.checked) })
	return err
}

func TestDNSPolicyCacheWaiterCancellationDoesNotWaitForResolver(t *testing.T) {
	var c dnsPolicyCache
	view, name := dnsPolicyView{index: 1, raftIndex: 10}, dnsPolicyName{"tenant", "dns"}
	started, release := make(chan struct{}), make(chan struct{})
	var finish sync.Once
	var wg sync.WaitGroup
	t.Cleanup(func() { finish.Do(func() { close(release) }); wg.Wait() })
	wg.Go(func() {
		_, err := c.current(context.Background(), view, name, func() (services.DNSOwnerPolicy, error) {
			close(started)
			<-release
			return services.DNSOwnerPolicy{Config: services.DNSConfig{Source: 1}}, nil
		})
		if err != nil {
			t.Error(err)
		}
	})
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := &dnsWaitContext{Context: ctx, checked: make(chan struct{})}
	done := make(chan error, 1)
	wg.Go(func() {
		_, err := c.current(observed, view, name, func() (services.DNSOwnerPolicy, error) {
			t.Error("matching waiter duplicated the active resolver")
			return services.DNSOwnerPolicy{}, nil
		})
		done <- err
	})
	<-observed.checked
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("waiter cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled query waited for the unrelated active resolver")
	}
	finish.Do(func() { close(release) })
	wg.Wait()
	if len(c.working) != 0 {
		t.Fatal("completed work retained")
	}
}

func TestDNSPolicyCacheSlowOldResolutionDoesNotBlockNewViewOrName(t *testing.T) {
	var c dnsPolicyCache
	old := dnsPolicyView{engine: &cluster.Engine{}, index: 1, raftIndex: 10}
	current := old
	current.index, current.raftIndex = 2, 11
	name := dnsPolicyName{"tenant", "dns"}
	started, release := make(chan struct{}), make(chan struct{})
	var finish sync.Once
	var wg sync.WaitGroup
	t.Cleanup(func() { finish.Do(func() { close(release) }); wg.Wait() })
	wg.Go(func() {
		p, err := c.current(context.Background(), old, name, func() (services.DNSOwnerPolicy, error) {
			close(started)
			<-release
			return services.DNSOwnerPolicy{Config: services.DNSConfig{Source: 1}}, nil
		})
		if err != nil || p.Config.Source != 1 {
			t.Error("original snapshot result", p, err)
		}
	})
	<-started
	done := make(chan error, 1)
	wg.Go(func() {
		for _, selected := range []dnsPolicyName{name, {"tenant", "other"}} {
			p, err := c.current(context.Background(), current, selected, func() (services.DNSOwnerPolicy, error) {
				return services.DNSOwnerPolicy{Config: services.DNSConfig{Source: 2}}, nil
			})
			if err != nil || p.Config.Source != 2 {
				done <- fmt.Errorf("current snapshot/name: %v", err)
				return
			}
		}
		done <- nil
	})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("new view/name waited for older snapshot interpretation")
	}
	finish.Do(func() { close(release) })
	wg.Wait()
	p, err := c.current(context.Background(), current, name, func() (services.DNSOwnerPolicy, error) {
		t.Error("late older resolver evicted current view")
		return services.DNSOwnerPolicy{}, nil
	})
	if err != nil || p.Config.Source != 2 || c.view != current || len(c.working) != 0 {
		t.Fatal("late old completion corrupted current cache", p, err)
	}
}
