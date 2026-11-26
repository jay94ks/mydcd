// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"slices"
	"sync"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/network/services"
)

const maxDNSPolicyCacheEntries = 16

// This key names the exact committed view read for a Current callback. It is
// neither a TTL nor an authority token. Even a hit requires a new Engine read.
type dnsPolicyView struct {
	engine                        *cluster.Engine
	cluster, owner                [32]byte
	index, epoch, raftIndex, term uint64
	local                         bool
}

type dnsPolicyName struct{ tenant, id string }

type dnsPolicyWorkKey struct {
	view dnsPolicyView
	name dnsPolicyName
}

type dnsPolicyWork struct {
	done   chan struct{}
	policy services.DNSOwnerPolicy
	err    error
}

type dnsPolicyCache struct {
	mu      sync.Mutex
	view    dnsPolicyView
	entries map[dnsPolicyName]services.DNSOwnerPolicy
	working map[dnsPolicyWorkKey]*dnsPolicyWork
}

func (c *dnsPolicyCache) current(ctx context.Context, view dnsPolicyView, name dnsPolicyName, resolve func() (services.DNSOwnerPolicy, error)) (services.DNSOwnerPolicy, error) {
	if err := ctx.Err(); err != nil {
		return services.DNSOwnerPolicy{}, err
	}
	c.mu.Lock()
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return services.DNSOwnerPolicy{}, err
	}
	// A caller may have read an older view before waiting on this mutex.
	// Resolve its exact snapshot without evicting a newer committed cache.
	cacheable := c.view.engine != view.engine || c.view.cluster != view.cluster || c.view.owner != view.owner || view.raftIndex >= c.view.raftIndex
	if cacheable && c.view != view {
		c.view, c.entries = view, nil
	}
	if cacheable {
		if p, ok := c.entries[name]; ok {
			c.mu.Unlock()
			return ownDNSPolicy(p), nil
		}
	}
	key := dnsPolicyWorkKey{view, name}
	if work := c.working[key]; work != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return services.DNSOwnerPolicy{}, ctx.Err()
		case <-work.done:
		}
		if err := ctx.Err(); err != nil {
			return services.DNSOwnerPolicy{}, err
		}
		if work.err != nil {
			return services.DNSOwnerPolicy{}, work.err
		}
		return ownDNSPolicy(work.policy), nil
	}
	var work *dnsPolicyWork
	if len(c.working) < maxDNSPolicyCacheEntries {
		work = &dnsPolicyWork{done: make(chan struct{})}
		if c.working == nil {
			c.working = make(map[dnsPolicyWorkKey]*dnsPolicyWork)
		}
		c.working[key] = work
	}
	c.mu.Unlock()
	// Resolve only this immutable snapshot, outside the cache mutex. A slow
	// older view/name cannot block a fresh query or its context cancellation.
	// The bounded work table coalesces matching reads without a new goroutine;
	// overflow retains the existing uncached interpretation behavior.
	p, err := resolve()
	if err == nil {
		p = ownDNSPolicy(p)
	}
	contextErr := ctx.Err()
	c.mu.Lock()
	if work != nil {
		work.policy, work.err = p, err
		delete(c.working, key)
		close(work.done)
	}
	// Selection may have advanced while resolving; never republish an older
	// snapshot. A canceled owner does not publish a cache entry, but matching
	// waiters still consume their own snapshot and context, not its cancellation.
	if err == nil && contextErr == nil && cacheable && c.view == view && len(c.entries) < maxDNSPolicyCacheEntries {
		if c.entries == nil {
			c.entries = make(map[dnsPolicyName]services.DNSOwnerPolicy)
		}
		c.entries[name] = p
	}
	c.mu.Unlock()
	if err != nil {
		return services.DNSOwnerPolicy{}, err
	}
	if contextErr != nil {
		return services.DNSOwnerPolicy{}, contextErr
	}
	return ownDNSPolicy(p), nil
}

func ownDNSPolicy(p services.DNSOwnerPolicy) services.DNSOwnerPolicy {
	p.Unavailable = slices.Clone(p.Unavailable)
	// Catalog, Networks and Authority expose immutable transitions. The
	// configuration's exported slices, however, belong to each caller.
	p.Config.Members = slices.Clone(p.Config.Members)
	p.Config.Names = slices.Clone(p.Config.Names)
	p.Config.Leases = slices.Clone(p.Config.Leases)
	p.Config.Upstreams = slices.Clone(p.Config.Upstreams)
	p.ProtectedZones = slices.Clone(p.ProtectedZones)
	return p
}
