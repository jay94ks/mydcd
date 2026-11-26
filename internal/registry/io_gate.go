// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"sync"
)

// This gate belongs to a single retained Store. HTTP requests borrow a read
// lease; explicit metadata deletion/GC joins them before changing the graph.
// Waiting for a large blob/push is cancellable, without a parked lock goroutine.
type registryIOGate struct {
	mu              sync.Mutex
	active, waiting int
	exclusive       bool
	changed         chan struct{}
}

func (g *registryIOGate) notify() {
	if g.changed != nil {
		close(g.changed)
	}
	g.changed = make(chan struct{})
}
func (g *registryIOGate) acquire(ctx context.Context, write bool) (func(), error) {
	if ctx == nil {
		return nil, ErrStorage
	}
	g.mu.Lock()
	if g.changed == nil {
		g.changed = make(chan struct{})
	}
	if write {
		g.waiting++
		g.notify()
	}
	for g.exclusive || write && g.active > 0 || !write && g.waiting > 0 {
		next := g.changed
		g.mu.Unlock()
		select {
		case <-next:
		case <-ctx.Done():
		}
		g.mu.Lock()
		if ctx.Err() != nil {
			if write {
				g.waiting--
				g.notify()
			}
			g.mu.Unlock()
			return nil, ctx.Err()
		}
	}
	if ctx.Err() != nil {
		if write {
			g.waiting--
			g.notify()
		}
		g.mu.Unlock()
		return nil, ctx.Err()
	}
	if write {
		g.waiting--
		g.exclusive = true
	} else {
		g.active++
	}
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			if write {
				g.exclusive = false
			} else {
				g.active--
			}
			g.notify()
			g.mu.Unlock()
		})
	}, nil
}
