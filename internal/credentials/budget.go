// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type attemptRate struct {
	limit *rate.Limiter
	last  time.Time
}

// Budget is node-local admission for expensive authentication, never shared
// account state. Times come from the edge; it never runs inside the FSM.
type Budget struct {
	mu             sync.Mutex
	global         *rate.Limiter
	users, sources map[string]attemptRate
	last           time.Time
	active         chan struct{}
}

func NewBudget() *Budget {
	return &Budget{global: rate.NewLimiter(20, 20), users: map[string]attemptRate{}, sources: map[string]attemptRate{}, active: make(chan struct{}, 1)}
}

func (b *Budget) Begin(ctx context.Context, username, source string, now time.Time) (func(), error) {
	if b == nil || ctx.Err() != nil || username == "" || len(username) > 63 || source == "" || len(source) > 256 || now.IsZero() {
		return nil, ErrDenied
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Before(b.last) {
		return nil, ErrDenied
	}
	b.last = now
	if b.global.TokensAt(now) < 1 {
		return nil, ErrDenied
	}
	for _, table := range []map[string]attemptRate{b.users, b.sources} {
		if len(table) >= 1024 {
			for key, value := range table {
				if now.Sub(value.last) >= 5*time.Minute {
					delete(table, key)
				}
			}
		}
	}
	var admitted [2]*rate.Limiter
	for i, key := range []string{username, source} {
		table, limit, burst := b.users, rate.Every(12*time.Second), 5
		if i == 1 {
			table, limit, burst = b.sources, rate.Every(2*time.Second), 10
		}
		entry, known := table[key]
		if !known {
			if len(table) >= 1024 {
				return nil, ErrDenied
			}
			entry = attemptRate{limit: rate.NewLimiter(limit, burst)}
		}
		entry.last = now
		table[key] = entry
		admitted[i] = entry.limit
		if entry.limit.TokensAt(now) < 1 {
			return nil, ErrDenied
		}
	}
	select {
	case b.active <- struct{}{}:
	default:
		return nil, ErrDenied
	}
	// All counters and the verifier slot passed preflight under this mutex.
	// A rejected username/source/concurrency admission consumes none of the
	// shared buckets and cannot starve another account with repeated retries.
	b.global.AllowN(now, 1)
	for _, limit := range admitted {
		limit.AllowN(now, 1)
	}
	var once sync.Once
	return func() { once.Do(func() { <-b.active }) }, nil
}
