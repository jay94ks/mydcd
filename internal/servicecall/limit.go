// SPDX-License-Identifier: Apache-2.0

package servicecall

import "sync"

// Limiter is node-local admission, outside the deterministic FSM. The stable
// account/tenant key survives session renewal; no per-call journal is created.
type Limiter struct {
	mu                                     sync.Mutex
	Concurrent, PerMinute, ScopedPerMinute int
	window                                 int64
	initialized                            bool
	active, total                          int
	scopes                                 map[string]limitScope
	Accepted, Rejected                     uint64
}
type limitScope struct{ active, total int }

func (l *Limiter) Acquire(key string, now int64) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Concurrent < 1 || l.PerMinute < 1 || l.ScopedPerMinute < 1 || key == "" || now < 0 {
		return nil, false
	}
	if l.scopes == nil {
		l.scopes = map[string]limitScope{}
	}
	if minute := now / 60; minute > l.window || !l.initialized {
		l.window = minute
		l.initialized = true
		l.total = 0
		for key, v := range l.scopes {
			if v.active == 0 {
				delete(l.scopes, key)
			} else {
				v.total = 0
				l.scopes[key] = v
			}
		}
	}
	scope, exists := l.scopes[key]
	if l.active >= l.Concurrent || scope.active >= l.Concurrent || l.total >= l.PerMinute || scope.total >= l.ScopedPerMinute || !exists && len(l.scopes) >= 4096 {
		l.Rejected++
		return nil, false
	}
	l.active++
	l.total++
	scope.active++
	scope.total++
	l.scopes[key] = scope
	l.Accepted++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.active--
			scope := l.scopes[key]
			scope.active--
			l.scopes[key] = scope
		})
	}, true
}
