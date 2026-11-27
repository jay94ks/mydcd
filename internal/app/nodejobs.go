// SPDX-License-Identifier: Apache-2.0

package app

import "sync"

// nodeJob is one kind of node-side job (raft compaction, tunnel reconnect,
// image cache prune): at most one run of a kind is in flight on this node,
// and every run is tracked by the runtime's WaitGroup so Close waits for it.
// The job's own code only decides what to run; this owns the busy flag and
// the goroutine. See devel/refactor/18-sfcd-structure.md (S4).
type nodeJob struct {
	mu   sync.Mutex
	busy bool
}

// startJob runs run(op) in the background unless a run of j is already in
// flight or the runtime is stopping. It reports whether a run started.
func (r *Runtime) startJob(j *nodeJob, op string, run func(op string)) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.busy || r.ctx.Err() != nil {
		return false
	}
	j.busy = true
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() { j.mu.Lock(); j.busy = false; j.mu.Unlock() }()
		run(op)
	}()
	return true
}
