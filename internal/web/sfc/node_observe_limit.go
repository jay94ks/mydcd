// SPDX-License-Identifier: Apache-2.0

package sfc

// DefaultObserveLimitSeconds is the fake's REQ-53 observe limit: a server
// whose summary is older than this is unreachable (fixture node-d, 600 s).
// The real value is sfcd's.
const DefaultObserveLimitSeconds = 120

// SetObserveLimit sets FixtureNodeSummary.ObserveLimitSeconds (0 = default).
// The fake does not recompute Status from it; use SetNodeStatus.
func (f *Fake) SetObserveLimit(seconds int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if seconds <= 0 {
		seconds = DefaultObserveLimitSeconds
	}
	f.w.observeLimit = seconds
}
