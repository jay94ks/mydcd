// SPDX-License-Identifier: Apache-2.0

package volumes

import "github.com/jay94ks/seafield/internal/cluster/lifecycle"

// Activity preserves ambiguous starts and original unreturned bindings. Native
// Volume bytes with no active consumer are retained data, not a live writer.
func (s *Activations) Activity() (lifecycle.Activity, error) { return s.TenantActivity("") }

func (s *Activations) TenantActivity(tenant string) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return activity, ErrActivation
	}
	s.mu.Lock()
	entries := make([]*activationEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	s.mu.Unlock()
	for _, entry := range entries {
		if tenant != "" && entry.scope.Tenant != tenant {
			continue
		}
		if !entry.mu.TryLock() {
			activity.Writers++
			continue
		}
		if entry.disk.Gate.Starting != nil {
			activity.Writers++
		}
		for _, binding := range entry.disk.Bindings {
			if binding.Closed && binding.Released {
				continue
			}
			if binding.Ref.Consumer.Writable {
				activity.Writers++
			} else {
				activity.Leases++
			}
		}
		entry.mu.Unlock()
	}
	return activity, nil
}
