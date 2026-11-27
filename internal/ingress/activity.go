// SPDX-License-Identifier: Apache-2.0

package ingress

import "github.com/jay94ks/seafield/internal/cluster/lifecycle"

func (m *Manager) Activity() (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	if !m.mu.TryLock() {
		activity.Resources = 1
		return activity, nil
	}
	defer m.mu.Unlock()
	if m.closed {
		return activity, ErrRoute
	}
	for _, instance := range m.instances {
		instance.mu.Lock()
		if !instance.record.Gone || instance.started {
			activity.Resources++
		}
		activity.Flows += uint32(instance.requests())
		instance.mu.Unlock()
	}
	return activity, nil
}
