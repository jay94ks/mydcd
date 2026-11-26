// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	node "github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"strings"
)

// SourceActivity counts actual borrowed IO, not immutable retained bytes.
func (m *SourceStore) Activity() (node.Activity, error) { return m.TenantActivity("") }

func (m *SourceStore) TenantActivity(tenant string) (node.Activity, error) {
	var activity node.Activity
	if !m.mu.TryLock() {
		activity.CDJobs = 1
		return activity, nil
	}
	defer m.mu.Unlock()
	if m.closed || m.uncertain {
		return activity, ErrSourceUncertain
	}
	for key, count := range m.busy {
		if tenant != "" && !strings.HasPrefix(key, tenant+"/") {
			continue
		}
		if count > 0 {
			activity.CDJobs += uint32(count)
		}
	}
	return activity, nil
}
