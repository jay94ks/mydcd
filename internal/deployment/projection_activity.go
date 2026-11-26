// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"strings"
)

func (m *ProjectionStore) Activity() (lifecycle.Activity, error) { return m.TenantActivity("") }

func (m *ProjectionStore) TenantActivity(tenant string) (lifecycle.Activity, error) {
	var activity lifecycle.Activity
	if !m.mu.TryLock() {
		activity.Leases = 1
		return activity, nil
	}
	defer m.mu.Unlock()
	if m.closed {
		return activity, ErrProjectionStore
	}
	for _, key := range m.journal.Keys() {
		if tenant != "" && !strings.HasPrefix(key, "workload/inputs/"+tenant+"/") {
			continue
		}
		record, err := m.journal.Read(key)
		if err != nil {
			return activity, err
		}
		if record.State.Pending != nil {
			activity.Resources++
		}
		activity.Leases += uint32(len(record.Consumers))
	}
	return activity, nil
}
