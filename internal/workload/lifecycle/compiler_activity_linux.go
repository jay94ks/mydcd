// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	node "github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"strings"
)

// Activity does not wait behind a compiler's SDK Wait. A busy native owner is
// positively outstanding work; uncertainty is never translated into zero.
func (m *CompilerOwner) Activity() (node.Activity, error) { return m.TenantActivity("") }

func (m *CompilerOwner) TenantActivity(tenant string) (node.Activity, error) {
	var activity node.Activity
	m.life.RLock()
	defer m.life.RUnlock()
	if !m.mu.TryLock() {
		activity.CDJobs = 1
		return activity, nil
	}
	defer m.mu.Unlock()
	if m.closed || m.uncertain {
		return activity, ErrCompilerOwner
	}
	for key, pending := range m.known {
		if tenant != "" && !strings.HasPrefix(key, compilerRecordPrefix+tenant+"/") {
			continue
		}
		if pending {
			activity.CDJobs++
		}
	}
	m.interruptMu.Lock()
	for key := range m.active {
		if tenant == "" || strings.HasPrefix(key, tenant+"/") {
			activity.CDJobs++
		}
	}
	m.interruptMu.Unlock()
	return activity, nil
}
