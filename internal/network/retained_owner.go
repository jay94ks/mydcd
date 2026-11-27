// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"github.com/jay94ks/seafield/internal/engine"
	"sync"
)

// AttachRetained is local startup wiring for installed identity history. The
// original manager keeps its native journal and exact consumer generations.
func (m *Manager) AttachRetained(other *Manager) error {
	if m == nil || other == nil || m == other || m.driver.Engine == nil || other.driver.Engine == nil || m.driver.Engine.Owner == other.driver.Engine.Owner || m.driver.Engine.API.DaemonHost() != other.driver.Engine.API.DaemonHost() {
		return engine.ErrOwnership
	}
	m.admitMu.Lock()
	defer m.admitMu.Unlock()
	if m.retained == nil {
		m.retained = map[string]*Manager{}
	}
	if prior := m.retained[other.driver.Engine.Owner]; prior != nil && prior != other {
		return engine.ErrOwnership
	}
	m.retained[other.driver.Engine.Owner] = other
	if m.consumerGroup == nil {
		m.consumerGroup = &consumerOwnerGroup{managers: []*Manager{m}}
	}
	if other.consumerGroup != nil && other.consumerGroup != m.consumerGroup {
		return engine.ErrOwnership
	}
	other.consumerGroup = m.consumerGroup
	for _, prior := range m.consumerGroup.managers {
		if prior == other {
			return nil
		}
	}
	m.consumerGroup.managers = append(m.consumerGroup.managers, other)
	return nil
}
func (m *Manager) Retained(owner string) *Manager {
	if m == nil {
		return nil
	}
	if m.driver.Engine != nil && m.driver.Engine.Owner == owner {
		return m
	}
	m.admitMu.Lock()
	defer m.admitMu.Unlock()
	return m.retained[owner]
}

type consumerOwnerGroup struct {
	mu       sync.Mutex
	managers []*Manager
}

func (m *Manager) lockConsumerAdmission() func() {
	if m.consumerGroup != nil {
		m.consumerGroup.mu.Lock()
		return m.consumerGroup.mu.Unlock
	}
	m.admitMu.Lock()
	return m.admitMu.Unlock
}

// Quota census joins retained owner namespaces in memory only. Original scopes
// and pins stay in their original DB; the installed runtime fixes this group.
func (m *Manager) consumerCensus(ctx context.Context) ([]consumerCount, error) {
	if m.consumerGroup == nil {
		return m.localConsumerCensus(ctx)
	}
	var result []consumerCount
	for _, owner := range m.consumerGroup.managers {
		rows, err := owner.localConsumerCensus(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if row.scope.Owner != owner.driver.Engine.Owner {
				return nil, ErrPolicy
			}
			row.scope.Owner = m.driver.Engine.Owner
			result = append(result, row)
		}
	}
	return result, nil
}
