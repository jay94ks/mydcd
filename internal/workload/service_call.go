// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/hex"
	"strings"
)

// BorrowServiceCall reuses the original native Task read lease, with its own
// consumer namespace so a new process can settle dead HTTP readers safely.
func (m *Manager) BorrowServiceCall(ctx context.Context, key string, generation, revision uint64, native, runID string, call [32]byte) (ReadProbeLease, error) {
	return m.borrowReadProbe(ctx, key, generation, revision, native, runID, call, "service-call")
}

// RecoverServiceCalls runs before the User service starts. All old process
// sockets have ended; returning their exact pins never retries the POST or
// claims that its remote effect did not happen. Other consumers stay intact.
func (m *Manager) RecoverServiceCalls(ctx context.Context) error {
	for _, key := range m.journal.Keys() {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, err := m.journal.Read(key)
		if err != nil {
			return err
		}
		for consumer, pin := range record.Consumers {
			if validServiceCallConsumer(consumer) {
				spec, cause := DecodeContainer(record.State.Applied.Spec)
				if cause != nil || !record.State.Applied.Present || spec.Node != m.driver.Engine.Owner {
					continue // This journal row belongs to another native owner.
				}
				if err := m.journal.Return(key, consumer, pin); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validServiceCallConsumer(consumer string) bool {
	parts := strings.Split(consumer, "/")
	if len(parts) != 3 || parts[0] != "service-call" {
		return false
	}
	for _, part := range parts[1:] {
		raw, err := hex.DecodeString(part)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != part || part == strings.Repeat("0", 64) {
			return false
		}
	}
	return true
}
