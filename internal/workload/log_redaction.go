// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// logRedactionValues uses the same original native consumer pin as Status;
// logging never acquires a new Secret grant or reads an arbitrary host path.
func (m *Manager) logRedactionValues(ctx context.Context, target containerops.Target) ([]containerops.RedactionValue, error) {
	r, err := m.journal.Read(target.Instance)
	if err != nil {
		return nil, err
	}
	spec, err := probeTaskRecord(r, target.Generation, target.Revision)
	if err != nil {
		return nil, err
	}
	_, id, err := m.driver.parameters(target.Instance, reconcile.Operation{ID: 1, Kind: reconcile.Apply, Target: r.State.Applied})
	if err != nil {
		return nil, err
	}
	lease, err := m.driver.inputLease(ctx, spec, id, target.Instance, target.Generation, "inspect")
	if err != nil {
		return nil, err
	}
	var values []containerops.RedactionValue
	total := 0
	for _, file := range lease.Files {
		value, readErr := readInputValue(ctx, file, containerops.MaxRedactionBytes-total)
		if readErr != nil {
			destroyLogValues(values)
			return nil, containerops.ErrRedaction
		}
		total += len(value)
		values = append(values, containerops.RedactionValue{Reference: file.Reference, Value: value})
	}
	return values, nil
}

func destroyLogValues(values []containerops.RedactionValue) {
	for _, value := range values {
		clear(value.Value)
	}
}
