// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
)

// Owner reports may finish a pass before its DNS tail. A successful report is
// still progress, but cannot starve the live prerequisite required by Start.
// The callbacks below are the existing Runtime paths, not alternate effects.
func reconcileManagedPass(ctx context.Context, owners func() (dnsVisited bool, err error), dns, workloads func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dnsVisited, err := owners()
	if err != nil {
		return fmt.Errorf("app owner reconciliation: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !dnsVisited {
		if err := dns(); err != nil {
			return fmt.Errorf("app DNS prerequisite reconciliation: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return workloads()
}
