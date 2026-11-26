// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"

	"github.com/jay94ks/mydcd/internal/cluster"
)

// currentView keeps native I/O on its exact installed owner while joining the
// authenticated quorum barrier to that owner's durable local policy prefix.
func (r *Runtime) currentView(ctx context.Context) (cluster.View, error) {
	return cluster.CurrentView(ctx, r.Engine(), r.Mesh, r.Identity, r.controlPolicy.Cluster)
}
