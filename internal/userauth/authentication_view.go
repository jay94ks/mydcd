// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"

	"github.com/jay94ks/seafield/internal/cluster"
)

// Keep credentials on their pinned issuer while consuming the same quorum
// prefix as native owner reads. Current issuer/user checks remain at the caller.
func (s Service) authenticationView(ctx context.Context) (cluster.View, error) {
	return cluster.CurrentView(ctx, s.Engine, s.Mesh, s.Self, s.Policy.Cluster)
}
