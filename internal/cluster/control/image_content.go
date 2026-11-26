// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

type ImageContentRead struct {
	Query   registryclient.ContentQuery
	Resolve ImageResolveRead
}

func (p Policy) PlanImageContent(s state.State, session access.Session, at int64, tenant string, q registryclient.ContentQuery, resolver [32]byte) (ImageContentRead, error) {
	if !q.Valid() {
		return ImageContentRead{}, access.ErrInvalid
	}
	read, err := p.PlanImageResolve(s, session, at, tenant, ImageResolveQuery{Ref: q.Ref}, resolver)
	return ImageContentRead{Query: q, Resolve: read}, err
}
func (p Policy) CurrentImageContent(s state.State, read ImageContentRead, at int64) (ImageContentRead, error) {
	current, err := p.PlanImageContent(s, read.Resolve.Session, at, read.Resolve.Tenant, read.Query, read.Resolve.Resolver)
	if err != nil || !current.Resolve.Target.Same(read.Resolve.Target) {
		return ImageContentRead{}, access.ErrDenied
	}
	return current, nil
}
