// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

type CDProbeRead struct {
	Session access.Session
	Tenant  string
	Query   deployment.GitProbeRequest
	Epoch   uint64
}

func (p Policy) CDProbePermit(s state.State, read CDProbeRead, at int64, node string) error {
	var err error
	p, err = p.Current(s)
	if err != nil {
		return err
	}
	if !validID(read.Tenant) || !read.Query.Valid() || read.Epoch != s.ModuleEpoch() {
		return access.ErrInvalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if c.AuthorizeSession(read.Session, p.Cluster, p.Issuer(read.Session.Issuer), at, read.Tenant, access.Deploy, node) != nil || c.OperationAllowed(read.Session, "cd-probe") != nil {
		return access.ErrDenied
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return err
	}
	if _, exists := a.entries[appKey(read.Tenant, read.Query.App)]; !exists {
		return access.ErrConflict
	}
	return nil
}
