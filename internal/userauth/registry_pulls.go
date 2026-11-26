// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (s Service) registryPulls(ctx context.Context, view cluster.View, q Request, session access.Session) Reply {
	if s.NodeObservations == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	reports, err := s.NodeObservations(ctx, view)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	// Reports can involve a node read. Recheck the original session/current
	// tenant authorization after it; observations never carry that authority.
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	page, err := s.Policy.RegistryPulls(latest.State, session, time.Now().Unix(), q.Tenant, q.After, reports)
	if err != nil {
		code := "unavailable"
		if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
			code = "denied"
		}
		if errors.Is(err, access.ErrConflict) {
			code = "conflict"
		}
		return Reply{Schema: 1, Code: code}
	}
	return Reply{Schema: 1, Code: "ok", Tenant: q.Tenant, RegistryPulls: &page}
}

func (c Client) RegistryPulls(ctx context.Context, peer mydcp.Peer, session access.Session, tenant, after string) (control.RegistryPullPage, error) {
	if tenant == "" || len(after) > 512 {
		return control.RegistryPullPage{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "external-registry-pulls", Tenant: tenant, After: after})
	if err != nil {
		return control.RegistryPullPage{}, err
	}
	page := reply.RegistryPulls

	if page == nil || reply.Tenant != tenant || !page.Valid(tenant, after) {
		return control.RegistryPullPage{}, mydcp.ErrFrame
	}
	return *page, nil
}
