// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// IngressesMethod reads ingress mappings, blocks, node summaries and a
// server's gateways. The observer asks each owner server; the reply is kept
// only when the leader's current page still selects the same rows.
var IngressesMethod = define(Method[control.IngressQuery, control.IngressPage]{Name: "ingresses"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q control.IngressQuery) (control.IngressPage, string) {
	if s.IngressObserver == nil {
		return control.IngressPage{}, "unavailable"
	}
	page, err := s.IngressObserver(ctx, control.IngressRead{Session: session, Query: q, At: time.Now().Unix(), Index: view.State.Index()})
	if err != nil {
		if errors.Is(err, access.ErrDenied) || errors.Is(err, sfcp.ErrAdmission) {
			return control.IngressPage{}, "denied"
		}
		return control.IngressPage{}, "unavailable"
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return control.IngressPage{}, "unavailable"
	}
	current, err := s.Policy.IngressPage(latest.State, session, time.Now().Unix(), q)
	if err != nil || !page.SameSelection(current) {
		return control.IngressPage{}, "denied"
	}
	return page, "ok"
})

func (c Client) Ingresses(ctx context.Context, peer sfcp.Peer, session access.Session, q control.IngressQuery) (control.IngressPage, error) {
	if !q.Valid() {
		return control.IngressPage{}, sfcp.ErrAdmission
	}
	page, err := call(ctx, c, peer, session, IngressesMethod, q)
	if err != nil {
		return control.IngressPage{}, err
	}
	if page.Schema != 1 || page.Index == 0 || len(page.Mappings) > 1 {
		return control.IngressPage{}, sfcp.ErrFrame
	}
	for _, row := range page.Mappings {
		if row.Key == "" || row.Generation == 0 || q.Node != "" && row.Node != q.Node || q.Tenant != "" && row.Tenant != q.Tenant || q.App != "" && row.App != q.App || q.Key != "" && row.Key != q.Key {
			return control.IngressPage{}, sfcp.ErrFrame
		}
	}
	return page, nil
}
