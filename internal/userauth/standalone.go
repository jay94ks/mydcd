// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"reflect"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (c Client) StandalonePage(ctx context.Context, peer sfcp.Peer, session access.Session, tenant, name, after string) (Reply, error) {
	method := "standalone-list"
	if name != "" {
		method = "standalone-get"
	}
	return c.query(ctx, peer, session, Request{Method: method, Tenant: tenant, After: after, Standalone: &control.StandaloneQuery{Name: name}})
}

// StandalonePlan names the typed finite-query alias of the same app compiler.
// Larger inputs use StreamAppPlan with the identical explicit owner field.
func (c Client) StandalonePlan(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q control.AppPlanRequest) (Reply, error) {
	if q.Standalone == nil {
		return Reply{}, sfcp.ErrAdmission
	}
	return c.query(ctx, peer, session, Request{Method: "standalone-plan", Tenant: tenant, AppPlan: &q})
}

// Shared by the transport admission and direct execute selectors. These
// exact shapes also exclude the other features' optional request fields.
func (r Request) validStandaloneFileFields() bool {
	if r.Method == "standalone-list" || r.Method == "standalone-get" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, After: r.After, Standalone: r.Standalone}
		return lifecycle.ValidID(r.Tenant) && r.Standalone != nil && (r.Method == "standalone-list" && r.Standalone.Name == "" || r.Method == "standalone-get" && lifecycle.ValidID(r.Standalone.Name)) && (r.After == "" || lifecycle.ValidID(r.After)) && reflect.DeepEqual(r, want)
	}
	if r.Standalone != nil {
		return false
	}
	return true
}
