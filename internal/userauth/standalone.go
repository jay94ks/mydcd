// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"reflect"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (c Client) StandalonePage(ctx context.Context, peer mydcp.Peer, session access.Session, tenant, name, after string) (Reply, error) {
	method := "standalone-list"
	if name != "" {
		method = "standalone-get"
	}
	return c.query(ctx, peer, session, Request{Method: method, Tenant: tenant, After: after, Standalone: &control.StandaloneQuery{Name: name}})
}
func (c Client) VolumeFilePlan(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.VolumeFileQuery) (control.VolumeFilePlan, error) {
	r, err := c.query(ctx, peer, session, Request{Method: "volume-file-plan", Tenant: tenant, VolumeFile: &q})
	if err != nil {
		return control.VolumeFilePlan{}, err
	}
	if r.VolumeFilePlan == nil || r.VolumeFilePlan.Change.Scope.Cluster != c.Cluster || r.VolumeFilePlan.Change.Scope.Tenant != tenant || r.VolumeFilePlan.Change.Scope.App != q.App || r.VolumeFilePlan.Change.Scope.ID != q.Volume || r.VolumeFilePlan.Change.Path != q.Path || r.VolumeFilePlan.Revision == 0 || !r.VolumeFilePlan.Change.Valid(q.Method) {
		return control.VolumeFilePlan{}, mydcp.ErrAdmission
	}
	return *r.VolumeFilePlan, nil
}
func (c Client) VolumeFileStatus(ctx context.Context, peer mydcp.Peer, session access.Session, tenant, id string) (control.VolumeFileView, error) {
	r, err := c.query(ctx, peer, session, Request{Method: "volume-file-status", Tenant: tenant, VolumeFile: &control.VolumeFileQuery{ID: id}})
	if err != nil {
		return control.VolumeFileView{}, err
	}
	if r.VolumeFileStatus == nil || r.VolumeFileStatus.ID != id || r.VolumeFileStatus.Request.Scope.Cluster != c.Cluster || r.VolumeFileStatus.Request.Scope.Tenant != tenant {
		return control.VolumeFileView{}, mydcp.ErrAdmission
	}
	return *r.VolumeFileStatus, nil
}

// StandalonePlan names the typed finite-query alias of the same app compiler.
// Larger inputs use StreamAppPlan with the identical explicit owner field.
func (c Client) StandalonePlan(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.AppPlanRequest) (Reply, error) {
	if q.Standalone == nil {
		return Reply{}, mydcp.ErrAdmission
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
	if r.Method == "volume-file-plan" || r.Method == "volume-file-status" {
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, VolumeFile: r.VolumeFile}
		return lifecycle.ValidID(r.Tenant) && r.VolumeFile != nil && r.VolumeFile.Valid(r.Method == "volume-file-status") && reflect.DeepEqual(r, want)
	}
	return r.VolumeFile == nil
}
