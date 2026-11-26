// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// RQ10 reads through mydcd's common PublicRead envelope
// (docs/reference/resource-queries.md): pages of at most 8 rows, each a
// Key and one payload. Key and Next are opaque: Next only goes back as the
// next After. A cursor conflict (the snapshot or the caller's permission
// changed) starts the read over once.

// publicReadPages bounds one web read (8 rows a page).
const publicReadPages = 64

// publicReadAll reads every row of one method/tenant/selector. The page
// returned is the first one (its revisions, Rules and Total).
func publicReadAll(ctx context.Context, c mydc.Conn, method, tenant string, q control.PublicReadQuery) (control.PublicReadPage, []control.PublicReadRow, error) {
	for try := 0; ; try++ {
		first, rows, err := publicReadOnce(ctx, c, method, tenant, q)
		if err != nil && try == 0 && isMydcCode(err, mydc.CodeConflict) {
			continue
		}
		return first, rows, err
	}
}

func publicReadOnce(ctx context.Context, c mydc.Conn, method, tenant string, q control.PublicReadQuery) (control.PublicReadPage, []control.PublicReadRow, error) {
	var first control.PublicReadPage
	var rows []control.PublicReadRow
	after := ""
	for i := range publicReadPages {
		p, err := c.PublicRead(ctx, method, tenant, q, after)
		if err != nil {
			return first, nil, err
		}
		if i == 0 {
			first = p
		}
		rows = append(rows, p.Rows...)
		if p.Next == "" || p.Next == after {
			return first, rows, nil
		}
		after = p.Next
	}
	return first, rows, &httpErr{http.StatusBadGateway, "public-read-too-long", "the list is longer than the web reads at once"}
}

// resourceUsers folds network-users / volume-users rows into the web's
// users view: one entry per app service (or standalone container, or
// volume operation) and server, with a selection per present container.
// network: attached = mydcd saw the endpoint; volume: the container is
// there (Writable from the consumer).
func resourceUsers(rows []control.PublicReadRow, network bool) ([]resourceUser, int, int) {
	out := []resourceUser{}
	at := map[[5]string]int{}
	apps, standalones := map[string]bool{}, map[string]bool{}
	for _, r := range rows {
		u := r.User
		if u == nil {
			continue
		}
		kind := u.Kind
		switch kind {
		case "app", "app-service", "": // mydcd TaskView kind "app"
			kind = mydc.NetworkUserService
			apps[u.App] = true
		case "standalone":
			kind = mydc.NetworkUserStandalone
			standalones[u.Standalone] = true
		}
		k := [5]string{kind, u.App, u.Service, u.Standalone, u.Node}
		if kind == "volume-operation" {
			k[2] = u.Consumer
		}
		i, ok := at[k]
		if !ok {
			i = len(out)
			at[k] = i
			out = append(out, resourceUser{Kind: kind, App: u.App, Service: u.Service, Standalone: u.Standalone, Node: u.Node, Consumer: u.Consumer})
		}
		e := &out[i]
		if u.Writable != nil && !*u.Writable {
			e.ReadOnly = true
		}
		present := u.ContainerPresent != nil && *u.ContainerPresent
		if network {
			present = u.EndpointPresent != nil && *u.EndpointPresent
		}
		if !present || kind == "volume-operation" {
			continue
		}
		e.Attached = true
		if kind == mydc.NetworkUserStandalone {
			e.Selection = append(e.Selection, mydc.ContainerSelection{Standalone: u.Standalone})
		} else {
			e.Selection = append(e.Selection, mydc.ContainerSelection{App: u.App, Service: u.Service})
		}
	}
	return out, len(apps), len(standalones)
}

// resourceUser: one entry of GET …/networks|volumes/{name}/users. Kind
// service / standalone / volume-operation (a backup or move reader;
// Consumer is its consumer ID).
type resourceUser struct {
	Kind                     string
	App, Service, Standalone string `json:",omitempty"`
	Node                     string `json:",omitempty"`
	Consumer                 string `json:",omitempty"`
	ReadOnly                 bool
	Attached                 bool
	Selection                []mydc.ContainerSelection `json:",omitempty"`
}

type resourceUsersView struct {
	Tenant      string `json:",omitempty"`
	Network     string `json:",omitempty"`
	Volume      string `json:",omitempty"`
	Users       []resourceUser
	Apps        int
	Standalones int
	Total       int
}

func readResourceUsers(ctx context.Context, c mydc.Conn, method, tenant, name, app string) (resourceUsersView, error) {
	p, rows, err := publicReadAll(ctx, c, method, tenant, control.PublicReadQuery{Name: name, App: app})
	if err != nil {
		return resourceUsersView{}, err
	}
	network := method == "network-users"
	users, apps, standalones := resourceUsers(rows, network)
	v := resourceUsersView{Tenant: tenant, Users: users, Apps: apps, Standalones: standalones, Total: p.Total}
	if network {
		v.Network = name
	} else {
		v.Volume = name
	}
	return v, nil
}

// readImageTrust: image-trust's page Rules and Image rows as the web's
// trust model; Revision is the tenant revision (set-trust's Expected).
func readImageTrust(ctx context.Context, c mydc.Conn, tenant string) (mydc.ImageTrust, error) {
	p, rows, err := publicReadAll(ctx, c, "image-trust", tenant, control.PublicReadQuery{})
	if err != nil {
		return mydc.ImageTrust{}, err
	}
	t := mydc.ImageTrust{Tenant: tenant, Revision: p.TenantRevision, Rules: p.Rules, Uses: []mydc.ImageTrustUse{}}
	for _, r := range rows {
		if u := r.Image; u != nil {
			t.Uses = append(t.Uses, mydc.ImageTrustUse{App: u.App, Deployment: u.Deployment, Service: u.Service, Standalone: u.Standalone, Image: u.Reference, Rules: u.Rules})
		}
	}
	return t, nil
}

// readFileGrants: volume-file-grants rows for one volume (or the tenant
// when volume is "").
func readFileGrants(ctx context.Context, c mydc.Conn, tenant, volume, app string) ([]control.PublicFileGrant, error) {
	_, rows, err := publicReadAll(ctx, c, "volume-file-grants", tenant, control.PublicReadQuery{Name: volume, App: app})
	if err != nil {
		return nil, err
	}
	out := []control.PublicFileGrant{}
	for _, r := range rows {
		if r.FileGrant != nil {
			out = append(out, *r.FileGrant)
		}
	}
	return out, nil
}

// readClosure: network-closure of one draining member (one row, After is
// not allowed).
func readClosure(ctx context.Context, c mydc.Conn, tenant, member string) (control.NetworkClosureStatus, error) {
	p, err := c.PublicRead(ctx, "network-closure", tenant, control.PublicReadQuery{Name: member}, "")
	if err != nil {
		return control.NetworkClosureStatus{}, err
	}
	for _, r := range p.Rows {
		if r.Closure != nil {
			return *r.Closure, nil
		}
	}
	return control.NetworkClosureStatus{}, &httpErr{http.StatusBadGateway, "closure-missing", "mydcd gave no closure row for the member"}
}

// readBackupLimits: volume-backup-limits rows (tenant "" = the server-wide
// rows, system administrator); a tenant's rows only say whether the
// server-wide row exists (GlobalPresent).
func readBackupLimits(ctx context.Context, c mydc.Conn, tenant, node string) ([]control.PublicBackupLimit, error) {
	_, rows, err := publicReadAll(ctx, c, "volume-backup-limits", tenant, control.PublicReadQuery{Node: node})
	if err != nil {
		return nil, err
	}
	out := []control.PublicBackupLimit{}
	for _, r := range rows {
		if r.BackupLimit != nil {
			out = append(out, *r.BackupLimit)
		}
	}
	return out, nil
}

// readLifecycleUses: lifecycle-uses of one named script.
func readLifecycleUses(ctx context.Context, c mydc.Conn, tenant, name string) ([]control.PublicLifecycleUse, error) {
	_, rows, err := publicReadAll(ctx, c, "lifecycle-uses", tenant, control.PublicReadQuery{Name: name})
	if err != nil {
		return nil, err
	}
	out := []control.PublicLifecycleUse{}
	for _, r := range rows {
		if r.Lifecycle != nil {
			out = append(out, *r.Lifecycle)
		}
	}
	return out, nil
}

// readRouteEndpoints: route-endpoints of another tenant, the open
// TUN members it offers as route destinations.
func readRouteEndpoints(ctx context.Context, c mydc.Conn, tenant string) ([]control.RouteEndpoint, error) {
	_, rows, err := publicReadAll(ctx, c, "route-endpoints", tenant, control.PublicReadQuery{})
	if err != nil {
		return nil, err
	}
	out := []control.RouteEndpoint{}
	for _, r := range rows {
		if e := r.RouteEndpoint; e != nil {
			out = append(out, control.RouteEndpoint{Tenant: e.Tenant, Network: e.Network, Node: e.Node, Pool: e.Pool})
		}
	}
	return out, nil
}
