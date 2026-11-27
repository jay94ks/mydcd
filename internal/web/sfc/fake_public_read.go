// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/secrets"
)

// RQ10 reads in sfcd's common envelope (docs/reference/resource-queries.md
// '요청과 페이지', userauth.Client.PublicRead): one User request
// {Method, Tenant, PublicRead: control.PublicReadQuery{Name, App, Node},
// After} for network-users, network-closure, volume-users,
// volume-backup-limits, route-endpoints, lifecycle-uses, vault-approvals,
// vault-usages, volume-retained-sources, image-trust and volume-file-grants.
// The reply is control.PublicReadPage{Schema, Method, Tenant, Index,
// RootRevision, CatalogRevision, TenantRevision, Rules?, Rows (at most 8),
// Next, Total}; each row has Key and exactly one payload.
//
// sfcd marks these reads '구현·연동 중'. The fake builds the rows from the
// same state its older per-method mocks read (NetworkUsers, VolumeUsers, …),
// which stay until the daemon moves.

// PublicReadPageRows is sfcd's page size for these reads.
const PublicReadPageRows = 8

func (c *fakeConn) PublicRead(ctx context.Context, method, tenant string, q control.PublicReadQuery, after string) (control.PublicReadPage, error) {
	m := method
	if !control.PublicReadMethod(method) || !q.Valid(method) || len(after) > 512 || method == "network-closure" && after != "" {
		return control.PublicReadPage{}, fail(m, CodeInvalid, "method or selector")
	}
	// The permission boundary of control.Policy.PublicRead.
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.PublicReadPage{}, err
	}
	w := c.f.w
	allowed := false
	switch {
	case method == "route-endpoints", method == "bridge-endpoints":
		allowed = w.admin(user) || slices.ContainsFunc(sortedKeys(w.tenants), func(t string) bool { return w.canManage(user, t) })
	case tenant == "":
		allowed = w.admin(user) && (method == "vault-approvals" || method == "vault-usages" || method == "volume-backup-limits")
	case method == "network-closure", method == "lifecycle-uses", method == "vault-approvals", method == "vault-usages":
		allowed = w.canManage(user, tenant)
	default:
		allowed = w.canRead(user, tenant)
	}
	c.unlock()
	if !allowed {
		return control.PublicReadPage{}, fail(m, CodeDenied, "")
	}
	page := control.PublicReadPage{Schema: 1, Method: method, Tenant: tenant, Rows: []control.PublicReadRow{}}
	rows, err := c.publicRows(ctx, method, tenant, q, &page)
	if err != nil {
		return control.PublicReadPage{}, err
	}
	if _, err := c.lockSession(ctx, m); err != nil {
		return control.PublicReadPage{}, err
	}
	page.Index, page.RootRevision, page.CatalogRevision = w.root, w.keyRoot(publicReadRoot(method)), w.keyRoot(control.CatalogKey)
	if _, ok := w.tenants[tenant]; ok && method != "route-endpoints" && method != "bridge-endpoints" {
		page.TenantRevision = w.tenantRev[tenant]
	}
	c.unlock()
	page.Total = len(rows)
	start := 0
	if after != "" {
		start = slices.IndexFunc(rows, func(r control.PublicReadRow) bool { return r.Key == after }) + 1
		if start == 0 {
			return control.PublicReadPage{}, fail(m, CodeCursorExpired, "")
		}
	}
	end := min(start+PublicReadPageRows, len(rows))
	page.Rows = append(page.Rows, rows[start:end]...)
	if end < len(rows) {
		page.Next = rows[end-1].Key
	}
	return page, nil
}

// publicReadRoot: control's state root per method.
func publicReadRoot(method string) string {
	switch method {
	case "network-closure", "network-users", "route-endpoints", "bridge-endpoints":
		return control.ResourcesKey
	case "volume-backup-limits", "volume-users", "volume-retained-sources":
		return control.VolumesKey
	case "lifecycle-uses":
		return control.LifecycleKey
	case "vault-approvals", "vault-usages":
		return control.VaultKey
	}
	return control.CatalogKey
}

func userKind(kind string) string {
	if kind == "standalone" {
		return "standalone"
	}
	return "app-service"
}

func publicUser(tenant, kind, app, service, standalone, node string, attached bool, writable *bool) control.PublicResourceUser {
	u := control.PublicResourceUser{Kind: userKind(kind), Tenant: tenant, App: app, Service: service, Standalone: standalone, Node: node,
		Desired: "running", Observed: "exited", Live: true, Writable: writable}
	present := attached
	u.ContainerPresent, u.EndpointPresent = &present, nil
	if attached {
		u.Observed = "running"
		u.EndpointPresent = &present
	}
	return u
}

func userKey(u control.PublicResourceUser) string {
	return strings.Join([]string{u.Kind, u.App, u.Service, u.Standalone, u.Node}, "/")
}

// publicRows builds every row of one read, in key order, through the
// fake's per-method mocks (each takes the lock itself).
func (c *fakeConn) publicRows(ctx context.Context, method, tenant string, q control.PublicReadQuery, page *control.PublicReadPage) ([]control.PublicReadRow, error) {
	var rows []control.PublicReadRow
	add := func(key string, r control.PublicReadRow) {
		r.Key = key
		rows = append(rows, r)
	}
	switch method {
	case "network-users":
		v, err := c.networkUsers(ctx, tenant, q.Name)
		if err != nil {
			return nil, err
		}
		for _, x := range v.Users {
			u := publicUser(tenant, x.Kind, x.App, x.Service, x.Standalone, x.Node, x.Attached, nil)
			add(userKey(u), control.PublicReadRow{User: &u})
		}
	case "volume-users":
		v, err := c.volumeUsers(ctx, tenant, q.Name, q.App)
		if err != nil {
			return nil, err
		}
		for _, x := range v.Users {
			writable := !x.ReadOnly
			u := publicUser(tenant, x.Kind, x.App, x.Service, x.Standalone, x.Node, x.Attached, &writable)
			add(userKey(u), control.PublicReadRow{User: &u})
		}
	case "network-closure":
		v, err := c.networkClosure(ctx, tenant, q.Name)
		if err != nil {
			return nil, err
		}
		st := control.NetworkClosureStatus{State: "pending"}
		switch {
		case v.Unreachable:
			st.State = "unreachable"
		case v.Closed != nil:
			cl := *v.Closed
			st.State, st.Closure = "closed", &cl
		default:
			gone, eps, flows, pins := v.NativeGone, v.PendingEndpoints, v.PendingFlows, v.PendingPins
			st.NativeGone, st.PendingEndpoints, st.PendingFlows, st.PendingPins = &gone, &eps, &flows, &pins
		}
		add(q.Name, control.PublicReadRow{Closure: &st})
	case "volume-backup-limits":
		var limits []BackupLimitRow
		if tenant == "" {
			if _, err := c.lockSession(ctx, method); err != nil {
				return nil, err
			}
			for _, l := range c.f.w.backupLimits {
				if l.Tenant == "" && (q.Node == "" || l.Node == q.Node) {
					limits = append(limits, BackupLimitRow{Limit: l, Used: c.f.w.backupUsage("", l.Node)})
				}
			}
			c.unlock()
		} else {
			v, err := c.volumeBackupLimits(ctx, tenant, q.Node)
			if err != nil {
				return nil, err
			}
			limits = v.Rows
		}
		global, globalOriginal := map[string]bool{}, map[string]bool{}
		for _, r := range limits {
			if r.Limit.Tenant == "" {
				global[r.Limit.Node] = true
				globalOriginal[r.Limit.Node] = r.Limit.Original != nil
			}
		}
		for _, r := range limits {
			if r.Limit.Tenant != tenant {
				continue
			}
			l := r.Limit
			b := control.PublicBackupLimit{Tenant: tenant, Node: l.Node, Revision: l.Revision, Bytes: l.Bytes, Count: l.Count, StagingBytes: l.StagingBytes, StagingCount: l.StagingCount,
				UsedBytes: r.Used.Bytes, UsedCount: r.Used.Count, UsedStagingBytes: r.Used.StagingBytes, UsedStagingCount: r.Used.StagingCount, GlobalPresent: global[l.Node] && tenant != "", GlobalOriginal: globalOriginal[l.Node] && tenant != "", Original: l.Original}
			add(l.Node, control.PublicReadRow{BackupLimit: &b})
		}
	case "route-endpoints":
		v, err := c.routeEndpoints(ctx, tenant)
		if err != nil {
			return nil, err
		}
		for _, e := range v.Endpoints {
			r := control.PublicRouteEndpoint{Tenant: e.Tenant, Network: e.Network, Node: e.Node, Pool: e.Pool}
			add(strings.Join([]string{e.Network, e.Node, e.Pool}, "/"), control.PublicReadRow{RouteEndpoint: &r})
		}
	case "bridge-endpoints":
		for _, name := range c.bridgeEndpoints(tenant) {
			r := control.PublicBridgeEndpoint{Tenant: tenant, Network: name}
			add(name, control.PublicReadRow{BridgeEndpoint: &r})
		}
	case "lifecycle-uses":
		v, err := c.lifecycleUses(ctx, tenant, q.Name)
		if err != nil {
			return nil, err
		}
		for _, x := range v.Items {
			id := strings.Join([]string{x.Kind, x.App, x.Service, x.Node}, "/")
			l := control.PublicLifecycleUse{ID: id, Kind: x.Kind, App: x.App, Service: x.Service, Node: x.Node, Revision: x.Revision}
			add(id, control.PublicReadRow{Lifecycle: &l})
		}
	case "vault-approvals":
		for after := ""; ; {
			p, err := c.vaultApprovals(ctx, tenant, q.App, after)
			if err != nil {
				return nil, err
			}
			for _, x := range p.Items {
				a := secrets.PublicApproval{ID: x.ID, Realm: x.Realm, Tenant: x.Realm, Group: x.Group, User: x.User, App: x.App, Deployment: x.Deployment,
					Services: slices.Clone(x.Services), Nodes: slices.Clone(x.Nodes), ApprovedAt: x.ApprovedAt, ExpiresAt: x.ExpiresAt, Revoking: x.Revoked}
				add(x.ID, control.PublicReadRow{Approval: &a})
			}
			if p.Next == "" || p.Next == after {
				break
			}
			after = p.Next
		}
	case "vault-usages":
		for after := ""; ; {
			p, err := c.vaultUsages(ctx, tenant, q.Name, after)
			if err != nil {
				return nil, err
			}
			for _, x := range p.Items {
				id := strings.Join([]string{x.App, x.Deployment, x.Service, x.Standalone, x.Node}, "/")
				u := secrets.PublicUsage{ID: id, Realm: tenant, Tenant: tenant, App: x.App, Standalone: x.Standalone, Deployment: x.Deployment, Service: x.Service, Node: x.Node,
					Secrets: slices.Clone(x.Secrets), Live: x.Live}
				add(id, control.PublicReadRow{SecretUsage: &u})
			}
			if p.Next == "" || p.Next == after {
				break
			}
			after = p.Next
		}
	case "volume-retained-sources":
		for after := ""; ; {
			p, err := c.Volumes(ctx, tenant, after)
			if err != nil {
				return nil, err
			}
			for _, v := range p.Items {
				if v.Scope.ID != q.Name || q.App != "" && v.Scope.App != q.App {
					continue
				}
				for _, r := range v.Retained {
					x := control.PublicRetainedSource{Scope: v.Scope, Move: r.Move, Node: r.Node, State: r.State}
					add(r.Move+"/"+r.Node, control.PublicReadRow{Retained: &x})
				}
			}
			if p.Next == "" || p.Next == after {
				break
			}
			after = p.Next
		}
	case "image-trust":
		v, err := c.imageTrust(ctx, tenant)
		if err != nil {
			return nil, err
		}
		page.Rules = slices.Clone(v.Rules)
		for i, x := range v.Uses {
			kind := "app-service"
			if x.Standalone != "" {
				kind = "standalone"
			}
			u := control.PublicImageTrustUse{Kind: kind, App: x.App, Deployment: x.Deployment, Service: x.Service, Standalone: x.Standalone, Reference: x.Image, Rules: slices.Clone(x.Rules)}
			add(strconv.Itoa(i)+"/"+userKind(kind)+"/"+x.App+"/"+x.Service+"/"+x.Standalone, control.PublicReadRow{Image: &u})
		}
	case "volume-file-grants":
		v, err := c.volumeFileGrants(ctx, tenant, q.Name)
		if err != nil {
			return nil, err
		}
		for _, x := range v {
			if q.App != "" && x.App != q.App {
				continue
			}
			g := control.PublicFileGrant{Tenant: x.Tenant, App: x.App, Volume: x.Volume, Prefix: x.Prefix, User: x.User, Revision: x.Revision,
				AccountEnabled: x.Active, VolumePresent: true, Operations: []string{"put", "get", "list", "delete"}}
			add(strings.Join([]string{x.App, x.Volume, x.Prefix, x.User}, "/"), control.PublicReadRow{FileGrant: &g})
		}
	}
	slices.SortStableFunc(rows, func(a, b control.PublicReadRow) int { return strings.Compare(a.Key, b.Key) })
	return rows, nil
}
