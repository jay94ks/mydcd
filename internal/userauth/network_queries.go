// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// ResourcesQuery selects one page of the resources book. An empty Tenant
// asks for the whole cluster (administrators).
type ResourcesQuery struct {
	Tenant string `json:",omitempty"`
	After  string `json:",omitempty"`
}

func (q ResourcesQuery) Valid() bool {
	return (q.Tenant == "" || lifecycle.ValidID(q.Tenant)) && len(q.After) <= 512
}

// ResourcesPage is one page of resource rows from one committed view: the
// book's root revision (the CAS an operation compares against), the view
// index, the book, network and quota revisions, and the rows.
type ResourcesPage struct {
	RootRevision    uint64
	Index           uint64
	Revision        uint64
	NetworkRevision uint64
	QuotaRevision   uint64
	Items           []control.ResourceEntry
	Next            string `json:",omitempty"`
}

// NetworkDNSNamesQuery names one network of a tenant.
type NetworkDNSNamesQuery struct{ Tenant, Network string }

func (q NetworkDNSNamesQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && (control.NetworkDNSNamesQuery{Network: q.Network}).Valid()
}

// PublicReadParams is the request of every PublicRead method: the tenant
// (empty for the cluster-wide vault and backup-limit reads), the method's
// selectors and the page cursor. Which selectors a method takes is
// control.PublicReadQuery.Valid(method); network-closure has no pages.
type PublicReadParams struct {
	Tenant string `json:",omitempty"`
	Query  control.PublicReadQuery
	After  string `json:",omitempty"`
}

func (p PublicReadParams) valid(method string) bool {
	return control.PublicReadMethod(method) && (p.Tenant == "" || lifecycle.ValidID(p.Tenant)) && p.Query.Valid(method) && len(p.After) <= 512 && (method != "network-closure" || p.After == "")
}

func (c Client) Resources(ctx context.Context, target sfcp.Peer, session access.Session, q ResourcesQuery) (ResourcesPage, error) {
	page, err := call(ctx, c, target, session, ResourcesMethod, q)
	if err == nil && (len(page.Items) > 8 || len(page.Next) > 512 || len(page.Items) == 0 && page.Next != "") {
		return ResourcesPage{}, sfcp.ErrFrame
	}
	return page, err
}

func (c Client) NetworkDNSNames(ctx context.Context, target sfcp.Peer, session access.Session, q NetworkDNSNamesQuery) (control.NetworkDNSNames, error) {
	return call(ctx, c, target, session, NetworkDNSNamesMethod, q)
}

// PublicRead reads one page of a PublicRead method and checks its rows
// against the method, tenant and selectors asked for.
func (c Client) PublicRead(ctx context.Context, target sfcp.Peer, session access.Session, method, tenant string, q control.PublicReadQuery, after string) (control.PublicReadPage, error) {
	m, ok := publicReadMethods[method]
	p := PublicReadParams{Tenant: tenant, Query: q, After: after}
	if !ok || !p.valid(method) {
		return control.PublicReadPage{}, sfcp.ErrAdmission
	}
	page, err := call(ctx, c, target, session, m, p)
	if err != nil {
		return control.PublicReadPage{}, err
	}
	if err := verifyPublicReadPage(c.Cluster, method, tenant, q, page); err != nil {
		return control.PublicReadPage{}, err
	}
	return page, nil
}

var (
	// ResourcesMethod: a tenant page needs Read on it, the whole cluster
	// ManageCluster. Managed DNS rows carry their live owner state, checked
	// again against a fresh quorum view.
	ResourcesMethod = define(Method[ResourcesQuery, ResourcesPage]{Name: "resources"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q ResourcesQuery) (ResourcesPage, string) {
		catalog, err := s.Policy.Catalog(view.State)
		if err != nil {
			return ResourcesPage{}, "unavailable"
		}
		action := access.Read
		if q.Tenant == "" {
			action = access.ManageCluster
		}
		if catalog.AuthorizeSession(session, s.Policy.Cluster, s.Policy.Issuer(session.Issuer), time.Now().Unix(), q.Tenant, action, "") != nil {
			return ResourcesPage{}, "denied"
		}
		projection, err := s.Policy.ProjectResources(view.State)
		if err != nil {
			return ResourcesPage{}, "unavailable"
		}
		resources := projection.Resources
		page := ResourcesPage{RootRevision: view.State.Object(control.ResourcesKey).Revision, Index: view.State.Index(), Revision: resources.Revision, NetworkRevision: resources.Networks.Revision(), QuotaRevision: resources.Quotas.Revision()}
		if projection.NetworkAuthority != nil {
			page.Items, page.Next, err = resources.Page(catalog, session.User, q.Tenant, q.After, *projection.NetworkAuthority)
		} else {
			page.Items, page.Next, err = resources.Page(catalog, session.User, q.Tenant, q.After)
		}
		if err != nil {
			return ResourcesPage{}, "denied"
		}
		if page.Items == nil {
			page.Items = []control.ResourceEntry{}
		}
		if code := s.resourceDNSRead(ctx, view, session, page.Items); code != "ok" {
			return ResourcesPage{}, code
		}
		return page, "ok"
	})
	// NetworkDNSNamesMethod: Policy.NetworkDNSNames checks Read on the tenant.
	NetworkDNSNamesMethod = define(Method[NetworkDNSNamesQuery, control.NetworkDNSNames]{Name: "network-dns-names"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q NetworkDNSNamesQuery) (control.NetworkDNSNames, string) {
		names, err := s.Policy.NetworkDNSNames(view.State, session, time.Now().Unix(), q.Tenant, control.NetworkDNSNamesQuery{Network: q.Network})
		if err != nil {
			if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
				return control.NetworkDNSNames{}, "denied"
			}
			return control.NetworkDNSNames{}, "unavailable"
		}
		return names, "ok"
	})
)

// publicReadMethods holds one typed method per control.PublicReadMethod
// name; all share PublicReadParams and control.PublicReadPage, and
// control.Policy.PublicRead authorizes each.
var publicReadMethods = func() map[string]Method[PublicReadParams, control.PublicReadPage] {
	out := map[string]Method[PublicReadParams, control.PublicReadPage]{}
	for _, name := range control.PublicReadMethods() {
		out[name] = publicRead(name)
	}
	return out
}()

func publicRead(name string) Method[PublicReadParams, control.PublicReadPage] {
	// Public reads are served by every member, ingress-only ones too.
	return define(Method[PublicReadParams, control.PublicReadPage]{Name: name}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, p PublicReadParams) (control.PublicReadPage, string) {
		if !p.valid(name) {
			return control.PublicReadPage{}, "denied"
		}
		return s.publicReadPage(ctx, view, session, name, p)
	})
}
