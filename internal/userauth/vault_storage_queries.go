// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// VaultQuery selects one page of a realm's Vault metadata. An empty Tenant
// is the cluster realm (ManageCluster).
type VaultQuery struct {
	Tenant string `json:",omitempty"`
	After  string `json:",omitempty"`
}

func (q VaultQuery) Valid() bool {
	return (q.Tenant == "" || lifecycle.ValidID(q.Tenant)) && len(q.After) <= 512
}

// VaultPage is one page of public Vault metadata. Pages of one tree share
// RootRevision and TreeRevision; a change on the tree uses Revision,
// TreeRevision, WriteEpoch and ApprovalRevision from the same read.
type VaultPage struct {
	Items            []control.VaultView
	Next             string `json:",omitempty"`
	RootRevision     uint64
	Revision         uint64
	ApprovalRevision uint64
	TreeRevision     uint64 `json:",omitempty"`
	WriteEpoch       uint64 `json:",omitempty"`
}

// VaultApprovalPlanQuery asks for one part of a realm's approval plan.
type VaultApprovalPlanQuery struct {
	Tenant string
	Plan   control.VaultApprovalPlanRequest
}

func (q VaultApprovalPlanQuery) Valid() bool { return lifecycle.ValidID(q.Tenant) }

// NodeStorageQuery selects one page of registered storage roots, on one
// server when Node is set.
type NodeStorageQuery struct {
	Node  string `json:",omitempty"`
	After string `json:",omitempty"`
}

func (q NodeStorageQuery) Valid() bool {
	return (q.Node == "" || lifecycle.ValidID(q.Node)) && len(q.After) <= 512
}

// NodeStoragePage is one page of storage roots. Revision is the book's and
// RootRevision its root object's.
type NodeStoragePage struct {
	Items        []nodestorage.Root
	Next         string `json:",omitempty"`
	Revision     uint64
	RootRevision uint64
}

// NodeStorageSpaceQuery names one storage root to measure.
type NodeStorageSpaceQuery struct{ control.NodeStorageSelection }

func (q NodeStorageSpaceQuery) Valid() bool {
	return lifecycle.ValidID(q.Node) && lifecycle.ValidID(q.ID)
}

// NodeStorageSpaceReply is the owner's measured space of one root, checked
// against the committed index it was read at.
type NodeStorageSpaceReply struct {
	Space        nodestorage.Space
	Revision     uint64
	RootRevision uint64
	ModuleEpoch  uint64
	Index        uint64
}

// TenantStorageQuery selects one page of the storage roots a tenant may use.
type TenantStorageQuery struct {
	Tenant string
	Node   string `json:",omitempty"`
	After  string `json:",omitempty"`
}

func (q TenantStorageQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && (q.Node == "" || lifecycle.ValidID(q.Node)) && len(q.After) <= 512
}

func (c Client) QueryVault(ctx context.Context, target sfcp.Peer, session access.Session, realm, after string) (VaultPage, error) {
	return call(ctx, c, target, session, VaultMethod, VaultQuery{Tenant: realm, After: after})
}

// PlanVaultWrite returns public metadata from one authenticated quorum view.
// Private input never traverses the query/relay path.
func (c Client) PlanVaultWrite(ctx context.Context, target sfcp.Peer, session access.Session, q control.VaultWritePlanRequest) (control.VaultWritePlan, error) {
	p, err := call(ctx, c, target, session, VaultWritePlanMethod, q)
	if err != nil {
		return control.VaultWritePlan{}, err
	}
	if p.Schema != 1 || p.Realm != q.Realm || p.Request.ID != q.ID {
		return control.VaultWritePlan{}, sfcp.ErrFrame
	}
	return p, nil
}

func (c Client) NodeStoragePage(ctx context.Context, target sfcp.Peer, session access.Session, node, after string) (NodeStoragePage, error) {
	return call(ctx, c, target, session, NodeStorageMethod, NodeStorageQuery{Node: node, After: after})
}

func (c Client) NodeStorageSpace(ctx context.Context, target sfcp.Peer, session access.Session, selection control.NodeStorageSelection) (NodeStorageSpaceReply, error) {
	reply, err := call(ctx, c, target, session, NodeStorageSpaceMethod, NodeStorageSpaceQuery{selection})
	if err != nil {
		return NodeStorageSpaceReply{}, err
	}
	v := reply.Space
	if v.Root.Validate() != nil || v.Root.Cluster != c.Cluster || v.Root.Node != selection.Node || v.Root.ID != selection.ID || reply.Index == 0 || reply.RootRevision == 0 || reply.ModuleEpoch == 0 {
		return NodeStorageSpaceReply{}, sfcp.ErrAdmission
	}
	if _, err = nodestorage.AggregateSpaces([]nodestorage.Space{v}); err != nil {
		return NodeStorageSpaceReply{}, sfcp.ErrAdmission
	}
	return reply, nil
}

func (c Client) TenantStoragePage(ctx context.Context, target sfcp.Peer, session access.Session, tenant, node, after string) (control.TenantStoragePage, error) {
	page, err := call(ctx, c, target, session, TenantStorageMethod, TenantStorageQuery{Tenant: tenant, Node: node, After: after})
	if err != nil {
		return control.TenantStoragePage{}, err
	}
	if page.Index == 0 || len(page.Items) > 8 || len(page.Next) > 512 {
		return control.TenantStoragePage{}, sfcp.ErrFrame
	}
	previous := ""
	for _, root := range page.Items {
		key := root.Node + "/" + root.ID
		if !root.Allowed || root.Revision == 0 || root.Generation == 0 || root.Root.Validate() != nil || root.Root.Cluster != c.Cluster || root.Node != root.Root.Node || root.ID != root.Root.ID || root.Generation != root.Root.Generation || node != "" && root.Node != node || previous != "" && key <= previous {
			return control.TenantStoragePage{}, sfcp.ErrFrame
		}
		previous = key
	}
	if page.Next != "" && (len(page.Items) == 0 || page.Next == after) {
		return control.TenantStoragePage{}, sfcp.ErrFrame
	}
	return page, nil
}

// authorize checks one action of the session on tenant (or the cluster).
func (s Service) authorize(view cluster.View, session access.Session, tenant string, action access.Action, cleanup bool) (access.Catalog, string) {
	c, err := s.Policy.Catalog(view.State)
	if err != nil {
		return access.Catalog{}, "unavailable"
	}
	issuer, now := s.Policy.Issuer(session.Issuer), time.Now().Unix()
	if cleanup {
		err = c.AuthorizeSessionCleanup(session, s.Policy.Cluster, issuer, now, tenant, action)
	} else {
		err = c.AuthorizeSession(session, s.Policy.Cluster, issuer, now, tenant, action, "")
	}
	if err != nil {
		return access.Catalog{}, "denied"
	}
	return c, "ok"
}

// secretsAction is ManageSecrets on a tenant realm, ManageCluster on the
// cluster realm.
func secretsAction(tenant string) access.Action {
	if tenant == "" {
		return access.ManageCluster
	}
	return access.ManageSecrets
}

var (
	// VaultMethod pages a realm's public Vault metadata. Read-only metadata
	// stays available to current cleanup authority after retirement blocks
	// new value and metadata writes.
	VaultMethod = define(Method[VaultQuery, VaultPage]{Name: "vault"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q VaultQuery) (VaultPage, string) {
		c, code := s.authorize(view, session, q.Tenant, secretsAction(q.Tenant), q.Tenant != "")
		if code != "ok" {
			return VaultPage{}, code
		}
		v, err := s.Policy.Vault(view.State)
		if err != nil {
			return VaultPage{}, "unavailable"
		}
		page := VaultPage{RootRevision: view.State.Object(control.VaultKey).Revision, Revision: v.Revision, ApprovalRevision: v.Approvals.Revision()}
		if tree, ok := v.Trees[q.Tenant]; ok {
			page.TreeRevision, page.WriteEpoch = tree.Revision(), tree.WriteEpoch()
		}
		if page.Items, page.Next, err = v.Page(c, session.User, q.Tenant, q.After); err != nil {
			return VaultPage{}, "denied"
		}
		if page.Items == nil {
			page.Items = []control.VaultView{}
		}
		return page, "ok"
	})

	// VaultApprovalPlanMethod returns one part of a realm's approval plan. A
	// member that runs no workloads serves it only for an accepted original,
	// so it can be found before its recovery call; fresh planning is not
	// recovery.
	VaultApprovalPlanMethod = defineIngressIf(Method[VaultApprovalPlanQuery, control.VaultApprovalPart]{Name: "vault-approval-plan"}, func(_ Service, view state.State, q VaultApprovalPlanQuery) bool {
		return acceptedNodeApproval(view, q.Plan.Origin, q.Plan.Selection)
	}, func(_ context.Context, s Service, view cluster.View, session access.Session, q VaultApprovalPlanQuery) (control.VaultApprovalPart, string) {
		if _, code := s.authorize(view, session, q.Tenant, access.Deploy, false); code != "ok" {
			return control.VaultApprovalPart{}, code
		}
		part, err := s.Policy.PlanVaultApproval(view.State, session, time.Now().Unix(), q.Tenant, q.Plan)
		if err != nil {
			return control.VaultApprovalPart{}, "denied"
		}
		return part, "ok"
	})

	// VaultWritePlanMethod returns the public plan of one Vault write; the
	// ingress rule is the approval plan's, for an original write.
	VaultWritePlanMethod = defineIngressIf(Method[control.VaultWritePlanRequest, control.VaultWritePlan]{Name: "vault-write-plan"}, func(s Service, view state.State, q control.VaultWritePlanRequest) bool {
		vault, err := s.Policy.Vault(view)
		if err != nil {
			return false
		}
		tree, found := vault.Trees[q.Realm]
		if !found {
			return false
		}
		_, known := tree.Write(q.ID)
		return known
	}, func(_ context.Context, s Service, view cluster.View, session access.Session, q control.VaultWritePlanRequest) (control.VaultWritePlan, string) {
		if q.Realm != "" && !lifecycle.ValidID(q.Realm) {
			return control.VaultWritePlan{}, "denied"
		}
		if _, code := s.authorize(view, session, q.Realm, secretsAction(q.Realm), false); code != "ok" {
			return control.VaultWritePlan{}, code
		}
		plan, err := s.Policy.PlanVaultWrite(view.State, session, time.Now().Unix(), q)
		if err != nil {
			return control.VaultWritePlan{}, "denied"
		}
		return plan, "ok"
	})

	// NodeStorageMethod pages registered storage roots (administrators).
	NodeStorageMethod = define(Method[NodeStorageQuery, NodeStoragePage]{Name: "node-storage"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q NodeStorageQuery) (NodeStoragePage, string) {
		c, code := s.authorize(view, session, "", access.ManageCluster, false)
		if code != "ok" {
			return NodeStoragePage{}, code
		}
		roots, err := s.Policy.NodeStorage(view.State)
		if err != nil {
			return NodeStoragePage{}, "unavailable"
		}
		page := NodeStoragePage{Revision: roots.Revision(), RootRevision: view.State.Object(control.NodeStorageKey).Revision}
		if page.Items, page.Next, err = s.Policy.NodeStoragePage(view.State, c, session.User, q.Node, q.After); err != nil {
			return NodeStoragePage{}, "denied"
		}
		if page.Items == nil {
			page.Items = []nodestorage.Root{}
		}
		return page, "ok"
	})

	// NodeStorageSpaceMethod asks the owner to measure one root and answers
	// only when the root is unchanged at a newer leader read.
	NodeStorageSpaceMethod = define(Method[NodeStorageSpaceQuery, NodeStorageSpaceReply]{Name: "node-storage-space"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q NodeStorageSpaceQuery) (NodeStorageSpaceReply, string) {
		if _, code := s.authorize(view, session, "", access.ManageCluster, false); code != "ok" {
			return NodeStorageSpaceReply{}, code
		}
		if s.NodeStorageObserver == nil {
			return NodeStorageSpaceReply{}, "unavailable"
		}
		root, err := s.Policy.NodeStorageRead(view.State, session, time.Now().Unix(), q.NodeStorageSelection)
		if err != nil {
			return NodeStorageSpaceReply{}, "denied"
		}
		value, err := s.NodeStorageObserver(ctx, root)
		if err != nil {
			return NodeStorageSpaceReply{}, "unavailable"
		}
		roots, err := s.Policy.NodeStorage(view.State)
		if err != nil {
			return NodeStorageSpaceReply{}, "unavailable"
		}
		if _, err = roots.Capacities([]nodestorage.Space{value}); err != nil || value.Root != root.Reference(s.Policy.Cluster) {
			return NodeStorageSpaceReply{}, "unavailable"
		}
		latest, err := s.Engine.Read(ctx, true)
		if err != nil || latest.Local {
			return NodeStorageSpaceReply{}, "unavailable"
		}
		current, err := s.Policy.NodeStorageRead(latest.State, session, time.Now().Unix(), q.NodeStorageSelection)
		a, _ := json.Marshal(root)
		b, _ := json.Marshal(current)
		if err != nil || !bytes.Equal(a, b) {
			return NodeStorageSpaceReply{}, "denied"
		}
		book, err := s.Policy.NodeStorage(latest.State)
		if err != nil {
			return NodeStorageSpaceReply{}, "unavailable"
		}
		return NodeStorageSpaceReply{Space: value, Revision: book.Revision(), RootRevision: latest.State.Object(control.NodeStorageKey).Revision, ModuleEpoch: latest.State.ModuleEpoch(), Index: latest.State.Index()}, "ok"
	})

	// TenantStorageMethod pages the storage roots a tenant's volume or
	// registry managers may place data on; the policy reader checks
	// ManageVolumes or ManageRegistry on each server it shows.
	TenantStorageMethod = define(Method[TenantStorageQuery, control.TenantStoragePage]{Name: "tenant-storage"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q TenantStorageQuery) (control.TenantStoragePage, string) {
		c, err := s.Policy.Catalog(view.State)
		if err != nil {
			return control.TenantStoragePage{}, "unavailable"
		}
		issuer, now := s.Policy.Issuer(session.Issuer), time.Now().Unix()
		if c.AuthorizeSession(session, s.Policy.Cluster, issuer, now, q.Tenant, access.ManageVolumes, q.Node) != nil && c.AuthorizeSession(session, s.Policy.Cluster, issuer, now, q.Tenant, access.ManageRegistry, q.Node) != nil {
			return control.TenantStoragePage{}, "denied"
		}
		page, err := s.Policy.TenantStoragePage(view.State, session, now, q.Tenant, q.Node, q.After)
		switch {
		case err == nil:
			if page.Items == nil {
				page.Items = []control.TenantStorageRoot{}
			}
			return page, "ok"
		case errors.Is(err, access.ErrConflict):
			return control.TenantStoragePage{}, "conflict"
		}
		return control.TenantStoragePage{}, "denied"
	})
)
