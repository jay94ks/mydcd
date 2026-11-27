// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/jay94ks/seafield/internal/userauth"
)

// Account and cluster reads of the real adapter (W1.2 step 2): each is the
// same userauth.Client read the CLI makes, returned in the product types.

// read runs one query with the current session.
func (c *realConn) read(ctx context.Context, r userauth.Request) (userauth.Reply, error) {
	s, done, err := c.open(ctx, r.Method, true)
	if err != nil {
		return userauth.Reply{}, err
	}
	defer done()
	reply, err := c.c.QueryRequest(ctx, c.peer, s, r)
	return reply, realError(r.Method, err)
}

// call runs a typed userauth read with the current session.
func realCall[T any](ctx context.Context, c *realConn, m string, f func(userauth.Client, access.Session) (T, error)) (T, error) {
	var zero T
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return zero, err
	}
	defer done()
	v, err := f(c.c, s)
	if err != nil {
		return zero, realError(m, err)
	}
	return v, nil
}

func missingReply(m string) error { return fail(m, CodeUnknown, "reply without "+m) }

// --- account ---

func (c *realConn) UserCredentials(ctx context.Context, username string) (User, error) {
	const m = "user-credentials"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.UserCredentials(ctx, c.peer, s, username)
	})
	if err != nil {
		return User{}, err
	}
	if reply.CredentialUser == nil {
		return User{}, missingReply(m)
	}
	return *reply.CredentialUser, nil
}

func (c *realConn) OwnCredentials(ctx context.Context) (PublicUser, error) {
	const m = "my-credentials"
	reply, err := c.read(ctx, userauth.Request{Method: m})
	if err != nil {
		return PublicUser{}, err
	}
	if reply.SelfCredentials == nil {
		return PublicUser{}, missingReply(m)
	}
	return *reply.SelfCredentials, nil
}

func (c *realConn) Users(ctx context.Context, after string) (Page[PublicUser], error) {
	reply, err := c.read(ctx, userauth.Request{Method: "users", After: after})
	if err != nil {
		return Page[PublicUser]{}, err
	}
	return Page[PublicUser]{Items: reply.Users, Next: reply.UsersNext, Revision: reply.UsersRevision}, nil
}

func (c *realConn) TenantMembers(ctx context.Context, tenant, after string) (Page[TenantMember], error) {
	reply, err := c.read(ctx, userauth.Request{Method: "tenant-members", Tenant: tenant, After: after})
	if err != nil {
		return Page[TenantMember]{}, err
	}
	return Page[TenantMember]{Items: reply.TenantMembers, Next: reply.TenantMembersNext, Revision: reply.TenantRevision, Collection: reply.TenantMembersRevision}, nil
}

func (c *realConn) NodeCLIPolicy(ctx context.Context) (NodeCLIPolicy, error) {
	const m = "node-cli-policy"
	reply, err := c.read(ctx, userauth.Request{Method: m})
	if err != nil {
		return NodeCLIPolicy{}, err
	}
	if reply.NodeCLI == nil {
		return NodeCLIPolicy{}, missingReply(m)
	}
	return *reply.NodeCLI, nil
}

func (c *realConn) TenantRetirement(ctx context.Context, tenant, after string) (TenantRetirement, error) {
	const m = "tenant-retirement"
	reply, err := c.read(ctx, userauth.Request{Method: m, Tenant: tenant, After: after})
	if err != nil {
		return TenantRetirement{}, err
	}
	if reply.TenantRetirement == nil {
		return TenantRetirement{}, missingReply(m)
	}
	return *reply.TenantRetirement, nil
}

// --- cluster / nodes ---

func (c *realConn) Members(ctx context.Context, after string) (MembersPage, error) {
	reply, err := realCall(ctx, c, "members", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.MemberPage(ctx, c.peer, s, after)
	})
	if err != nil {
		return MembersPage{}, err
	}
	// sfcd leaves ModuleEpoch out while it is still the first epoch
	// (userauth service: whoami and members set it only above 1).
	epoch := reply.ModuleEpoch
	if epoch == 0 {
		epoch = 1
	}
	return MembersPage{Entries: reply.Members, Nodes: reply.NodeLifecycle, Next: reply.MembersNext, RootRevision: reply.MembersRootRevision,
		NodeRuntimeRevision: reply.NodeRuntimeRevision, NodeOperationEpoch: reply.NodeOperationEpoch, NodeConfigurationIndex: reply.NodeConfigurationIndex,
		LedgerEpoch: epoch, NodeVoters: reply.NodeVoters, NodeQuorum: reply.NodeQuorum}, nil
}

func (c *realConn) NodeInvitation(ctx context.Context, node string) (membership.Invitation, error) {
	return realCall(ctx, c, "node-invitation", func(u userauth.Client, s access.Session) (membership.Invitation, error) {
		return u.NodeInvitation(ctx, c.peer, s, node)
	})
}

func (c *realConn) NodeSummary(ctx context.Context, tenant, node, after string) (NodeSummaryPage, error) {
	return realCall(ctx, c, "node-summary", func(u userauth.Client, s access.Session) (NodeSummaryPage, error) {
		return u.NodeSummary(ctx, c.peer, s, userauth.NodeObservationQuery{Tenant: tenant, Node: node, After: after})
	})
}

func (c *realConn) NodeDisks(ctx context.Context, tenant, node, after string) (NodeDisksPage, error) {
	return realCall(ctx, c, "node-disks", func(u userauth.Client, s access.Session) (NodeDisksPage, error) {
		return u.NodeDisks(ctx, c.peer, s, userauth.NodeObservationQuery{Tenant: tenant, Node: node, After: after})
	})
}

func (c *realConn) MeshLinks(ctx context.Context, tenant, node, after string) (MeshLinksPage, error) {
	return realCall(ctx, c, "mesh-links", func(u userauth.Client, s access.Session) (MeshLinksPage, error) {
		return u.MeshLinks(ctx, c.peer, s, userauth.NodeObservationQuery{Tenant: tenant, Node: node, After: after})
	})
}

func (c *realConn) NodeStorage(ctx context.Context, node, after string) (Page[StorageRoot], error) {
	reply, err := realCall(ctx, c, "node-storage", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.NodeStoragePage(ctx, c.peer, s, node, after)
	})
	if err != nil {
		return Page[StorageRoot]{}, err
	}
	return Page[StorageRoot]{Items: reply.NodeStorage, Next: reply.NodeStorageNext, Revision: reply.NodeStorageRootRevision}, nil
}

func (c *realConn) NodeStorageSpace(ctx context.Context, node, id string) (StorageSpace, error) {
	const m = "node-storage-space"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.NodeStorageSpace(ctx, c.peer, s, control.NodeStorageSelection{Node: node, ID: id})
	})
	if err != nil {
		return StorageSpace{}, err
	}
	if reply.NodeStorageSpace == nil {
		return StorageSpace{}, missingReply(m)
	}
	return StorageSpace{Space: *reply.NodeStorageSpace, ObservedIndex: reply.NodeStorageObservedIndex}, nil
}

func (c *realConn) TenantStoragePage(ctx context.Context, tenant, node, after string) (control.TenantStoragePage, error) {
	reply, err := realCall(ctx, c, "tenant-storage", func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.TenantStoragePage(ctx, c.peer, s, tenant, node, after)
	})
	if err != nil {
		return control.TenantStoragePage{}, err
	}
	return control.TenantStoragePage{Index: reply.TenantStorageViewIndex, RootRevision: reply.NodeStorageRootRevision, Revision: reply.NodeStorageRevision, Items: reply.TenantStorage, Next: reply.TenantStorageNext}, nil
}

// RaftStatus joins the node pages as `sfcli cluster status` does; a node
// list that changes between pages is CodeConflict.
func (c *realConn) RaftStatus(ctx context.Context) (RaftStatus, error) {
	const m = "raft-status"
	var status *RaftStatus
	after := ""
	for pages := 0; pages < 256; pages++ {
		reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
			return u.RaftStatusPage(ctx, c.peer, s, after)
		})
		if err != nil {
			return RaftStatus{}, err
		}
		if reply.RaftStatus == nil {
			return RaftStatus{}, missingReply(m)
		}
		if status == nil {
			status = reply.RaftStatus
		} else if reply.RaftStatus.NodesRootRevision != status.NodesRootRevision {
			return RaftStatus{}, fail(m, CodeConflict, "the node list changed while it was read")
		} else {
			status.Nodes = append(status.Nodes, reply.RaftStatus.Nodes...)
		}
		if after = reply.RaftStatus.NodesNext; after == "" {
			status.NodesNext = ""
			return *status, nil
		}
	}
	return RaftStatus{}, fail(m, CodeUnknown, "too many node pages")
}

func (c *realConn) Events(ctx context.Context, q EventQuery) (EventsPage, error) {
	return realCall(ctx, c, "events", func(u userauth.Client, s access.Session) (eventlog.Page, error) {
		return u.EventsPage(ctx, c.peer, s, q)
	})
}

// ServerVersion needs no login.
func (c *realConn) ServerVersion(ctx context.Context) (ServerVersion, error) {
	const m = "server-version"
	_, done, err := c.open(ctx, m, false)
	if err != nil {
		return ServerVersion{}, err
	}
	defer done()
	v, err := c.c.ServerVersion(ctx, c.peer)
	return v, realError(m, err)
}

// --- server shell ---

func (c *realConn) NodeShellPolicy(ctx context.Context) (NodeShellPolicy, error) {
	const m = "node-shell-policy"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.NodeShellPolicy(ctx, c.peer, s)
	})
	if err != nil {
		return NodeShellPolicy{}, err
	}
	return *reply.NodeShellPolicy, nil
}

func (c *realConn) NodeShellSessions(ctx context.Context, after string) (NodeShellSessionsPage, error) {
	return c.QueryNodeShellSessions(ctx, NodeShellSessionsQuery{After: after})
}

func (c *realConn) QueryNodeShellSessions(ctx context.Context, q NodeShellSessionsQuery) (NodeShellSessionsPage, error) {
	const m = "node-shell-sessions"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.NodeShellSessions(ctx, c.peer, s, q.After, control.NodeShellSessionsQuery{State: q.State, Node: q.Node})
	})
	if err != nil {
		return NodeShellSessionsPage{}, err
	}
	return *reply.NodeShellSessions, nil
}

// --- node lifecycle plans ---

func (c *realConn) PlanNodeRemoval(ctx context.Context, node string) (control.NodeRemovePlan, error) {
	return realCall(ctx, c, "node-remove-plan", func(u userauth.Client, s access.Session) (control.NodeRemovePlan, error) {
		return u.NodeRemovePlan(ctx, c.peer, s, node)
	})
}

func (c *realConn) PlanNodeDemotion(ctx context.Context, node string) (control.NodeVotingPlan, error) {
	return realCall(ctx, c, "node-demote-plan", func(u userauth.Client, s access.Session) (control.NodeVotingPlan, error) {
		return u.NodeDemotePlan(ctx, c.peer, s, node)
	})
}

func (c *realConn) PlanNodeDrain(ctx context.Context, q control.NodeDrainQuery) (control.NodeDrainPlan, error) {
	return realCall(ctx, c, "node-drain-plan", func(u userauth.Client, s access.Session) (control.NodeDrainPlan, error) {
		return u.NodeDrainPlan(ctx, c.peer, s, q)
	})
}

func (c *realConn) NodeDrainStatus(ctx context.Context, q control.NodeDrainQuery) (control.NodeDrainStatus, error) {
	return realCall(ctx, c, "node-drain-status", func(u userauth.Client, s access.Session) (control.NodeDrainStatus, error) {
		return u.NodeDrainStatus(ctx, c.peer, s, q)
	})
}

func (c *realConn) PlanNodeForceRemoval(ctx context.Context, q control.NodeForceQuery) (control.NodeForcePlan, error) {
	return realCall(ctx, c, "node-force-remove-plan", func(u userauth.Client, s access.Session) (control.NodeForcePlan, error) {
		return u.NodeForceRemovePlan(ctx, c.peer, s, q)
	})
}

func (c *realConn) ReadNodeDiagnostics(ctx context.Context, node string) (control.NodeDiagnosticsBundle, error) {
	return realCall(ctx, c, "node-diagnostics", func(u userauth.Client, s access.Session) (control.NodeDiagnosticsBundle, error) {
		return u.NodeDiagnostics(ctx, c.peer, s, node)
	})
}

func (c *realConn) NodeDisk(ctx context.Context, op control.NodeDiskOp) (control.NodeDiskResult, error) {
	return realCall(ctx, c, "node-disk", func(u userauth.Client, s access.Session) (control.NodeDiskResult, error) {
		return u.NodeDisk(ctx, c.peer, s, op)
	})
}

func (c *realConn) NodeFirewall(ctx context.Context, op control.NodeFirewallOp) (control.NodeFirewallResult, error) {
	return realCall(ctx, c, "node-firewall", func(u userauth.Client, s access.Session) (control.NodeFirewallResult, error) {
		return u.NodeFirewall(ctx, c.peer, s, op)
	})
}

func (c *realConn) ClusterFirewall(ctx context.Context) (control.ClusterFirewallView, error) {
	return realCall(ctx, c, "cluster-firewall", func(u userauth.Client, s access.Session) (control.ClusterFirewallView, error) {
		return u.ClusterFirewall(ctx, c.peer, s)
	})
}

// --- maintenance plans ---

func (c *realConn) PlanTunnelReconnect(ctx context.Context, node, peer string) (control.TunnelPlan, error) {
	return realCall(ctx, c, "tunnel-reconnect-plan", func(u userauth.Client, s access.Session) (control.TunnelPlan, error) {
		return u.TunnelReconnectPlan(ctx, c.peer, s, node, peer)
	})
}

func (c *realConn) TunnelReconnectStatus(ctx context.Context, operation string) (control.TunnelStatus, error) {
	return realCall(ctx, c, "tunnel-reconnect-status", func(u userauth.Client, s access.Session) (control.TunnelStatus, error) {
		return u.TunnelReconnectStatus(ctx, c.peer, s, operation)
	})
}

func (c *realConn) RaftCompactPlan(ctx context.Context, sel CompactSelection, after string) (CompactPlanPage, error) {
	return realCall(ctx, c, "raft-compact-plan", func(u userauth.Client, s access.Session) (CompactPlanPage, error) {
		return u.CompactPlanPage(ctx, c.peer, s, userauth.CompactPlanQuery{Selection: sel, After: after})
	})
}

func (c *realConn) RaftCompactStatus(ctx context.Context, operation, after string) (CompactStatusPage, error) {
	return realCall(ctx, c, "raft-compact-status", func(u userauth.Client, s access.Session) (CompactStatusPage, error) {
		return u.CompactStatus(ctx, c.peer, s, userauth.CompactStatusQuery{Operation: operation, After: after})
	})
}

func (c *realConn) ImageCachePlan(ctx context.Context, q ImageCacheQuery) (ImageCachePlan, error) {
	const m = "image-cache-plan"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.QueryImageCache(ctx, c.peer, s, true, q)
	})
	if err != nil {
		return ImageCachePlan{}, err
	}
	if reply.ImageCachePlan == nil {
		return ImageCachePlan{}, missingReply(m)
	}
	return *reply.ImageCachePlan, nil
}

func (c *realConn) ImageCacheStatus(ctx context.Context, operation string) (ImageCacheStatus, error) {
	const m = "image-cache-status"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
		return u.QueryImageCache(ctx, c.peer, s, false, imagecache.Query{Operation: operation})
	})
	if err != nil {
		return ImageCacheStatus{}, err
	}
	if reply.ImageCacheStatus == nil {
		return ImageCacheStatus{}, missingReply(m)
	}
	return *reply.ImageCacheStatus, nil
}

func (c *realConn) PublicRead(ctx context.Context, method, tenant string, q control.PublicReadQuery, after string) (control.PublicReadPage, error) {
	return realCall(ctx, c, method, func(u userauth.Client, s access.Session) (control.PublicReadPage, error) {
		return u.PublicRead(ctx, c.peer, s, method, tenant, q, after)
	})
}

// AccountScope reads the account's ceiling and key-only flag from its
// record: the caller's own through my-credentials, another account's from
// the users list (system administrator; sfcd refuses anyone else).
func (c *realConn) AccountScope(ctx context.Context, user string) (AccountScope, error) {
	if s, ok := c.Session(); ok && s.User == user {
		u, err := c.OwnCredentials(ctx)
		if err != nil {
			return AccountScope{}, err
		}
		return accountScopeOf(u.ID, u.Operations, u.AutomationOnly, u.Revision), nil
	}
	for after := ""; ; {
		p, err := c.Users(ctx, after)
		if err != nil {
			return AccountScope{}, err
		}
		for _, u := range p.Items {
			if u.ID == user {
				return accountScopeOf(u.ID, u.Operations, u.AutomationOnly, u.Revision), nil
			}
		}
		if p.Next == "" || p.Next == after {
			return AccountScope{}, fail("account-scope", CodeMissing, "")
		}
		after = p.Next
	}
}
