// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/eventlog"
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
	return realCall(ctx, c, "user-credentials", func(u userauth.Client, s access.Session) (User, error) {
		return u.UserCredentials(ctx, c.peer, s, username)
	})
}

func (c *realConn) OwnCredentials(ctx context.Context) (PublicUser, error) {
	return realCall(ctx, c, "my-credentials", func(u userauth.Client, s access.Session) (PublicUser, error) {
		return u.MyCredentials(ctx, c.peer, s)
	})
}

func (c *realConn) Users(ctx context.Context, after string) (Page[PublicUser], error) {
	return realCall(ctx, c, "users", func(u userauth.Client, s access.Session) (Page[PublicUser], error) {
		r, err := u.Users(ctx, c.peer, s, after)
		return Page[PublicUser]{Items: r.Users, Next: r.Next, Revision: r.Revision}, err
	})
}

func (c *realConn) TenantMembers(ctx context.Context, tenant, after string) (Page[TenantMember], error) {
	return realCall(ctx, c, "tenant-members", func(u userauth.Client, s access.Session) (Page[TenantMember], error) {
		r, err := u.TenantMembers(ctx, c.peer, s, tenant, after)
		return Page[TenantMember]{Items: r.Members, Next: r.Next, Revision: r.TenantRevision, Collection: r.Revision}, err
	})
}

func (c *realConn) NodeCLIPolicy(ctx context.Context) (NodeCLIPolicy, error) {
	return realCall(ctx, c, "node-cli-policy", func(u userauth.Client, s access.Session) (NodeCLIPolicy, error) {
		return u.NodeCLIPolicy(ctx, c.peer, s)
	})
}

func (c *realConn) TenantRetirement(ctx context.Context, tenant, after string) (TenantRetirement, error) {
	return realCall(ctx, c, "tenant-retirement", func(u userauth.Client, s access.Session) (TenantRetirement, error) {
		return u.TenantRetirement(ctx, c.peer, s, tenant, after)
	})
}

// --- cluster / nodes ---

func (c *realConn) Members(ctx context.Context, after string) (MembersPage, error) {
	reply, err := realCall(ctx, c, "members", func(u userauth.Client, s access.Session) (userauth.MembersReply, error) {
		return u.MemberPage(ctx, c.peer, s, after)
	})
	if err != nil {
		return MembersPage{}, err
	}
	return MembersPage{Entries: reply.Members, Nodes: reply.Nodes, Next: reply.Next, RootRevision: reply.RootRevision,
		NodeRuntimeRevision: reply.RuntimeRevision, NodeOperationEpoch: reply.OperationEpoch, NodeConfigurationIndex: reply.ConfigurationIndex,
		NodeVoters: reply.Voters, NodeQuorum: reply.Quorum}, nil
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
	reply, err := realCall(ctx, c, "node-storage", func(u userauth.Client, s access.Session) (userauth.NodeStoragePage, error) {
		return u.NodeStoragePage(ctx, c.peer, s, node, after)
	})
	if err != nil {
		return Page[StorageRoot]{}, err
	}
	return Page[StorageRoot]{Items: reply.Items, Next: reply.Next, Revision: reply.RootRevision}, nil
}

func (c *realConn) NodeStorageSpace(ctx context.Context, node, id string) (StorageSpace, error) {
	const m = "node-storage-space"
	reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.NodeStorageSpaceReply, error) {
		return u.NodeStorageSpace(ctx, c.peer, s, control.NodeStorageSelection{Node: node, ID: id})
	})
	if err != nil {
		return StorageSpace{}, err
	}
	return StorageSpace{Space: reply.Space, ObservedIndex: reply.Index}, nil
}

func (c *realConn) TenantStoragePage(ctx context.Context, tenant, node, after string) (control.TenantStoragePage, error) {
	return realCall(ctx, c, "tenant-storage", func(u userauth.Client, s access.Session) (control.TenantStoragePage, error) {
		return u.TenantStoragePage(ctx, c.peer, s, tenant, node, after)
	})
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
	return realCall(ctx, c, m, func(u userauth.Client, s access.Session) (NodeShellPolicy, error) {
		return u.NodeShellPolicy(ctx, c.peer, s)
	})
}

func (c *realConn) NodeShellSessions(ctx context.Context, after string) (NodeShellSessionsPage, error) {
	return c.QueryNodeShellSessions(ctx, NodeShellSessionsQuery{After: after})
}

func (c *realConn) QueryNodeShellSessions(ctx context.Context, q NodeShellSessionsQuery) (NodeShellSessionsPage, error) {
	const m = "node-shell-sessions"
	return realCall(ctx, c, m, func(u userauth.Client, s access.Session) (NodeShellSessionsPage, error) {
		return u.NodeShellSessions(ctx, c.peer, s, q.After, control.NodeShellSessionsQuery{State: q.State, Node: q.Node})
	})
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
		return u.NodeDiagnostics(ctx, c.peer, s, node, 0)
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
	return realCall(ctx, c, "image-cache-plan", func(u userauth.Client, s access.Session) (ImageCachePlan, error) {
		return u.PlanImageCache(ctx, c.peer, s, q)
	})
}

func (c *realConn) ImageCacheStatus(ctx context.Context, operation string) (ImageCacheStatus, error) {
	return realCall(ctx, c, "image-cache-status", func(u userauth.Client, s access.Session) (ImageCacheStatus, error) {
		return u.ImageCacheStatus(ctx, c.peer, s, operation)
	})
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
