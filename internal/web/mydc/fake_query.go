// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/observability"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func paginate[T any](items []T, key func(T) string, after string, size int, rev uint64) Page[T] {
	sorted := append([]T(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool { return key(sorted[i]) < key(sorted[j]) })
	p := Page[T]{Revision: rev}
	for _, it := range sorted {
		if key(it) <= after {
			continue
		}
		if len(p.Items) == size {
			p.Next = key(p.Items[len(p.Items)-1])
			break
		}
		p.Items = append(p.Items, it)
	}
	return p
}

func checkAfter(m, after string) error {
	if len(after) > 512 {
		return fail(m, CodeInvalid, "after too long")
	}
	return nil
}

// lockSession runs the common checks and returns the caller's user ID.
func (c *fakeConn) lockSession(ctx context.Context, m string) (string, error) {
	c.f.mu.Lock()
	if err := c.begin(ctx, m, true); err != nil {
		c.f.mu.Unlock()
		return "", err
	}
	return c.session.User, nil
}

func (c *fakeConn) unlock() { c.f.mu.Unlock() }

func (c *fakeConn) Whoami(ctx context.Context) (Whoami, error) {
	user, err := c.lockSession(ctx, "whoami")
	if err != nil {
		return Whoami{}, err
	}
	defer c.unlock()
	u := c.f.w.users[user].rec
	return Whoami{User: UserView{ID: u.ID, Username: u.Username, Revision: u.Revision, SystemAdmin: u.SystemAdmin},
		RootRevision: c.f.w.catalogRoot(), LedgerRootRevision: c.f.w.keyRoot(control.StorageKey), LedgerEpoch: c.f.w.ledgerEpoch, Session: *c.session, Roots: c.f.w.rootsView()}, nil
}

func (c *fakeConn) Tenants(ctx context.Context) ([]TenantView, error) {
	user, err := c.lockSession(ctx, "tenants")
	if err != nil {
		return nil, err
	}
	defer c.unlock()
	w := c.f.w
	var out []TenantView
	for _, t := range sortedKeys(w.tenants) {
		r, ok := w.role(user, t)
		if !ok && w.admin(user) {
			r, ok = RoleManager, true
		}
		if ok {
			out = append(out, TenantView{ID: t, Revision: w.tenantRev[t], Role: r, AllowedNodes: w.allowedNodes(t)})
		}
	}
	return out, nil
}

func (c *fakeConn) SelectTenant(ctx context.Context, tenant string) (TenantView, error) {
	const m = "select-tenant"
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return TenantView{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canRead(user, tenant) {
		return TenantView{}, fail(m, CodeDenied, "")
	}
	r, ok := w.role(user, tenant)
	if !ok {
		r = RoleManager
	}
	return TenantView{ID: tenant, Revision: w.tenantRev[tenant], Role: r, AllowedNodes: w.allowedNodes(tenant)}, nil
}

// allowedNodes: REQ-32 as mydcd returns it on select-tenant
// (TenantAllowedNodes) and on each tenants row (AllowedNodes): the tenant's
// allowed servers the caller may read, never nil.
func (w *world) allowedNodes(tenant string) []string {
	nodes := slices.Clone(w.tenantNodes[tenant])
	slices.Sort(nodes)
	if nodes == nil {
		nodes = []string{}
	}
	return nodes
}

// scheduling: the members row's NodeLifecycle.Scheduling.
func (m FixtureMember) scheduling() membership.CordonView {
	v := membership.CordonView{Enabled: m.Cordoned, Revision: m.Revision}
	if m.Cordoned {
		v.CordonedBy, v.Reason = m.CordonedBy, m.CordonReason
		if m.CordonedAt != nil {
			v.CordonedAt = m.CordonedAt.UTC().Format(time.RFC3339)
		}
	}
	return v
}

func (c *fakeConn) adminOnly(ctx context.Context, m string) error {
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return err
	}
	if !c.f.w.admin(user) {
		c.unlock()
		return fail(m, CodeDenied, "")
	}
	return nil
}

func (c *fakeConn) UserCredentials(ctx context.Context, username string) (User, error) {
	const m = "user-credentials"
	if err := c.adminOnly(ctx, m); err != nil {
		return User{}, err
	}
	defer c.unlock()
	u := c.f.w.byName(username)
	if u == nil {
		return User{}, fail(m, CodeMissing, "")
	}
	return cloneUser(u.rec), nil
}

func (c *fakeConn) OwnCredentials(ctx context.Context) (PublicUser, error) {
	user, err := c.lockSession(ctx, "own-credentials")
	if err != nil {
		return PublicUser{}, err
	}
	defer c.unlock()
	return access.PublicUserOf(c.f.w.users[user].rec), nil
}

func cloneUser(u User) User {
	u.Credentials = append([]Credential(nil), u.Credentials...)
	u.Operations = slices.Clone(u.Operations)
	return u
}

func (c *fakeConn) Users(ctx context.Context, after string) (Page[PublicUser], error) {
	const m = "users"
	if err := checkAfter(m, after); err != nil {
		return Page[PublicUser]{}, err
	}
	if err := c.adminOnly(ctx, m); err != nil {
		return Page[PublicUser]{}, err
	}
	defer c.unlock()
	var all []PublicUser
	for _, u := range c.f.w.users {
		all = append(all, access.PublicUserOf(u.rec))
	}
	return paginate(all, func(u PublicUser) string { return u.Username }, after, c.f.pageSize, c.f.w.root), nil
}

func (c *fakeConn) TenantMembers(ctx context.Context, tenant, after string) (Page[TenantMember], error) {
	const m = "tenant-members"
	if err := checkAfter(m, after); err != nil {
		return Page[TenantMember]{}, err
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return Page[TenantMember]{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.canManage(user, tenant) {
		return Page[TenantMember]{}, fail(m, CodeDenied, "")
	}
	var all []TenantMember
	for id, r := range w.tenants[tenant] {
		u := w.users[id]
		if u == nil {
			continue
		}
		// The fake keeps one revision per tenant, not per membership, and
		// does not list system administrators implicitly or compute
		// Actions (mydcd does).
		all = append(all, TenantMember{User: id, Username: u.rec.Username, Role: r, Revision: w.tenantRev[tenant], Enabled: true, AccountEnabled: u.rec.Enabled, Actions: []access.Action{}})
	}
	p := paginate(all, func(t TenantMember) string { return t.Username }, after, c.f.pageSize, w.tenantRev[tenant])
	p.Collection = w.keyRoot(control.CatalogKey)
	return p, nil
}

func (c *fakeConn) NodeCLIPolicy(ctx context.Context) (NodeCLIPolicy, error) {
	if err := c.adminOnly(ctx, "node-cli-policy"); err != nil {
		return NodeCLIPolicy{}, err
	}
	defer c.unlock()
	return c.f.w.nodeCLI, nil
}

func (c *fakeConn) TenantRetirement(ctx context.Context, tenant, after string) (TenantRetirement, error) {
	const m = "tenant-retirement"
	if err := c.adminOnly(ctx, m); err != nil {
		return TenantRetirement{}, err
	}
	defer c.unlock()
	if _, ok := c.f.w.tenants[tenant]; !ok {
		return TenantRetirement{}, fail(m, CodeMissing, "")
	}
	w := c.f.w
	v := TenantRetirement{Schema: 1, Index: w.root, RootRevision: w.root, Remaining: []access.RetirementTarget{},
		Tenant: access.Tenant{ID: tenant, Revision: w.tenantRev[tenant], Enabled: true, Phase: access.TenantActive, AllowedNodes: slices.Clone(w.tenantNodes[tenant])}}
	switch op, ok := w.retiring[tenant]; {
	case w.retired[tenant]:
		v.Tenant.Phase = access.TenantDeleted
	case ok:
		// node reports are not modeled: every owner has closed at once
		v.Tenant.Phase = access.TenantRetiring
		v.Tenant.Retirement = &access.TenantRetirement{Cluster: w.cluster, Operation: op}
		v.OwnerCount = len(w.tenantNodes[tenant])
		v.ClosedOwners = v.OwnerCount
		for _, r := range w.retirementRemaining(tenant) {
			kind, id, _ := strings.Cut(r, "/")
			v.Remaining = append(v.Remaining, access.RetirementTarget{Tenant: tenant, Kind: kind, ID: id, Operation: op})
		}
		v.RemainingCount, v.TargetCount = len(v.Remaining), len(v.Remaining)
	}
	return v, nil
}

// --- cluster / nodes ---

func (c *fakeConn) Members(ctx context.Context, after string) (MembersPage, error) {
	const m = "members"
	if err := checkAfter(m, after); err != nil {
		return MembersPage{}, err
	}
	if err := c.adminOnly(ctx, m); err != nil {
		return MembersPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	voters := 0
	for _, n := range w.members {
		if n.Voter && n.Phase != NodePhaseRemoved {
			voters++
		}
	}
	pg := paginate(w.members, func(n FixtureMember) string { return n.ID }, after, c.f.pageSize, w.root)
	out := MembersPage{
		Entries: []membership.Entry{}, Next: pg.Next, RootRevision: w.root,
		NodeRuntimeRevision: w.root, NodeOperationEpoch: fakeNodeEpoch, NodeConfigurationIndex: w.raft.ConfigurationIndex, LedgerEpoch: w.ledgerEpoch,
		NodeVoters: voters, NodeQuorum: voters/2 + 1,
	}
	for _, n := range pg.Items {
		e, v, ok := n.real()
		out.Entries = append(out.Entries, e)
		if ok {
			out.Nodes = append(out.Nodes, v)
		}
	}
	return out, nil
}

// real: the fake member as mydcd's membership entry and, once the server
// has joined (not pending), its lifecycle row. The fake keeps one revision
// a server, so the entry, lifecycle and cordon revisions are the same.
func (m FixtureMember) real() (membership.Entry, membership.NodeView, bool) {
	join := m.Join
	switch {
	case join != "":
	case m.Phase == NodePhasePending:
		join = JoinInvited
	default:
		join = JoinActive
	}
	e := membership.Entry{Peer: config.Peer{ID: m.ID, Key: m.Key, Endpoint: m.Endpoint, Voter: m.Voter}, JoinID: m.JoinID, Revision: m.Revision, Phase: membership.Phase(join)}
	if m.Phase == NodePhasePending {
		return e, membership.NodeView{}, false
	}
	var key [32]byte
	_, _ = hex.Decode(key[:], []byte(m.Key))
	n := lifecycle.Node{Member: lifecycle.Member{ID: m.ID, Key: key, Voter: m.Voter}, Generation: 1, Revision: m.Revision, Phase: lifecycle.Phase(m.Phase)}
	if m.PendingOperation != "" {
		n.Pending = &lifecycle.Operation{ID: m.PendingOperation, Generation: 1, Revision: m.Revision, Epoch: fakeNodeEpoch}
	}
	return e, membership.NodeView{Identity: m.Identity, Scheduling: m.scheduling(), Node: n, AdmitsWork: m.AdmitsWork}, true
}

// visibleNodes returns the nodes the caller may see for tenant ("" = all for
// a system admin) and the tenants whose tasks count.
func (c *fakeConn) visibleNodes(m, user, tenant string) (map[string]bool, map[string]bool, error) {
	w := c.f.w
	nodes, tenants := map[string]bool{}, map[string]bool{}
	if tenant == "" {
		if !w.admin(user) {
			return nil, nil, fail(m, CodeDenied, "tenant required")
		}
		for _, n := range w.members {
			nodes[n.ID] = true
		}
		for t := range w.tenants {
			tenants[t] = true
		}
		return nodes, tenants, nil
	}
	if !w.canRead(user, tenant) {
		return nil, nil, fail(m, CodeDenied, "")
	}
	for _, n := range w.tenantNodes[tenant] {
		nodes[n] = true
	}
	tenants[tenant] = true
	return nodes, tenants, nil
}

func (c *fakeConn) NodeSummary(ctx context.Context, tenant, node, after string) (NodeSummaryPage, error) {
	const m = "node-summary"
	if err := checkAfter(m, after); err != nil {
		return NodeSummaryPage{}, err
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return NodeSummaryPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	nodes, tenants, err := c.visibleNodes(m, user, tenant)
	if err != nil {
		return NodeSummaryPage{}, err
	}
	// containers per node and tenant (only tenants the caller may read)
	counts := map[string]map[string]uint64{}
	for _, a := range w.apps {
		if !tenants[a.view.Tenant] || a.view.Retiring {
			continue
		}
		for _, t := range a.tasks {
			if counts[t.Node] == nil {
				counts[t.Node] = map[string]uint64{}
			}
			counts[t.Node][a.view.Tenant]++
		}
	}
	now := uint64(c.f.now().UnixMilli())
	rows := []NodeSummaryView{}
	for _, s := range w.summaries {
		if !nodes[s.Node] || node != "" && s.Node != node {
			continue
		}
		rows = append(rows, w.summaryRow(s, tenant, counts[s.Node], now))
	}
	p := paginate(rows, func(r NodeSummaryView) string { return r.Node }, after, c.f.pageSize, w.root)
	return NodeSummaryPage{Nodes: append([]NodeSummaryView{}, p.Items...), Next: p.Next, RootRevision: w.keyRoot(control.MembersKey), CanAcceptChanges: true}, nil
}

// summaryRow: the real node-summary row of a seed summary (seconds → Unix
// ms). tenant "" is the cluster-wide admin view (Admin: host, disks, role,
// per-tenant usage); otherwise only that tenant's usage. The seed status
// gives the state (degraded/isolated → unready); a member not active
// gives its phase, as mydcd does.
func (w *world) summaryRow(s FixtureNodeSummary, tenant string, counts map[string]uint64, now uint64) NodeSummaryView {
	at := uint64(max(s.ObservedAt, 0)) * 1000
	limit := uint64(w.observeLimit)
	row := NodeSummaryView{Node: s.Node, State: s.Status, ObserveLimitSeconds: limit, ObservationMaxAge: limit * 1000, ObservedAt: at,
		Stale: at == 0 || now < at || now-at > limit*1000}
	switch s.Status {
	case "ready":
		row.Ready = !row.Stale
	case "degraded", "isolated":
		row.State = "unready"
	}
	if i := w.memberIndex(s.Node); i >= 0 {
		mb := w.members[i]
		row.Scheduling = mb.scheduling()
		row.CordonedBy, row.CordonedAt = row.Scheduling.CordonedBy, row.Scheduling.CordonedAt
		if mb.Phase != NodePhaseActive && s.Status != "removed" {
			row.State, row.Ready = string(mb.Phase), false
		}
	}
	if tenant != "" {
		n := counts[tenant]
		row.Usage = &NodeUsageView{Tenant: tenant, Node: s.Node, Containers: &n, ObservedAt: at, Stale: row.Stale, Complete: true}
		return row
	}
	adm := NodeAdminView{Role: s.Role, Address: "", Tenants: []NodeUsageView{}, DisksComplete: true}
	if i := w.memberIndex(s.Node); i >= 0 {
		adm.Address = w.members[i].Endpoint
	}
	if adm.Role == "removed" {
		adm.Role = "non-voter"
	}
	if s.MemTotal > 0 {
		const capacity = 8_000_000_000 // 8 logical processors, nanocores
		cpu, used, total := uint64(s.CPUPercent*capacity/100), s.MemUsed, s.MemTotal
		adm.Host = &observability.Host{RuntimeEnabled: true, Version: "fake", CPUCapacity: capacity, CPUUsed: &cpu, MemoryTotal: &total, MemoryUsed: &used, ModuleReady: true}
		adm.Version = "fake"
		du, dt := s.DiskUsed, s.DiskTotal
		adm.DiskUsed, adm.DiskTotal = &du, &dt
	}
	ts := make([]string, 0, len(counts))
	for t := range counts {
		ts = append(ts, t)
	}
	slices.Sort(ts)
	for _, t := range ts {
		n := counts[t]
		adm.Tenants = append(adm.Tenants, NodeUsageView{Tenant: t, Node: s.Node, Containers: &n, ObservedAt: at, Stale: row.Stale, Complete: true})
	}
	row.Admin = &adm
	return row
}

func (c *fakeConn) NodeStorage(ctx context.Context, node, after string) (Page[StorageRoot], error) {
	const m = "node-storage"
	if err := checkAfter(m, after); err != nil {
		return Page[StorageRoot]{}, err
	}
	if err := c.adminOnly(ctx, m); err != nil {
		return Page[StorageRoot]{}, err
	}
	defer c.unlock()
	w := c.f.w
	var all []StorageRoot
	for _, r := range w.nodeStorage {
		if node == "" || r.Node == node {
			all = append(all, w.storageRoot(r))
		}
	}
	return paginate(all, func(r StorageRoot) string { return r.Definition.Node + "/" + r.Definition.ID }, after, c.f.pageSize, w.keyRoot(control.NodeStorageKey)), nil
}

// storageRoot: the real node-storage row of a seed root. The fake's
// attestation and closure carry no node signature.
func (w *world) storageRoot(r FixtureStorageRoot) StorageRoot {
	ref := w.storageRef(r)
	out := StorageRoot{Definition: nodestorage.Definition{Node: r.Node, Key: ref.Key, ID: r.ID, Path: r.Path, Tenants: slices.Clone(r.Tenants), MaxVolumes: r.MaxVolumes},
		Generation: r.Generation, Revision: r.Revision, Draining: r.Draining}
	if out.Definition.Tenants == nil {
		out.Definition.Tenants = []string{}
	}
	if r.Attested {
		out.Attestation = &nodestorage.RootFact{Schema: 1, Root: ref, Directory: storageDirectory(r)}
	}
	if r.Closed {
		out.Closed = &nodestorage.RootClosed{Schema: 1, Root: ref, NoUsers: true, NoPending: true}
	}
	return out
}

func storageDirectory(r FixtureStorageRoot) nodestorage.Directory {
	return nodestorage.Directory{Filesystem: "ext4", FilesystemPath: r.Path}
}

func (c *fakeConn) NodeStorageSpace(ctx context.Context, node, id string) (StorageSpace, error) {
	const m = "node-storage-space"
	if err := c.adminOnly(ctx, m); err != nil {
		return StorageSpace{}, err
	}
	defer c.unlock()
	w := c.f.w
	i := slices.IndexFunc(w.nodeStorage, func(r FixtureStorageRoot) bool { return r.Node == node && r.ID == id })
	if i < 0 {
		return StorageSpace{}, fail(m, CodeMissing, "")
	}
	r := w.nodeStorage[i]
	for _, d := range w.disks {
		if d.Node == node && d.StorageRootID == id {
			return StorageSpace{Space: nodestorage.Space{Root: w.storageRef(r), Directory: storageDirectory(r), Total: d.Total, Free: d.Free, Available: d.Free}, ObservedIndex: w.root}, nil
		}
	}
	return StorageSpace{}, fail(m, CodeUnavailable, "no fresh observation")
}

func (c *fakeConn) NodeDisks(ctx context.Context, tenant, node, after string) (NodeDisksPage, error) {
	const m = "node-disks"
	if err := checkAfter(m, after); err != nil {
		return NodeDisksPage{}, err
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return NodeDisksPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	// Cluster-wide needs a system admin; a tenant view needs ManageVolumes
	// and shows only storage roots that allow the tenant (no device names).
	admin := tenant == ""
	if admin && !w.admin(user) || !admin && !w.canManage(user, tenant) {
		return NodeDisksPage{}, fail(m, CodeDenied, "")
	}
	allowed := map[string]bool{}
	for _, r := range w.nodeStorage {
		if slices.Contains(r.Tenants, tenant) {
			allowed[r.Node+"/"+r.ID] = true
		}
	}
	now := uint64(c.f.now().UnixMilli())
	rows := []NodeDiskView{}
	for _, d := range w.disks {
		if node != "" && d.Node != node || !admin && (d.StorageRootID == "" || !allowed[d.Node+"/"+d.StorageRootID]) {
			continue
		}
		at := uint64(d.ObservedAt) * 1000
		total, used, free, inodes := d.Total, d.Used, d.Free, d.InodesFree
		row := NodeDiskView{Node: d.Node, ID: d.Device, Mount: d.Mount, Filesystem: d.FSType, State: "observed",
			Purposes: []string{d.Purpose}, StorageRoots: []string{}, SourceCount: 1,
			Total: &total, Used: &used, Free: &free, Available: &free, InodesFree: &inodes,
			ObservedAt: at, ObservationMaxAge: observability.MaxAge, Stale: !observability.Fresh(at, now)}
		if admin {
			row.Device = d.Device
		}
		if d.StorageRootID != "" {
			row.StorageRoots = []string{d.StorageRootID}
		}
		rows = append(rows, row)
	}
	p := paginate(rows, func(r NodeDiskView) string { return r.Node + "/" + r.ID }, after, c.f.pageSize, w.root)
	return NodeDisksPage{Disks: append([]NodeDiskView{}, p.Items...), Next: p.Next, RootRevision: w.keyRoot(control.NodeStorageKey)}, nil
}

func (c *fakeConn) MeshLinks(ctx context.Context, tenant, node, after string) (MeshLinksPage, error) {
	const m = "mesh-links"
	if err := checkAfter(m, after); err != nil {
		return MeshLinksPage{}, err
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return MeshLinksPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	admin := tenant == ""
	if admin && !w.admin(user) || !admin && !w.canRead(user, tenant) {
		return MeshLinksPage{}, fail(m, CodeDenied, "")
	}
	nodes := map[string]bool{}
	for _, n := range w.tenantNodes[tenant] {
		nodes[n] = true
	}
	now := uint64(c.f.now().UnixMilli())
	rows := []MeshLinkView{}
	for _, l := range w.links {
		if !admin && (!nodes[l.NodeA] || !nodes[l.NodeB]) || node != "" && node != l.NodeA && node != l.NodeB {
			continue
		}
		a, b := min(l.NodeA, l.NodeB), max(l.NodeA, l.NodeB)
		at := uint64(l.ObservedAt) * 1000
		row := MeshLinkView{ID: observability.PairID(a, b), NodeA: a, NodeB: b, State: l.State, ObservationMaxAge: observability.MaxAge, Stale: true}
		if l.State != "pending" {
			row.ObservedAt, row.Stale = at, !observability.Fresh(at, now)
			if admin {
				peer := l.NodeB
				if l.ObservedBy == l.NodeB {
					peer = l.NodeA
				}
				obs := observability.Link{ID: row.ID, Peer: peer, State: l.State, Measurement: "wireguard",
					LastHandshakeAt: uint64(l.LastHandshakeAt) * 1000, LastChangeAt: uint64(l.LastChangeAt) * 1000}
				rtt, loss := l.RTTMillis, l.LossPercent
				obs.RTTMillis, obs.LossPct = &rtt, &loss
				row.Ends = []MeshLinkEnd{{ObservedBy: l.ObservedBy, Observation: obs, ObservedAt: at, Stale: row.Stale}}
			}
		}
		rows = append(rows, row)
	}
	p := paginate(rows, func(r MeshLinkView) string { return r.ID }, after, c.f.pageSize, w.root)
	return MeshLinksPage{Links: append([]MeshLinkView{}, p.Items...), Next: p.Next, RootRevision: w.keyRoot(control.MembersKey)}, nil
}

func (c *fakeConn) RaftStatus(ctx context.Context) (RaftStatus, error) {
	if err := c.adminOnly(ctx, "raft-status"); err != nil {
		return RaftStatus{}, err
	}
	defer c.unlock()
	r := c.f.w.raft
	r.Servers = append([]FixtureRaftServer(nil), r.Servers...)
	r.Elections = append([]FixtureRaftElection(nil), r.Elections...)
	if lc := r.LastCompaction; lc != nil {
		cp := *lc
		cp.Results = append([]FixtureRaftCompactResult(nil), lc.Results...)
		r.LastCompaction = &cp
	}
	commit := max(r.CommitIndex, c.f.w.root)
	for i := range r.Servers {
		s := &r.Servers[i]
		if s.SnapshotIndex == 0 {
			s.SnapshotIndex = r.LastSnapshotIndex
		}
		if s.LogEntries == 0 {
			s.LogEntries = commit - min(commit, s.SnapshotIndex)
		}
		if s.LogFileBytes == 0 {
			s.LogFileBytes = s.LogBytes
		}
	}
	r.CommitIndex = max(r.CommitIndex, c.f.w.root)
	return raftStatusOf(r, uint64(c.f.now().UnixMilli())), nil
}

// fakeContactMaxAge: how old a leader contact may be for a voter to count
// as responding (the fake's value; mydcd reports its own).
const fakeContactMaxAge = 10_000

// raftStatusOf builds the real raft-status reply from the fake's seed
// (seconds → Unix ms). The seed's leader is the observing node.
func raftStatusOf(r FixtureRaft, now uint64) RaftStatus {
	ms := func(sec int64) uint64 { return uint64(max(sec, 0)) * 1000 }
	p := func(v uint64) *uint64 { return &v }
	st := RaftStatus{Leader: r.Leader, ObservedBy: r.Leader, Term: r.Term, CommitIndex: r.CommitIndex, ConfigurationIndex: r.ConfigurationIndex,
		ObservedAt: now, ContactMaxAge: fakeContactMaxAge, LocalLastAppliedAuthorization: true, Nodes: []RaftNodeStatus{}, Elections: []cluster.ElectionObservation{}}
	byNode := map[string]FixtureRaftCompactResult{}
	if lc := r.LastCompaction; lc != nil {
		for _, x := range lc.Results {
			byNode[x.Node] = x
		}
		// At: Unix seconds (the original's At), as mydcd's CompactSummary.
		sum := compactSummary(lc)
		st.LastManualCompact = &sum
	}
	for _, s := range r.Servers {
		row := RaftNodeStatus{Node: s.Node, Role: "follower", Term: r.Term, MatchIndex: p(s.MatchIndex), AppliedIndex: p(s.AppliedIndex),
			SnapshotIndex: p(s.SnapshotIndex), LogBytes: p(s.LogBytes), LogEntries: p(s.LogEntries), Lag: p(s.Lag),
			LastContact: ms(s.LastContactAt), ObservedAt: now}
		switch {
		case s.Suffrage != "voter":
			row.Role = "non-voter"
		case s.Node == r.Leader:
			row.Role = "leader"
		}
		fresh := row.LastContact <= now && now-row.LastContact <= fakeContactMaxAge
		row.Stale = !fresh
		if s.Suffrage == "voter" {
			st.Voters++
			if fresh {
				st.RespondingVoters++
			}
		}
		if s.Node == r.Leader {
			st.AppliedIndex = s.AppliedIndex
			st.Local = observability.Consensus{Role: "leader", Leader: r.Leader, Term: r.Term, LastIndex: r.CommitIndex, CommitIndex: r.CommitIndex, AppliedIndex: s.AppliedIndex,
				SnapshotKnown: true, SnapshotIndex: max(s.SnapshotIndex, r.LastSnapshotIndex), SnapshotAt: ms(r.LastSnapshotAt),
				LogKnown: true, LogEntries: s.LogEntries, LogBytesKnown: true, LogBytes: s.LogBytes, TrailingLogs: raftKeepEntries}
		}
		if x, ok := byNode[s.Node]; ok {
			row.LastManualCompact = &userauth.RaftCompactNode{Operation: r.LastCompaction.Operation, User: r.LastCompaction.By, State: x.State, Code: x.Error,
				At: uint64(max(r.LastCompaction.At, 0)), SnapshotIndex: x.SnapshotIndex, SnapshotBytes: x.SnapshotBytes,
				LogEntriesBefore: x.LogEntriesBefore, LogEntriesAfter: x.LogEntriesAfter, LogFileBytesBefore: x.LogFileBytes, LogFileBytesAfter: x.LogFileBytes,
				LogUsedBytesBefore: x.LogBytesBefore, LogUsedBytesAfter: x.LogBytesAfter, LogKnown: true, LogFileKnown: true, LogUsedKnown: true,
				DurationMillis: uint64(max(x.DurationMS, 0)), TargetMet: x.State == "done"}
		}
		st.Nodes = append(st.Nodes, row)
	}
	slices.SortFunc(st.Nodes, func(a, b RaftNodeStatus) int { return strings.Compare(a.Node, b.Node) })
	st.Quorum = st.Voters/2 + 1
	st.Stale = r.Stale || r.Leader == "" || st.RespondingVoters < st.Quorum
	for _, e := range r.Elections {
		st.Elections = append(st.Elections, cluster.ElectionObservation{Term: e.Term, Leader: e.Leader, Role: "leader", ElectedAt: ms(e.At), ObservedAt: ms(e.At), Reason: e.Reason})
	}
	return st
}

func (c *fakeConn) Events(ctx context.Context, q EventQuery) (EventsPage, error) {
	const m = "events"
	if !q.Valid() {
		return EventsPage{}, fail(m, CodeInvalid, "")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return EventsPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	if q.Tenant == "" && !w.admin(user) || q.Tenant != "" && !w.canRead(user, q.Tenant) {
		return EventsPage{}, fail(m, CodeDenied, "")
	}
	since := q.After
	if since != "" {
		seq, err := strconv.ParseUint(since, 10, 64)
		if err != nil {
			return EventsPage{}, fail(m, CodeInvalid, "cursor")
		}
		if seq < w.evFloor {
			return EventsPage{}, fail(m, CodeCursorExpired, "")
		}
	} else if w.evFloor > 0 {
		since = cursorOf(w.evFloor)
	}
	limit := q.Limit
	if limit == 0 {
		limit = 100
	}
	p := EventsPage{Schema: 1, Items: []EventItem{}, Cursor: cursorOf(w.evSeq)}
	for _, e := range w.events {
		if e.Cursor <= since || q.Tenant != "" && e.Tenant != q.Tenant || q.App != "" && e.App != q.App || q.Node != "" && e.Node != q.Node || q.Kind != "" && e.Kind != q.Kind {
			continue
		}
		if len(p.Items) == limit {
			p.Cursor, p.More = p.Items[len(p.Items)-1].Cursor, true
			break
		}
		p.Items = append(p.Items, eventItem(e))
	}
	return p, nil
}

// eventItem: the real events row of a seed event.
func eventItem(e FixtureEvent) EventItem {
	it := EventItem{ID: "ev-" + e.Cursor, Cursor: e.Cursor, SourceNode: e.Node, Event: eventlog.Event{Kind: e.Kind, Scope: e.Scope, At: uint64(max(e.Time, 0)) * 1000,
		Target: eventlog.Target{Tenant: e.Tenant, App: e.App, Node: e.Node, Network: e.Network, PairID: e.PairID},
		Detail: eventlog.Detail{Reason: e.Detail}}}
	// The seed's target text carries the task ("tenant/app/service/
	// instance") or a node filesystem ("node:mount").
	if parts := strings.Split(e.Target, "/"); len(parts) == 4 && e.Tenant != "" && parts[0] == e.Tenant && parts[1] == e.App {
		it.Target.Service, it.Target.Task = parts[2], parts[3]
	} else if node, fs, ok := strings.Cut(e.Target, ":"); ok && node == e.Node && e.Tenant == "" {
		it.Target.FilesystemID = fs
	}
	if cd := e.CD; cd != nil {
		d := &it.Detail
		d.CandidateID, d.Commit, d.Actor, d.Code = cd.CandidateID, cd.Commit, cd.Actor, cd.Code
		d.FromVersion, _ = strconv.ParseUint(cd.FromVersion, 10, 64)
		d.ToVersion, _ = strconv.ParseUint(cd.ToVersion, 10, 64)
		if cd.Reason != "" {
			d.Reason = cd.Reason
		}
	}
	if in := e.Ingress; in != nil {
		t := &it.Target
		t.Gateway, t.RouteID, t.Host, t.Prefix = in.Gateway, in.RouteID, in.Host, in.Prefix
		it.Detail.Value = uint64(max(in.Value, 0))
	}
	if by := e.ShellClosedBy; by != nil {
		it.Detail.ClosedBy = &eventlog.ActorIdentity{User: by.User, Username: by.Username}
	}
	return it
}

// --- tenant resources ---

// tenantRead checks Read on tenant; "" means cluster-wide (system admin).
func (c *fakeConn) tenantRead(ctx context.Context, m, tenant, after string) error {
	if err := checkAfter(m, after); err != nil {
		return err
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return err
	}
	w := c.f.w
	if tenant == "" && !w.admin(user) || tenant != "" && !w.canRead(user, tenant) {
		c.unlock()
		return fail(m, CodeDenied, "")
	}
	return nil
}

func filterTenant[T any](items []T, tenant string, of func(T) string) []T {
	var out []T
	for _, it := range items {
		if tenant == "" || of(it) == tenant {
			out = append(out, it)
		}
	}
	return out
}

func (c *fakeConn) Resources(ctx context.Context, tenant, after string) (Page[ResourceEntry], error) {
	if err := c.tenantRead(ctx, "resources", tenant, after); err != nil {
		return Page[ResourceEntry]{}, err
	}
	defer c.unlock()
	items := filterTenant(c.f.w.resources, tenant, func(r ResourceEntry) string { return r.Tenant })
	for i, r := range items {
		if r.Network != nil { // REQ-35 counts
			n := *r.Network
			n.Apps, n.Standalones = countUsers(c.f.w.networkUsers(r.Tenant, n.Name, ""))
			items[i].Network = &n
		}
	}
	items = append(items, c.f.w.routeEntries(tenant)...)
	p := paginate(items, func(r ResourceEntry) string { return r.Key }, after, c.f.pageSize, c.f.w.root)
	p.Collection = c.f.w.netRev
	return p, nil
}

func (c *fakeConn) Volumes(ctx context.Context, tenant, after string) (Page[VolumeView], error) {
	if err := c.tenantRead(ctx, "volumes", tenant, after); err != nil {
		return Page[VolumeView]{}, err
	}
	defer c.unlock()
	rows := filterTenant(c.f.w.volumes, tenant, func(v volumeRow) string { return v.Tenant })
	items := make([]VolumeView, len(rows))
	now := uint64(c.f.now().UnixMilli())
	for i, v := range rows {
		items[i] = c.f.w.volumeView(v, now)
	}
	return paginate(items, func(v VolumeView) string { return v.Key }, after, c.f.pageSize, c.f.w.root), nil
}

func (c *fakeConn) VolumeBackups(ctx context.Context, tenant, after string) (Page[VolumeBackupView], error) {
	if err := c.tenantRead(ctx, "volume-backups", tenant, after); err != nil {
		return Page[VolumeBackupView]{}, err
	}
	defer c.unlock()
	items := filterTenant(c.f.w.backups, tenant, func(v VolumeBackupView) string { return v.Tenant })
	return paginate(items, func(v VolumeBackupView) string { return v.Key }, after, c.f.pageSize, c.f.w.root), nil
}

func (c *fakeConn) Vault(ctx context.Context, tenant, after string) (Page[VaultView], error) {
	const m = "vault"
	if err := checkAfter(m, after); err != nil {
		return Page[VaultView]{}, err
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return Page[VaultView]{}, err
	}
	defer c.unlock()
	w := c.f.w
	// Vault metadata needs ManageSecrets (tenant manager) as in mydcd.
	if tenant == "" && !w.admin(user) || tenant != "" && !w.canManage(user, tenant) {
		return Page[VaultView]{}, fail(m, CodeDenied, "")
	}
	var items []VaultView // realm "" is the cluster Vault, not every realm
	for _, v := range w.vault {
		if v.Realm == tenant {
			items = append(items, v)
		}
	}
	p := paginate(items, func(v VaultView) string { return v.Realm + "/" + v.Path }, after, c.f.pageSize, w.root)
	p.Collection, p.ApprovalRevision = w.vaultRev[tenant], w.approvalRev
	return p, nil
}

func (c *fakeConn) Lifecycles(ctx context.Context, tenant, after string) (Page[LifecycleEntry], error) {
	if tenant == "" {
		return Page[LifecycleEntry]{}, fail("lifecycles", CodeInvalid, "tenant required")
	}
	if err := checkAfter("lifecycles", after); err != nil {
		return Page[LifecycleEntry]{}, err
	}
	user, err := c.lockSession(ctx, "lifecycles")
	if err != nil {
		return Page[LifecycleEntry]{}, err
	}
	defer c.unlock()
	// ManageServices (cleanup authority) as LifecyclePage.
	if !c.f.w.canManage(user, tenant) {
		return Page[LifecycleEntry]{}, fail("lifecycles", CodeDenied, "")
	}
	items := c.f.w.lifecycleEntries(tenant)
	return paginate(items, func(v LifecycleEntry) string { return v.Key }, after, c.f.pageSize, c.f.w.root), nil
}

func (c *fakeConn) Registries(ctx context.Context, tenant, after string) (Page[RegistryView], error) {
	if tenant == "" {
		return Page[RegistryView]{}, fail("registries", CodeInvalid, "tenant required")
	}
	if err := c.tenantRead(ctx, "registries", tenant, after); err != nil {
		return Page[RegistryView]{}, err
	}
	defer c.unlock()
	items := filterTenant(c.f.w.registries, tenant, func(v RegistryView) string { return v.Tenant })
	for i := range items {
		items[i].Maintenance = c.f.w.maintenanceSummary(tenant, items[i].ID)
	}
	return paginate(items, func(v RegistryView) string { return v.ID }, after, c.f.pageSize, c.f.w.root), nil
}

// --- apps ---

func (c *fakeConn) appRead(ctx context.Context, m, tenant string) error {
	if tenant == "" {
		return fail(m, CodeInvalid, "tenant required")
	}
	return c.tenantRead(ctx, m, tenant, "")
}

func (c *fakeConn) Apps(ctx context.Context, tenant, after string) (Page[AppView], error) {
	const m = "apps"
	if tenant == "" {
		return Page[AppView]{}, fail(m, CodeInvalid, "tenant required")
	}
	if err := c.tenantRead(ctx, m, tenant, after); err != nil {
		return Page[AppView]{}, err
	}
	defer c.unlock()
	var items []AppView
	for _, a := range c.f.w.apps {
		if a.view.Tenant == tenant {
			v := a.view
			v.CD = a.cdView()
			items = append(items, v)
		}
	}
	return paginate(items, func(v AppView) string { return v.App }, after, c.f.pageSize, c.f.w.root), nil
}

func (c *fakeConn) AppOperation(ctx context.Context, tenant, app, id string) (AppOperation, error) {
	const m = "app-operation"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return AppOperation{}, err
	}
	defer c.unlock()
	a := c.f.w.apps[tenant+"/"+app]
	if a == nil || a.ops[id] == nil {
		return AppOperation{}, fail(m, CodeMissing, "")
	}
	op := *a.ops[id]
	op.Steps = append([]string(nil), op.Steps...)
	return op, nil
}

func (c *fakeConn) AppUploads(ctx context.Context, tenant, after string) (Page[AppUploadView], error) {
	const m = "app-uploads"
	if tenant == "" {
		return Page[AppUploadView]{}, fail(m, CodeInvalid, "tenant required")
	}
	if err := c.tenantRead(ctx, m, tenant, after); err != nil {
		return Page[AppUploadView]{}, err
	}
	defer c.unlock()
	var items []AppUploadView
	for _, u := range c.f.w.uploads {
		if u.tenant == tenant {
			v := u.view
			v.Missing = u.missing()
			items = append(items, v)
		}
	}
	return paginate(items, func(v AppUploadView) string { return v.ID }, after, c.f.pageSize, c.f.w.root), nil
}

func (c *fakeConn) AppPlan(ctx context.Context, req AppPlanRequest) (AppPlan, error) {
	const m = "app-plan-stream"
	if len(req.Document) == 0 || len(req.Document) > 4<<20 {
		return AppPlan{}, &Error{Code: CodeInvalid, Method: m, InputCode: "APP_DOCUMENT_SIZE"}
	}
	if err := c.appRead(ctx, m, req.Tenant); err != nil {
		return AppPlan{}, err
	}
	defer c.unlock()
	if !c.f.w.canManage(c.session.User, req.Tenant) {
		return AppPlan{}, fail(m, CodeDenied, "deploy permission required")
	}
	if req.Move != nil {
		return c.f.w.movePlan(c.session.User, req, c.f.now().Unix())
	}
	if req.Standalone != nil {
		c.f.w.expireStandalones(c.f.now().Unix())
		return c.f.w.standaloneAppPlan(c.session.User, req)
	}
	return c.f.w.plan(req.Tenant, req.Document, req.Diff)
}

func (c *fakeConn) AppSource(ctx context.Context, tenant, app string, version uint64) (AppSource, error) {
	const m = "app-source"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return AppSource{}, err
	}
	defer c.unlock()
	a := c.f.w.apps[tenant+"/"+app]
	if a == nil || len(a.sources) == 0 {
		return AppSource{}, fail(m, CodeMissing, "")
	}
	if version == 0 {
		s, ok := a.running()
		if !ok {
			return AppSource{}, fail(m, CodeMissing, "app is down")
		}
		s.Document = append([]byte(nil), s.Document...)
		return s, nil
	}
	if version > uint64(len(a.sources)) {
		return AppSource{}, fail(m, CodeMissing, "")
	}
	s := a.sources[version-1]
	s.Document = append([]byte(nil), s.Document...)
	return s, nil
}

func (c *fakeConn) AppRevisions(ctx context.Context, tenant, app, after string) (Page[AppRevision], error) {
	const m = "app-revisions"
	if err := checkAfter(m, after); err != nil {
		return Page[AppRevision]{}, err
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return Page[AppRevision]{}, err
	}
	defer c.unlock()
	a := c.f.w.apps[tenant+"/"+app]
	if a == nil {
		return Page[AppRevision]{}, fail(m, CodeMissing, "")
	}
	var items []AppRevision
	for _, s := range a.sources {
		status := "succeeded"
		if op := a.ops[s.Operation]; op != nil {
			status = op.Status
		}
		items = append(items, AppRevision{Version: s.Version, Digest: s.Digest, Submitter: s.Submitter, Operation: s.Operation, Status: status, AcceptedAt: s.AcceptedAt, Kind: s.Kind})
	}
	return paginate(items, func(r AppRevision) string { return fmt.Sprintf("%020d", r.Version) }, after, c.f.pageSize, a.view.Revision), nil
}

func (c *fakeConn) Tasks(ctx context.Context, f TaskFilter, after string) (Page[Task], error) {
	const m = "tasks"
	if err := checkAfter(m, after); err != nil {
		return Page[Task]{}, err
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return Page[Task]{}, err
	}
	defer c.unlock()
	w := c.f.w
	if f.Tenant == "" && !w.admin(user) || f.Tenant != "" && !w.canRead(user, f.Tenant) {
		return Page[Task]{}, fail(m, CodeDenied, "")
	}
	var items []Task
	for _, a := range w.apps {
		if a.view.Retiring || f.Tenant != "" && a.view.Tenant != f.Tenant || f.App != "" && a.view.App != f.App {
			continue
		}
		for _, t := range a.tasks {
			if f.Node == "" || t.Node == f.Node {
				items = append(items, t)
			}
		}
	}
	key := func(t Task) string { return t.Tenant + "/" + t.App + "/" + t.Service + "/" + t.Instance }
	return paginate(items, key, after, c.f.pageSize, w.root), nil
}

func (c *fakeConn) ContainerObserve(ctx context.Context, tenant string, q ContainerQuery) (ContainerResult, error) {
	const m = "container-observe"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return ContainerResult{}, err
	}
	defer c.unlock()
	a := c.f.w.apps[tenant+"/"+q.Selection.App]
	var task *Task
	if q.Selection.Standalone != "" {
		_, e, err := c.f.w.standaloneTarget(c.session.User, tenant, q.Selection.Standalone, c.f.now().Unix())
		if errors.Is(err, errForbidden) {
			return ContainerResult{}, fail(m, CodeDenied, "")
		}
		if e != nil {
			t := e.task()
			task = &t
		}
	} else if a != nil && !a.view.Retiring {
		for i := range a.tasks {
			t := &a.tasks[i]
			if t.Service == q.Selection.Service && (q.Selection.Instance == "" || q.Selection.Instance == t.Instance) {
				task = t
				break
			}
		}
	}
	if task == nil {
		return ContainerResult{}, fail(m, CodeMissing, "")
	}
	now := c.f.now().Unix()
	r := ContainerResult{Selection: selectionOf(task.App, task.Service, task.Instance),
		Node: task.Node, NativeID: nativeIDOf(*task),
		Kind: q.Kind, ObservedAt: now, ViewIndex: c.f.w.root}
	switch q.Kind {
	case "logs":
		tail := q.Tail
		if tail <= 0 || tail > 10000 {
			tail = 100
		}
		r.LogDriver = "local"
		n := min(tail, 20)
		for i := 0; i < n; i++ {
			stream := "stdout"
			if task.Health == "unhealthy" && i%4 == 3 {
				stream = "stderr"
			}
			if stream == "stdout" && !q.Stdout && q.Stderr || stream == "stderr" && !q.Stderr && q.Stdout {
				continue
			}
			if at := now - int64(n-i)*5; q.Since != 0 && at < q.Since || q.Until != 0 && at > q.Until {
				continue
			}
			r.Logs = append(r.Logs, LogLine{Time: now - int64(n-i)*5, Stream: stream,
				Text: fmt.Sprintf("[%s] %s line %d", task.Service, stream, i+1)})
		}
		r.Truncated = tail > n
	case "top":
		r.Processes = []Process{
			{PID: 1, User: "root", Command: task.Service, CPU: 1.5, MemRSS: 64 * mib},
			{PID: 27, User: "app", Command: task.Service + " worker", CPU: 0.4, MemRSS: 32 * mib},
		}
	case "stats":
		r.Stats = &ContainerStats{CPUPercent: 3.2, MemUsed: 210 * mib, MemLimit: 1 * gib, NetRxBytes: 12 * mib, NetTxBytes: 9 * mib, BlockRead: 4 * mib, BlockWrite: 2 * mib, PIDs: 7}
	default:
		return ContainerResult{}, fail(m, CodeInvalid, "kind")
	}
	return r, nil
}
