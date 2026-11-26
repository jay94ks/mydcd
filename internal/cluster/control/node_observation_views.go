// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/observability"
)

type NodeUsageView struct {
	Tenant, Node                                                      string
	CPUUsed, MemoryUsed, Containers, Problems                         *uint64 `json:",omitempty"`
	ReservedCPU, ReservedMemory, QuotaCPU, QuotaMemory, QuotaRevision uint64
	ObservedAt                                                        uint64
	Stale, Complete                                                   bool
}

type NodeAdminView struct {
	ConsensusObservedAt    uint64
	ConsensusStale         bool
	Role, Address, Version string
	Host                   *observability.Host `json:",omitempty"`
	DiskTotal, DiskUsed    *uint64             `json:",omitempty"`
	DisksComplete          bool
	Consensus              *observability.Consensus `json:",omitempty"`
	Tenants                []NodeUsageView
	TenantsNext            string
}

type NodeSummaryView struct {
	CordonedBy, CordonedAt        string `json:",omitempty"`
	Scheduling                    membership.CordonView
	ObserveLimitSeconds           uint64
	Node, State                   string
	Ready, Stale                  bool
	ObservedAt, ObservationMaxAge uint64
	Usage                         *NodeUsageView `json:",omitempty"`
	Admin                         *NodeAdminView `json:",omitempty"`
}

type NodeSummaryPage struct {
	Nodes            []NodeSummaryView
	Next             string
	RootRevision     uint64
	CanAcceptChanges bool
}

type NodeTenantPage struct {
	Usage        []NodeUsageView
	Next         string
	RootRevision uint64
}

type NodeDiskView struct {
	Node, ID, Mount, Device, Filesystem, State string
	Purposes, StorageRoots                     []string
	Sources                                    []string `json:"-"`
	SourceCount                                int
	Total, Used, Free, Available, InodesFree   *uint64 `json:",omitempty"`
	ObservedAt, ObservationMaxAge              uint64
	Stale                                      bool
	MeasurementOnly                            bool
}

type NodeDisksPage struct {
	Disks        []NodeDiskView
	Next         string
	RootRevision uint64
}

type nodeObservationAccess struct {
	policy  Policy
	catalog access.Catalog
	members membership.Directory
	admin   bool
	tenant  string
	nodes   map[string]bool
}

func (p Policy) observationAccess(s state.State, session access.Session, at int64, tenant, node string, manager bool) (nodeObservationAccess, error) {
	var a nodeObservationAccess
	if node != "" && !lifecycle.ValidID(node) || tenant != "" && !lifecycle.ValidID(tenant) {
		return a, access.ErrInvalid
	}
	current, err := p.Current(s)
	if err != nil {
		return a, access.ErrDenied
	}
	c, err := current.Catalog(s)
	if err != nil {
		return a, err
	}
	admin := c.SystemAllowed(session.User)
	action := access.Read
	if tenant == "" {
		action = access.ManageCluster
	} else if manager {
		action = access.ManageVolumes
	}
	if c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, tenant, action, "") != nil || tenant == "" && !admin {
		return a, access.ErrDenied
	}
	d, err := current.Members(s)
	if err != nil {
		return a, err
	}
	a = nodeObservationAccess{policy: current, catalog: c, members: d, admin: admin && tenant == "", tenant: tenant, nodes: map[string]bool{}}
	if a.admin {
		for _, entry := range d.Entries {
			a.nodes[entry.Peer.ID] = true
		}
	} else {
		t, ok := c.Tenant(tenant)
		if !ok {
			return a, access.ErrDenied
		}
		for _, id := range t.AllowedNodes {
			if c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, tenant, action, id) == nil {
				a.nodes[id] = true
			}
		}
	}
	if node != "" && !a.nodes[node] {
		return a, access.ErrDenied
	}
	return a, nil
}

// Validate every accepted edge observation against its installed logical node;
// callers receive owned DTOs, never the signature or unrelated report payload.
func allowedNodeReports(a nodeObservationAccess, reports []observability.Report) map[string]map[string]observability.Report {
	out := map[string]map[string]observability.Report{}
	for _, r := range reports {
		if !a.nodes[r.Node] || r.Cluster != a.policy.Cluster || !r.Valid() {
			continue
		}
		entry, ok := a.members.Entry(r.Node)
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if !ok || err != nil || key != r.Key {
			continue
		}
		if out[r.Node] == nil {
			out[r.Node] = map[string]observability.Report{}
		}
		old, known := out[r.Node][r.Source()]
		if !known || old.At < r.At {
			out[r.Node][r.Source()] = r
		}
	}
	return out
}

func observationBasis(s state.State, session access.Session, method, tenant, node string, rows any) [32]byte {
	raw, _ := json.Marshal(struct {
		Members, Catalog, Resources, Roots uint64
		User, Method, Tenant, Node         string
		Scopes                             []access.Scope
		Rows                               any
	}{s.Object(MembersKey).Revision, s.Object(CatalogKey).Revision, s.Object(ResourcesKey).Revision, s.Object(NodeStorageKey).Revision, session.User, method, tenant, node, session.Scopes, rows})
	return sha256.Sum256(append([]byte("mydc-node-observation-page-1\x00"), raw...))
}

func observationPage(after string, basis [32]byte, length int) (int, int, error) {
	offset, err := taskCursor(after, basis)
	if err != nil {
		return 0, 0, err
	}
	if uint64(offset) > uint64(length) {
		return 0, 0, access.ErrInvalid
	}
	return int(offset), min(int(offset)+8, length), nil
}

func (p Policy) nodeTenantUsage(s state.State, node string, reports map[string]observability.Report, tenant string, now uint64) ([]NodeUsageView, error) {
	resources, err := p.Resources(s)
	if err != nil {
		return nil, err
	}
	rows := map[string]NodeUsageView{}
	for _, limit := range resources.Quotas.Limits() {
		if limit.Node != node || limit.Tenant == "" || tenant != "" && limit.Tenant != tenant {
			continue
		}
		rows[limit.Tenant] = NodeUsageView{Tenant: limit.Tenant, Node: node, QuotaCPU: limit.Capacity.CPU, QuotaMemory: limit.Capacity.Memory, QuotaRevision: limit.Revision, Stale: true}
	}
	if tenant != "" {
		if _, known := rows[tenant]; !known {
			rows[tenant] = NodeUsageView{Tenant: tenant, Node: node, Stale: true}
		}
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return nil, err
	}
	for _, reservation := range projection.Resources.Quotas.Reservations() {
		if reservation.Node != node || tenant != "" && reservation.Tenant != tenant {
			continue
		}
		row := rows[reservation.Tenant]
		row.Tenant, row.Node = reservation.Tenant, node
		row.ReservedCPU += reservation.Need.CPU
		row.ReservedMemory += reservation.Need.Memory
		rows[row.Tenant] = row
	}
	for _, report := range reports {
		if report.Usage == nil || tenant != "" && report.Usage.Tenant != tenant {
			continue
		}
		u := report.Usage
		row := rows[u.Tenant]
		row.Tenant, row.Node = u.Tenant, node
		row.ObservedAt, row.Stale, row.Complete = report.At, !observability.Fresh(report.At, now), u.Complete
		if u.Complete {
			cpu, memory, containers, problems := u.CPUUsed, u.MemoryUsed, u.Containers, u.Problems
			if cpu != nil {
				value := *cpu
				row.CPUUsed = &value
			}
			if memory != nil {
				value := *memory
				row.MemoryUsed = &value
			}
			row.Containers, row.Problems = &containers, &problems
		}
		rows[u.Tenant] = row
	}
	keys := make([]string, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := make([]NodeUsageView, 0, len(keys))
	for _, key := range keys {
		out = append(out, rows[key])
	}
	return out, nil
}

func (p Policy) NodeSummary(s state.State, session access.Session, at int64, tenant, node, after string, reports []observability.Report, canAccept bool) (NodeSummaryPage, error) {
	a, err := p.observationAccess(s, session, at, tenant, node, false)
	if err != nil {
		return NodeSummaryPage{}, err
	}
	selected := allowedNodeReports(a, reports)
	now := uint64(at)*1000 + 999
	rows := []NodeSummaryView{}
	for _, entry := range a.members.Entries {
		id := entry.Peer.ID
		if !a.nodes[id] || node != "" && id != node {
			continue
		}
		row := NodeSummaryView{Node: id, State: "unknown", Stale: true, ObservationMaxAge: observability.MaxAge, ObserveLimitSeconds: observability.MaxAge / 1000}
		if !membership.FullMember(entry) {
			row.State = "pending"
		}
		work := membership.FullMember(entry)
		if view, ok := a.policy.publicNodeView(a.members, a.catalog, id); ok {
			row.Scheduling = view.Scheduling
			row.CordonedBy, row.CordonedAt = view.Scheduling.CordonedBy, view.Scheduling.CordonedAt
			work = view.AdmitsWork
			if view.Node.Phase != lifecycle.Active {
				row.State = string(view.Node.Phase)
			}
		}
		host, known := selected[id]["host"]
		if known && host.Host != nil {
			row.ObservedAt, row.Stale = host.At, !observability.Fresh(host.At, now)
			row.Ready = !row.Stale && host.Host.ModuleReady && work
			if row.State == "unknown" {
				if row.Ready {
					row.State = "ready"
				} else {
					row.State = "unready"
				}
			}
		}
		if work && (row.ObservedAt == 0 || row.Stale) {
			row.State = "unreachable"
		}
		usage, err := a.policy.nodeTenantUsage(s, id, selected[id], tenant, now)
		if err != nil {
			return NodeSummaryPage{}, err
		}
		if !a.admin {
			if len(usage) > 0 {
				u := usage[0]
				row.Usage = &u
			}
		} else {
			admin := NodeAdminView{Address: entry.Peer.Endpoint, Role: "non-voter", Tenants: usage[:min(8, len(usage))]}
			if entry.Peer.Voter {
				admin.Role = "voter"
			}
			if row.State == "pending" {
				admin.Role = "pending"
			}
			if known && host.Host != nil {
				copy := *host.Host
				if copy.CPUUsed != nil {
					n := *copy.CPUUsed
					copy.CPUUsed = &n
				}
				if copy.MemoryUsed != nil {
					n := *copy.MemoryUsed
					copy.MemoryUsed = &n
				}
				if copy.MemoryTotal != nil {
					n := *copy.MemoryTotal
					copy.MemoryTotal = &n
				}
				admin.Host = &copy
				admin.Version = copy.Version
			}
			if fact, ok := selected[id]["consensus"]; ok && fact.Consensus != nil {
				copy := *fact.Consensus
				admin.Consensus = &copy
				admin.ConsensusObservedAt, admin.ConsensusStale = fact.At, !observability.Fresh(fact.At, now)
				if copy.Role == "leader" || copy.Role == "candidate" {
					admin.Role = copy.Role
				}
			}
			if len(usage) > 8 {
				basis := observationBasis(s, session, "node-tenant-usage", "", id, usage)
				admin.TenantsNext = nextTaskCursor(basis, 8)
			}
			disks, err := a.policy.nodeDisks(s, a, id, selected[id], now)
			if err != nil {
				return NodeSummaryPage{}, err
			}
			if len(disks) > 0 {
				var total, used uint64
				complete, known := true, false
				for _, disk := range disks {
					if disk.Total == nil || disk.Used == nil {
						complete = false
						continue
					}
					if ^uint64(0)-total < *disk.Total || ^uint64(0)-used < *disk.Used {
						return NodeSummaryPage{}, access.ErrInvalid
					}
					known = true
					total += *disk.Total
					used += *disk.Used
					complete = complete && !disk.Stale
				}
				if known {
					admin.DiskTotal, admin.DiskUsed = &total, &used
				}
				admin.DisksComplete = complete
			}
			row.Admin = &admin
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b NodeSummaryView) int { return strings.Compare(a.Node, b.Node) })
	basis := observationBasis(s, session, "node-summary", tenant, node, rows)
	start, end, err := observationPage(after, basis, len(rows))
	if err != nil {
		return NodeSummaryPage{}, err
	}
	page := NodeSummaryPage{Nodes: rows[start:end], RootRevision: s.Object(MembersKey).Revision, CanAcceptChanges: canAccept}
	if end < len(rows) {
		page.Next = nextTaskCursor(basis, uint32(end))
	}
	return page, nil
}

func (p Policy) NodeTenantUsage(s state.State, session access.Session, at int64, node, after string, reports []observability.Report) (NodeTenantPage, error) {
	if node == "" {
		return NodeTenantPage{}, access.ErrInvalid
	}
	a, err := p.observationAccess(s, session, at, "", node, false)
	if err != nil {
		return NodeTenantPage{}, err
	}
	selected := allowedNodeReports(a, reports)
	usage, err := a.policy.nodeTenantUsage(s, node, selected[node], "", uint64(at)*1000+999)
	if err != nil {
		return NodeTenantPage{}, err
	}
	basis := observationBasis(s, session, "node-tenant-usage", "", node, usage)
	start, end, err := observationPage(after, basis, len(usage))
	if err != nil {
		return NodeTenantPage{}, err
	}
	page := NodeTenantPage{Usage: usage[start:end], RootRevision: s.Object(MembersKey).Revision}
	if end < len(usage) {
		page.Next = nextTaskCursor(basis, uint32(end))
	}
	return page, nil
}

func (p Policy) nodeDisks(s state.State, a nodeObservationAccess, node string, reports map[string]observability.Report, now uint64) ([]NodeDiskView, error) {
	type source struct {
		purpose, root, path  string
		generation, revision uint64
	}
	sources := map[string]source{}
	if a.admin {
		sources["system"] = source{purpose: "system", path: "/"}
		host, known := reports["host"]
		if known && host.Host != nil && host.Host.RuntimeEnabled || !known && reports["disk/container-runtime"].Disk != nil {
			sources["container-runtime"] = source{purpose: "container-runtime"}
		}
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return nil, err
	}
	for _, root := range roots.Roots() {
		if root.Definition.Node != node || root.Closed != nil || !a.admin && !slices.Contains(root.Definition.Tenants, a.tenant) {
			continue
		}
		sources["root/"+root.Definition.ID] = source{purpose: "storage-root", root: root.Definition.ID, path: root.Definition.Path, generation: root.Generation, revision: root.Revision}
	}
	keys := make([]string, 0, len(sources))
	for key := range sources {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	groups := map[string]NodeDiskView{}
	for _, name := range keys {
		definition := sources[name]
		row := NodeDiskView{Node: node, Mount: definition.path, State: "unknown", Sources: []string{name}, Purposes: []string{definition.purpose}, Stale: true, ObservationMaxAge: observability.MaxAge, MeasurementOnly: true, SourceCount: 1}
		if definition.root != "" {
			row.StorageRoots = []string{definition.root}
		}
		report, known := reports["disk/"+name]
		if !known || report.Disk == nil || definition.root != "" && (report.Disk.RootGeneration != definition.generation || report.Disk.RootRevision > definition.revision) {
			groups["unknown/"+name] = row
			continue
		}
		disk := report.Disk
		row.ID, row.State, row.Filesystem = disk.ID, "observed", disk.Filesystem
		row.ObservedAt, row.Stale = report.At, !observability.Fresh(report.At, now) || definition.root != "" && disk.RootRevision != definition.revision
		if a.admin {
			row.Mount, row.Device = disk.Mount, disk.Device
		}
		total, used, free, available, inodes := disk.Total, disk.Used, disk.Free, disk.Available, disk.InodesFree
		row.Total, row.Used, row.Free, row.Available, row.InodesFree = &total, &used, &free, &available, &inodes
		old, exists := groups[row.ID]
		if exists {
			purposes := append(slices.Clone(old.Purposes), row.Purposes...)
			roots := append(slices.Clone(old.StorageRoots), row.StorageRoots...)
			selectedSources := append(slices.Clone(old.Sources), row.Sources...)
			stale := old.Stale || row.Stale
			if old.ObservedAt > row.ObservedAt {
				row = old
			}
			row.Purposes, row.StorageRoots, row.Sources = purposes, roots, selectedSources
			row.Stale = stale
		}
		slices.Sort(row.Purposes)
		row.Purposes = slices.Compact(row.Purposes)
		slices.Sort(row.StorageRoots)
		row.StorageRoots = slices.Compact(row.StorageRoots)
		slices.Sort(row.Sources)
		row.Sources = slices.Compact(row.Sources)
		row.SourceCount = len(row.Sources)
		groups[row.ID] = row
	}
	out := make([]NodeDiskView, 0, len(groups))
	for _, row := range groups {
		out = append(out, row)
	}
	slices.SortFunc(out, func(a, b NodeDiskView) int {
		if a.ID != b.ID {
			return strings.Compare(a.ID, b.ID)
		}
		return strings.Compare(strings.Join(a.Sources, "/"), strings.Join(b.Sources, "/"))
	})
	return out, nil
}

func (p Policy) NodeDisks(s state.State, session access.Session, at int64, tenant, node, after string, reports []observability.Report) (NodeDisksPage, error) {
	a, err := p.observationAccess(s, session, at, tenant, node, true)
	if err != nil {
		return NodeDisksPage{}, err
	}
	selected := allowedNodeReports(a, reports)
	rows := []NodeDiskView{}
	for _, entry := range a.members.Entries {
		if !a.nodes[entry.Peer.ID] || node != "" && entry.Peer.ID != node {
			continue
		}
		disks, err := a.policy.nodeDisks(s, a, entry.Peer.ID, selected[entry.Peer.ID], uint64(at)*1000+999)
		if err != nil {
			return NodeDisksPage{}, err
		}
		rows = append(rows, disks...)
	}
	slices.SortFunc(rows, func(a, b NodeDiskView) int {
		if a.Node != b.Node {
			return strings.Compare(a.Node, b.Node)
		}
		if a.ID != b.ID {
			return strings.Compare(a.ID, b.ID)
		}
		return strings.Compare(strings.Join(a.Sources, "/"), strings.Join(b.Sources, "/"))
	})
	basis := observationBasis(s, session, "node-disks", tenant, node, rows)
	start, end, err := observationPage(after, basis, len(rows))
	if err != nil {
		return NodeDisksPage{}, err
	}
	// Mount paths may approach the path budget. Keep the common User frame
	// bounded even for eight maximum-length, escaped path rows.
	used := 0
	for i := start; i < end; i++ {
		raw, _ := json.Marshal(rows[i])
		if used+len(raw) > 120<<10 {
			end = i
			break
		}
		used += len(raw)
	}
	if start == end && start < len(rows) {
		return NodeDisksPage{}, access.ErrInvalid
	}
	page := NodeDisksPage{Disks: rows[start:end], RootRevision: s.Object(NodeStorageKey).Revision}
	if end < len(rows) {
		page.Next = nextTaskCursor(basis, uint32(end))
	}
	return page, nil
}

type MeshLinkEnd struct {
	ObservedBy  string
	Observation observability.Link
	ObservedAt  uint64
	Stale       bool
}

type MeshLinkView struct {
	ID, NodeA, NodeB, State       string
	ObservedAt, ObservationMaxAge uint64
	Stale                         bool
	Ends                          []MeshLinkEnd `json:",omitempty"`
}

type MeshLinksPage struct {
	Links        []MeshLinkView
	Next         string
	RootRevision uint64
}

func (p Policy) MeshLinks(s state.State, session access.Session, at int64, tenant, node, after string, reports []observability.Report) (MeshLinksPage, error) {
	a, err := p.observationAccess(s, session, at, tenant, node, false)
	if err != nil {
		return MeshLinksPage{}, err
	}
	selected := allowedNodeReports(a, reports)
	entries := slices.Clone(a.members.Entries)
	slices.SortFunc(entries, func(a, b membership.Entry) int { return strings.Compare(a.Peer.ID, b.Peer.ID) })
	rows := []MeshLinkView{}
	now := uint64(at)*1000 + 999
	for i, left := range entries {
		if !a.nodes[left.Peer.ID] {
			continue
		}
		if view, ok := a.members.NodeView(left.Peer.ID); ok && view.Node.Phase == lifecycle.Removed {
			continue
		}
		for _, right := range entries[i+1:] {
			if !a.nodes[right.Peer.ID] || node != "" && node != left.Peer.ID && node != right.Peer.ID {
				continue
			}
			if view, ok := a.members.NodeView(right.Peer.ID); ok && view.Node.Phase == lifecycle.Removed {
				continue
			}
			row := MeshLinkView{ID: observability.PairID(left.Peer.ID, right.Peer.ID), NodeA: left.Peer.ID, NodeB: right.Peer.ID, State: "pending", Stale: true, ObservationMaxAge: observability.MaxAge}
			if !membership.FullMember(left) || !membership.FullMember(right) {
				rows = append(rows, row)
				continue
			}
			ends := []MeshLinkEnd{}
			for _, pair := range [][2]string{{left.Peer.ID, right.Peer.ID}, {right.Peer.ID, left.Peer.ID}} {
				if report, known := selected[pair[0]]["link/"+pair[1]]; known && report.Link != nil {
					copy := *report.Link
					copy.Outages = slices.Clone(copy.Outages)
					if copy.RTTMillis != nil {
						v := *copy.RTTMillis
						copy.RTTMillis = &v
					}
					if copy.LossPct != nil {
						v := *copy.LossPct
						copy.LossPct = &v
					}
					ends = append(ends, MeshLinkEnd{ObservedBy: pair[0], Observation: copy, ObservedAt: report.At, Stale: !observability.Fresh(report.At, now)})
				}
			}
			if len(ends) > 0 {
				row.State = "up"
				row.Stale = len(ends) != 2
				for _, end := range ends {
					row.ObservedAt = max(row.ObservedAt, end.ObservedAt)
					row.Stale = row.Stale || end.Stale
					if end.Observation.State == "down" {
						row.State = "down"
					} else if row.State != "down" && end.Observation.State == "degraded" {
						row.State = "degraded"
					}
				}
				if row.Stale && row.State == "up" {
					row.State = "degraded"
				}
				if a.admin {
					row.Ends = ends
				}
			}
			rows = append(rows, row)
		}
	}
	basis := observationBasis(s, session, "mesh-links", tenant, node, rows)
	start, end, err := observationPage(after, basis, len(rows))
	if err != nil {
		return MeshLinksPage{}, err
	}
	page := MeshLinksPage{Links: rows[start:end], RootRevision: s.Object(MembersKey).Revision}
	if end < len(rows) {
		page.Next = nextTaskCursor(basis, uint32(end))
	}
	return page, nil
}
