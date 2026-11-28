// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/ingress"
)

const IngressManagementKey = "control/ingress-management"

type IngressBlockChange struct{ Block ingress.Block }
type IngressBlockSelection struct {
	ID        string
	ExpiresAt uint64 `json:",omitempty"`
}
type IngressBlockRecord struct {
	Block        ingress.Block
	Revision     uint64
	Removed      bool
	Origin, Last UserOperation
}
type IngressManagement struct {
	NodeGatewaysRecords []NodeGatewaysRecord   `json:",omitempty"`
	Balances            []IngressBalanceRecord `json:",omitempty"`
	Drains              []IngressDrainRecord   `json:",omitempty"`
	History             []IngressHistoryRecord `json:",omitempty"`
	Schema              uint8
	Cluster             [32]byte
	Revision            uint64
	Blocks              []IngressBlockRecord
	ClusterAppRoutes    []ClusterAppRouteRecord `json:",omitempty"`
}

func (p Policy) IngressManagement(s state.State) (IngressManagement, error) {
	out := IngressManagement{Schema: 1, Cluster: p.Cluster}
	raw, revision, err := readCheckpoint(s, IngressManagementKey, p.Cluster, p.TrustRoot)
	if err != nil || raw == nil {
		return out, err
	}
	if canonical(raw, &out) != nil || out.Schema != 1 || out.Cluster != p.Cluster || out.Revision != revision || len(out.Blocks) > 4096 || !validateIngressOperations(out) || !validClusterAppRouteRecords(out) {
		return out, ErrCatalog
	}
	seen := map[string]bool{}
	for _, r := range out.Blocks {
		if !r.Block.Valid() || r.Revision == 0 || seen[r.Block.ID] || r.Origin.VerifyOriginal(p.Cluster) != nil || r.Last.VerifyOriginal(p.Cluster) != nil || r.Origin.Change.Action != "ingress-block" || r.Origin.Session.User != r.Block.Actor || r.Block.CreatedAt != uint64(r.Origin.At) || r.Last.Change.Expected+1 != r.Revision {
			return out, ErrCatalog
		}
		var original IngressBlockChange
		if canonical(r.Origin.Change.Payload, &original) != nil {
			return out, ErrCatalog
		}
		want := original.Block
		want.Actor = r.Block.Actor
		want.CreatedAt = r.Block.CreatedAt
		want.ExpiresAt = r.Block.ExpiresAt
		if !ingress.EqualBlock(want, r.Block) {
			return out, ErrCatalog
		}
		switch r.Last.Change.Action {
		case "ingress-block":
			if r.Revision != 1 || r.Removed || !buildJSONEqual(r.Last, r.Origin) {
				return out, ErrCatalog
			}
		case "ingress-unblock", "ingress-block-extend":
			var q IngressBlockSelection
			if canonical(r.Last.Change.Payload, &q) != nil || q.ID != r.Block.ID || r.Removed != (r.Last.Change.Action == "ingress-unblock") || !r.Removed && q.ExpiresAt != r.Block.ExpiresAt {
				return out, ErrCatalog
			}
		default:
			return out, ErrCatalog
		}
		seen[r.Block.ID] = true
	}
	return out, nil
}
func (b IngressManagement) ConfiguredBlocks() []ingress.Block {
	var out []ingress.Block
	for _, r := range b.Blocks {
		if !r.Removed {
			out = append(out, r.Block)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (b IngressManagement) ActiveBlocks(now uint64) []ingress.Block {
	var out []ingress.Block
	for _, r := range b.Blocks {
		if !r.Removed && r.Block.Active(now) {
			out = append(out, r.Block)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func (p Policy) ingressBlockAuthorized(s state.State, c access.Catalog, op UserOperation) error {
	if extendedIngressAction(op.Change.Action) {
		return p.authorizeIngressOperation(s, c, op)
	}
	if c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return access.ErrDenied
	}
	if clusterAppRouteAction(op.Change.Action) {
		return p.authorizeClusterAppRoute(c, op)
	}
	var b ingress.Block
	if op.Change.Action == "ingress-block" {
		var q IngressBlockChange
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		b = q.Block
		if b.Actor != "" && b.Actor != op.Session.User || b.CreatedAt != 0 && b.CreatedAt != uint64(op.At) {
			return access.ErrInvalid
		}
		b.Actor, b.CreatedAt = op.Session.User, uint64(op.At)
		if !b.Valid() {
			return access.ErrInvalid
		}
	} else {
		var q IngressBlockSelection
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		book, err := p.IngressManagement(s)
		if err != nil {
			return err
		}
		found := false
		for _, r := range book.Blocks {
			if r.Block.ID == q.ID {
				b, found = r.Block, true
				break
			}
		}
		if !found {
			return access.ErrInvalid
		}
	}
	u, ok := c.User(op.Session.User)
	if !ok || !u.Enabled {
		return access.ErrDenied
	}
	if u.SystemAdmin {
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
	}
	if b.Scope == "node" || b.Scope == "tenant" || b.Scope == "gateway" {
		return access.ErrDenied
	}
	if err := c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, b.Tenant, access.ManageNetwork, b.Node); err != nil {
		return err
	}
	if b.Scope == "host" {
		projection, err := p.ProjectResources(s)
		if err != nil {
			return err
		}
		for _, g := range projection.Goals {
			if g.Ingress == nil {
				continue
			}
			for _, route := range g.Ingress.Routes {
				if route.Host == b.Host && (b.Node == "" || b.Node == g.Goal.Node) && g.Goal.Tenant != b.Tenant {
					return access.ErrDenied
				}
			}
		}
	}
	return nil
}
func (p Policy) ingressBlockTarget(s state.State, b ingress.Block) error {
	if b.Scope == "gateway" {
		return nil
	}
	if b.Scope == "node" {
		_, err := p.nodeOwner(s, b.Node)
		return err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if _, ok := c.Tenant(b.Tenant); !ok && !(b.Scope == "host" && b.Tenant == "") {
		return access.ErrInvalid
	}
	if b.Scope == "tenant" {
		return nil
	}
	if b.Scope == "source" {
		if len(b.Apps) > 0 {
			apps, err := p.readOnlyApps(s)
			if err != nil {
				return err
			}
			for _, app := range b.Apps {
				if _, ok := apps.entries[appKey(b.Tenant, app)]; !ok {
					return access.ErrInvalid
				}
			}
		}
		return nil
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return err
	}
	for key, g := range projection.Goals {
		if g.Ingress == nil || (b.Tenant != "" && g.Goal.Tenant != b.Tenant) || b.Node != "" && b.Node != g.Goal.Node || b.App != "" && b.App != g.Goal.App || b.Key != "" && b.Key != key {
			continue
		}
		switch b.Scope {
		case "instance":
			return nil
		case "host", "route":
			for _, r := range g.Ingress.Routes {
				if b.Scope == "host" && r.Host == b.Host || b.Scope == "route" && r.ID == b.Route && r.Host == b.Host && r.Prefix == b.Prefix {
					return nil
				}
			}
		case "backend":
			for _, svc := range g.Ingress.Services {
				if svc.ID != b.Service {
					continue
				}
				for _, backend := range svc.Backends {
					if backend.ID == b.Backend {
						return nil
					}
				}
			}
		}
	}
	return access.ErrInvalid
}
func (p Policy) reduceIngressManagement(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil {
		return nil, state.Forbidden
	}
	if err = p.ingressBlockAuthorized(s, c, op); err != nil {
		if err == access.ErrInvalid {
			return nil, state.Invalid
		}
		return nil, state.Forbidden
	}
	book, err := p.IngressManagement(s)
	if err != nil || book.Revision == math.MaxUint64 {
		return nil, state.Invalid
	}
	if len(book.History) >= 4096 {
		return nil, state.ConditionFailed
	}
	before := book
	before.Blocks = slices.Clone(book.Blocks)
	before.ClusterAppRoutes = slices.Clone(book.ClusterAppRoutes)
	if extendedIngressAction(op.Change.Action) {
		history, code := p.reduceIngressOperation(s, &book, op)
		if code != state.Applied {
			return nil, code
		}
		book.History = append(slices.Clone(book.History), history)
	} else if clusterAppRouteAction(op.Change.Action) {
		if code := p.reduceClusterAppRoute(s, &book, op); code != state.Applied {
			return nil, code
		}
	} else if op.Change.Action == "ingress-block" {
		var q IngressBlockChange
		if canonical(op.Change.Payload, &q) != nil || op.Change.Expected != 0 || len(book.Blocks) >= 4096 {
			return nil, state.ConditionFailed
		}
		q.Block.Actor, q.Block.CreatedAt = op.Session.User, uint64(op.At)
		for _, r := range book.Blocks {
			if r.Block.ID == q.Block.ID {
				return nil, state.ConditionFailed
			}
		}
		if p.ingressBlockTarget(s, q.Block) != nil {
			return nil, state.ConditionFailed
		}
		book.Blocks = append(book.Blocks, IngressBlockRecord{Block: q.Block, Revision: 1, Origin: op, Last: op})
	} else {
		var q IngressBlockSelection
		if canonical(op.Change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		found := false
		for i := range book.Blocks {
			r := &book.Blocks[i]
			if r.Block.ID != q.ID {
				continue
			}
			found = true
			if r.Removed || r.Revision != op.Change.Expected || r.Revision == math.MaxUint64 {
				return nil, state.ConditionFailed
			}
			switch op.Change.Action {
			case "ingress-unblock":
				if q.ExpiresAt != 0 {
					return nil, state.Invalid
				}
				r.Removed = true
			case "ingress-block-extend":
				if r.Block.ExpiresAt == 0 || q.ExpiresAt > math.MaxInt64 || q.ExpiresAt <= uint64(op.At) || q.ExpiresAt <= r.Block.ExpiresAt {
					return nil, state.ConditionFailed
				}
				r.Block.ExpiresAt = q.ExpiresAt
			default:
				return nil, state.Invalid
			}
			r.Revision++
			r.Last = op
		}
		if !found {
			return nil, state.ConditionFailed
		}
	}
	if !extendedIngressAction(op.Change.Action) {
		h := IngressHistoryRecord{Order: book.Revision + 1, Origin: op, Detail: slices.Clone(op.Change.Payload)}
		if clusterAppRouteAction(op.Change.Action) {
			h.App = deployment.ClusterAppPrefix + clusterAppRouteApp(op)
			if old, found := before.ClusterAppRoute(clusterAppRouteApp(op)); found {
				h.Previous, _ = json.Marshal(old.Ingress)
			}
		} else {
			for _, r := range book.Blocks {
				if r.Last.RequestID == op.RequestID {
					h.Tenant, h.App, h.Node, h.Route, h.Gateway = r.Block.Tenant, r.Block.App, r.Block.Node, r.Block.Route, r.Block.Gateway
					for _, old := range before.Blocks {
						if old.Block.ID == r.Block.ID {
							h.Previous, _ = json.Marshal(old.Block)
						}
					}
					h.Detail, _ = json.Marshal(r.Block)
					if r.Block.Tenant != "" && r.Block.App == "" {
						projection, e := p.ProjectResources(s)
						if e != nil {
							return nil, state.Invalid
						}
						for key, g := range projection.Goals {
							if g.Ingress == nil {
								continue
							}
							mapping := IngressMapping{Key: key, Tenant: g.Goal.Tenant, App: g.Goal.App, Node: g.Goal.Node, Spec: *g.Ingress}
							if ingressBlockMaps(r.Block, mapping) && !slices.Contains(h.AffectedApps, g.Goal.App) {
								h.AffectedApps = append(h.AffectedApps, g.Goal.App)
							}
						}
						slices.Sort(h.AffectedApps)
					}

					break
				}
			}
		}
		book.History = append(slices.Clone(book.History), h)
	}
	book.Revision++
	raw, err := json.Marshal(book)
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, IngressManagementKey, p.Cluster, p.TrustRoot, book.Revision, raw)
}

type IngressQuery struct {
	Check                        *NodeGatewaysCheck `json:",omitempty"`
	Node, Tenant, App, Key, Part string
	After                        string `json:",omitempty"`
	Offset                       uint32 `json:",omitempty"`
}

func (q IngressQuery) Valid() bool {
	return (q.Part == "" || q.Part == "mappings" || q.Part == "metrics" || q.Part == "errors" || q.Part == "blocks" || q.Part == "gateways" || q.Part == "history" || q.Part == "cluster-app-routes") && validIngressGatewayCheck(q) && q.Offset <= 4096 && len(q.After) <= 512 && (q.Node == "" || validID(q.Node)) && (q.Tenant == "" || validID(q.Tenant)) && (q.App == "" || validID(q.App)) && len(q.Key) <= 512
}

type IngressBlockView struct {
	Block                          ingress.Block
	Revision                       uint64
	Removed, Active, TargetMissing bool
	Applications                   []ingress.BlockApplication `json:",omitempty"`
}

func ingressBlockView(r IngressBlockRecord, at int64) IngressBlockView {
	return IngressBlockView{Block: r.Block, Revision: r.Revision, Removed: r.Removed, Active: !r.Removed && r.Block.Active(uint64(at))}
}

type IngressMapping struct {
	DrainRevision, DrainStartedAt, DrainDeadline                               uint64 `json:",omitempty"`
	LastMapping                                                                bool   `json:",omitempty"`
	Offset, Next                                                               uint32
	ListenersTotal, RoutesTotal, BackendsTotal, BlocksTotal, CertificatesTotal int
	Key, Tenant, App, Node                                                     string
	Owner                                                                      [32]byte
	Generation, Revision, ObservedAt                                           uint64
	Ready, Draining                                                            bool
	Error                                                                      string `json:",omitempty"`
	Spec                                                                       ingress.Spec
	Runtime                                                                    *ingress.InstanceSnapshot `json:",omitempty"`
	Blocks                                                                     []IngressBlockView        `json:",omitempty"`
}
type IngressGatewaySummary struct {
	Gateway                   string
	Unmatched, SourceRejected uint64
	Offset, Next              uint32
	BindingsTotal             int
	Listeners                 []ingress.SharedGatewayObservation `json:",omitempty"`
}
type IngressNodeSummary struct {
	Configuration                                                                                           *NodeGatewaysView       `json:",omitempty"`
	Gateways                                                                                                []IngressGatewaySummary `json:",omitempty"`
	Node                                                                                                    string
	Owner                                                                                                   [32]byte `json:",omitempty"`
	Enabled                                                                                                 *bool    `json:",omitempty"`
	Instances, Listeners, Connections, Requests, BufferBytes                                                int
	MaxIngressInstances, MaxIngressListeners, MaxIngressConnections, MaxIngressRequests, IngressBufferBytes int
}
type IngressSummaryRef struct {
	Key, Node  string
	Generation uint64
}
type IngressPage struct {
	GatewayEvidence            *NodeGatewaysEvidence `json:",omitempty"`
	GatewayCheckError          string                `json:",omitempty"`
	NodeGateways               []NodeGatewaysView    `json:",omitempty"`
	History                    []IngressHistoryView  `json:",omitempty"`
	System                     bool                  `json:"-"`
	SummaryRefs                []IngressSummaryRef   `json:"-"`
	ClusterAppRoutes           []ClusterAppRouteView `json:",omitempty"`
	Schema                     uint8
	Index, Epoch, RootRevision uint64
	BlockRevision              uint64 // committed policy book target; compare with owner Runtime.BlockRevision
	Mappings                   []IngressMapping
	Nodes                      []IngressNodeSummary
	Blocks                     []IngressBlockView `json:",omitempty"`
	Next                       string             `json:",omitempty"`
}
type IngressRead struct {
	SummaryQuery *IngressQuery `json:",omitempty"`
	Session      access.Session
	Query        IngressQuery
	At           int64
	Index        uint64
}

// SameSelection compares the authorized identities behind a collected read.
// Native values may change while gathering observations; a later authorization
// of a broad query must not authorize rows from a tenant that was just revoked.
func (p IngressPage) SameSelection(current IngressPage) bool {
	if p.System != current.System || p.Epoch != current.Epoch || p.RootRevision != current.RootRevision || p.BlockRevision != current.BlockRevision || p.Next != current.Next || !slices.Equal(p.SummaryRefs, current.SummaryRefs) || len(p.Mappings) != len(current.Mappings) || len(p.Nodes) != len(current.Nodes) || len(p.Blocks) != len(current.Blocks) {
		return false
	}
	for i, row := range p.Mappings {
		next := current.Mappings[i]
		if row.Key != next.Key || row.Tenant != next.Tenant || row.App != next.App || row.Node != next.Node || row.Owner != next.Owner || row.Generation != next.Generation || row.Revision != next.Revision {
			return false
		}
	}
	for i, row := range p.Nodes {
		if row.Node != current.Nodes[i].Node || row.Owner != current.Nodes[i].Owner {
			return false
		}
	}
	for i, row := range p.Blocks {
		next := current.Blocks[i]
		if row.Block.ID != next.Block.ID || row.Revision != next.Revision || row.Active != next.Active || row.Removed != next.Removed {
			return false
		}
	}
	return true
}

func (p Policy) IngressPage(s state.State, session access.Session, at int64, q IngressQuery) (IngressPage, error) {
	out := IngressPage{Schema: 1, Index: s.Index(), Epoch: s.ModuleEpoch(), RootRevision: s.Object(IngressManagementKey).Revision}
	if !q.Valid() {
		return out, access.ErrInvalid
	}
	current, err := p.Current(s)
	if err != nil {
		return out, err
	}
	p = current
	c, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	if c.VerifySession(session, p.Cluster, p.Issuer(session.Issuer), at) != nil {
		return out, access.ErrDenied
	}
	u, ok := c.User(session.User)
	if !ok {
		return out, access.ErrDenied
	}
	if q.Tenant != "" && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, q.Tenant, access.Read, q.Node) != nil {
		return out, access.ErrDenied
	}
	system := u.SystemAdmin && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") == nil
	out.System = system
	book, err := p.IngressManagement(s)
	if err != nil {
		return out, err
	}
	out.BlockRevision = book.Revision
	if q.Part == "history" {
		if q.Tenant == "" && !system {
			return out, access.ErrDenied
		}
		visible := func(row IngressHistoryRecord) bool {
			return system || row.Tenant != "" && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, row.Tenant, access.Read, row.Node) == nil
		}
		out.History, out.Next, err = book.historyPage(q, ingressHistoryBasis(c.Revision(), session, q), visible)
		return out, err
	}
	if q.Part == "cluster-app-routes" {
		if !system || q.Node != "" || q.Tenant != "" || q.App != "" {
			return out, access.ErrDenied
		}
		out.ClusterAppRoutes = book.clusterAppRouteViews()
		return out, nil
	}
	if q.Part == "gateways" {
		if !system || q.Node == "" || q.Tenant != "" || q.App != "" {
			return out, access.ErrDenied
		}
		owner, e := p.nodeOwner(s, q.Node)
		if e != nil {
			return out, e
		}
		row, found := book.NodeGateways(q.Node)
		v := NodeGatewaysView{Node: q.Node, Source: "file"}
		if found {
			v.Source, v.Configuration, v.Revision = "cluster", row.Configuration, row.Revision
		}
		out.NodeGateways = []NodeGatewaysView{v}
		out.Nodes = []IngressNodeSummary{{Node: q.Node, Owner: owner, Configuration: &v}}
		return out, nil
	}
	projection, err := p.ProjectResources(s)
	if err != nil {
		return out, err
	}
	allowed := func(tenant, node string) bool {
		return c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, node) == nil
	}
	for _, b := range book.Blocks {
		if (system || b.Block.Tenant != "" && allowed(b.Block.Tenant, func() string {
			if q.Node != "" {
				return q.Node
			}
			return b.Block.Node
		}())) && (q.Tenant == "" || b.Block.Tenant == q.Tenant) && (q.Node == "" || b.Block.Node == "" || b.Block.Node == q.Node) {
			view := ingressBlockView(b, at)
			view.TargetMissing = ingressBlockTargetMissing(b.Block, projection)
			out.Blocks = append(out.Blocks, view)
		}
	}
	keys := desired.Sorted(projection.Goals)
	summaries := map[string]IngressNodeSummary{}
	quotaSeen := map[string]bool{}
	listenerSeen := map[string]bool{}
	for _, key := range keys {
		g := projection.Goals[key]
		if g.Ingress == nil || !allowed(g.Goal.Tenant, g.Goal.Node) || q.Node != "" && g.Goal.Node != q.Node || q.Tenant != "" && g.Goal.Tenant != q.Tenant || q.App != "" && g.Goal.App != q.App || q.Key != "" && q.Key != key {
			continue
		}
		row := IngressMapping{Key: key, Tenant: g.Goal.Tenant, App: g.Goal.App, Node: g.Goal.Node, Owner: g.Goal.Owner, Generation: s.Object(key).Generation, Revision: s.Object(key).Revision, Draining: g.Ingress.Lifecycle.Drain, Spec: *g.Ingress}
		book.ApplyMapping(&row)

		for _, b := range book.Blocks {
			if !b.Removed && ingressBlockMaps(b.Block, row) {
				view := ingressBlockView(b, at)
				view.TargetMissing = ingressBlockTargetMissing(b.Block, projection)
				row.Blocks = append(row.Blocks, view)
			}
		}
		out.SummaryRefs = append(out.SummaryRefs, IngressSummaryRef{Key: row.Key, Node: row.Node, Generation: row.Generation})
		summary := summaries[row.Node]
		summary.Node = row.Node
		summary.Owner = row.Owner
		summary.Instances++
		summary.Listeners += countIngressListeners(row.Node, row.Spec.Listeners, listenerSeen)
		summary.BufferBytes += row.Spec.BufferBytes
		quotaTenant := q.Tenant
		if !system && quotaTenant == "" {
			quotaTenant = row.Tenant
		}
		quotaKey := row.Node + "/" + quotaTenant
		if !quotaSeen[quotaKey] {
			if lim, ok := projection.Resources.Quotas.Limit(quotaTenant, row.Node); ok {
				summary.MaxIngressInstances += lim.MaxIngressInstances
				summary.MaxIngressListeners += lim.MaxIngressListeners
				summary.MaxIngressRequests += lim.MaxIngressRequests
				summary.MaxIngressConnections += lim.MaxIngressConnections
				summary.IngressBufferBytes += lim.IngressBufferBytes
				quotaSeen[quotaKey] = true
			}
		}

		summaries[row.Node] = summary
		if key > q.After && len(out.Mappings) < 1 {
			out.Mappings = append(out.Mappings, row)
		} else if key > q.After && out.Next == "" {
			out.Next = out.Mappings[len(out.Mappings)-1].Key
		}
	}
	for _, row := range out.Mappings {
		if sum, ok := summaries[row.Node]; ok {
			out.Nodes = append(out.Nodes, sum)
			delete(summaries, row.Node)
		}
	}
	if q.Node != "" && len(out.Nodes) == 0 && q.Part != "blocks" {
		visible := system
		var tenants []string
		if q.Tenant != "" {
			visible = allowed(q.Tenant, q.Node)
			tenants = []string{q.Tenant}
		} else if system {
			tenants = []string{""}
		} else {
			for _, tenant := range c.Tenants() {
				if allowed(tenant.ID, q.Node) {
					visible = true
					tenants = append(tenants, tenant.ID)
				}
			}
		}
		if visible {
			owner, err := p.nodeOwner(s, q.Node)
			if err == nil {
				summary := IngressNodeSummary{Node: q.Node, Owner: owner}
				for _, tenant := range tenants {
					if limit, ok := projection.Resources.Quotas.Limit(tenant, q.Node); ok {
						summary.MaxIngressInstances += limit.MaxIngressInstances
						summary.MaxIngressListeners += limit.MaxIngressListeners
						summary.MaxIngressRequests += limit.MaxIngressRequests
						summary.MaxIngressConnections += limit.MaxIngressConnections
						summary.IngressBufferBytes += limit.IngressBufferBytes
					}
				}
				out.Nodes = append(out.Nodes, summary)
			}
		}
	}
	slices.SortFunc(out.Nodes, func(a, b IngressNodeSummary) int { return strings.Compare(a.Node, b.Node) })
	if q.Part == "blocks" {
		out.Next = ""
		start := min(int(q.Offset), len(out.Blocks))
		end := min(start+8, len(out.Blocks))
		if end < len(out.Blocks) {
			out.Next = fmt.Sprint(end)
		}
		out.Blocks = slices.Clone(out.Blocks[start:end])
		out.Mappings = nil
		out.Nodes = nil
		if q.Node != "" && len(out.Blocks) > 0 {
			owner, err := p.nodeOwner(s, q.Node)
			if err == nil {
				out.Nodes = []IngressNodeSummary{{Node: q.Node, Owner: owner}}
			}
		}
	} else {
		out.Blocks = nil
	}
	return out, nil
}

// Only call after the row's tenant/node visibility has been checked. The same
// shared listener is one address even when several visible apps borrow it.
func countIngressListeners(node string, listeners []ingress.Listener, seen map[string]bool) int {
	count := 0
	for _, listener := range listeners {
		id := node + "\x00direct\x00" + listener.Address
		if listener.Shared != "" {
			id = node + "\x00shared\x00" + listener.Shared
		}
		if !seen[id] {
			seen[id] = true
			count++
		}
	}
	return count
}

func ingressBlockMaps(b ingress.Block, row IngressMapping) bool {
	if b.Node != "" && b.Node != row.Node || b.Tenant != "" && b.Tenant != row.Tenant || b.App != "" && b.App != row.App || b.Key != "" && b.Key != row.Key {
		return false
	}
	switch b.Scope {
	case "host", "route":
		for _, route := range row.Spec.Routes {
			if route.Host == b.Host && (b.Scope == "host" || route.Prefix == b.Prefix) {
				return true
			}
		}
		return false
	case "backend":
		for _, svc := range row.Spec.Services {
			if svc.ID == b.Service {
				for _, backend := range svc.Backends {
					if backend.ID == b.Backend {
						return true
					}
				}
			}
		}
		return false
	case "source":
		return len(b.Apps) == 0 || slices.Contains(b.Apps, row.App)
	}
	return true
}

func ingressBlockTargetMissing(b ingress.Block, projection ResourceProjection) bool {
	if b.Scope == "node" || b.Scope == "tenant" || b.Scope == "source" || b.Scope == "gateway" {
		return false
	}
	for key, g := range projection.Goals {
		if g.Ingress == nil {
			continue
		}
		row := IngressMapping{Key: key, Tenant: g.Goal.Tenant, App: g.Goal.App, Node: g.Goal.Node, Spec: *g.Ingress}
		if ingressBlockMaps(b, row) {
			return false
		}
	}
	return true
}

// ingressManagementBook is the IngressManagementKey book (books.go).
var ingressManagementBook = Book{Key: IngressManagementKey, Reduce: Policy.reduceIngressManagement}
