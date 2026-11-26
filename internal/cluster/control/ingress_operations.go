// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/ingress"
)

type NodeGatewaysChange struct {
	Node            string
	External, Local *ingress.Gateway      `json:",omitempty"`
	Evidence        *NodeGatewaysEvidence `json:",omitempty"`
}
type NodeGatewaysCheck struct {
	Node            string
	External, Local *ingress.Gateway `json:",omitempty"`
	Expected        uint64
	Request         string
}
type NodeGatewaysEvidence struct {
	Cluster, Reporter       [32]byte
	Node, Request, User     string
	Key                     [32]byte
	Epoch, Expected         uint64
	At                      int64
	Previous, Configuration ingress.GatewayConfiguration
	Signature               []byte
}

func NodeGatewaysEvidenceBytes(e NodeGatewaysEvidence) []byte {
	e.Signature = nil
	raw, _ := json.Marshal(e)
	return append([]byte("mydc-node-gateways-1\x00"), raw...)
}
func MergeNodeGateways(previous ingress.GatewayConfiguration, external, local *ingress.Gateway) ingress.GatewayConfiguration {
	if external != nil {
		previous.External = *external
	}
	if local != nil {
		previous.Local = *local
	}
	return ingress.NormalizeGatewayConfiguration(previous)
}

type NodeGatewaysRecord struct {
	Node          string
	Configuration ingress.GatewayConfiguration
	Revision      uint64
	Origin        UserOperation
}
type NodeGatewaysView struct {
	Node, Source              string
	Revision, AppliedRevision uint64
	Configuration             ingress.GatewayConfiguration
	Error                     string `json:",omitempty"`
}
type IngressBalanceChange struct {
	Tenant, App, Route string
	Balance            ingress.Balance
}
type IngressBalanceRecord struct {
	IngressBalanceChange
	Revision uint64
	Origin   UserOperation
}
type IngressDrainChange struct {
	Tenant, App, Node string
	DrainSeconds      uint64 `json:",omitempty"`
}
type IngressDrainRecord struct {
	IngressDrainChange
	Revision, Order, StartedAt, Deadline uint64
	Draining, LastMapping                bool
	Origin                               UserOperation
}
type IngressHistoryRecord struct {
	AffectedApps                      []string `json:",omitempty"`
	Order                             uint64
	Origin                            UserOperation
	Tenant, App, Node, Route, Gateway string
	Detail, Previous                  json.RawMessage `json:",omitempty"`
}
type IngressHistoryView struct {
	At                                                        int64
	Actor, Action, Request, Tenant, App, Node, Route, Gateway string
	Detail, Previous                                          json.RawMessage `json:",omitempty"`
}

func extendedIngressAction(action string) bool {
	switch action {
	case "set-node-gateways", "set-ingress-balance", "drain-ingress", "undrain-ingress":
		return true
	}
	return false
}
func (b IngressManagement) NodeGateways(node string) (NodeGatewaysRecord, bool) {
	for _, r := range b.NodeGatewaysRecords {
		if r.Node == node {
			return r, true
		}
	}
	return NodeGatewaysRecord{}, false
}
func (b IngressManagement) Balance(tenant, app, route string) (IngressBalanceRecord, bool) {
	for _, r := range b.Balances {
		if r.Tenant == tenant && r.App == app && r.Route == route {
			return r, true
		}
	}
	return IngressBalanceRecord{}, false
}
func (b IngressManagement) Drain(tenant, app, node string) (IngressDrainRecord, bool) {
	var out IngressDrainRecord
	found := false
	for _, r := range b.Drains {
		if r.Tenant == tenant && r.App == app && (r.Node == "" || r.Node == node) && (!found || r.Order > out.Order) {
			out, found = r, true
		}
	}
	return out, found
}
func validGatewayConfiguration(c ingress.GatewayConfiguration) bool {
	return c.Validate() == nil && len(c.External.AllowedSources) == 0
}
func (p Policy) validNodeGatewaysEvidence(s state.State, op UserOperation, q NodeGatewaysChange) bool {
	e := q.Evidence
	if e == nil || e.Cluster != p.Cluster || e.Node != q.Node || e.Request != op.RequestID || e.User != op.Session.User || e.Key != op.Session.Key || e.Expected != op.Change.Expected || e.Epoch != op.Epoch || e.At <= 0 || e.At > op.At || op.At-e.At > 30 || !validGatewayConfiguration(e.Configuration) || !buildJSONEqual(e.Configuration, MergeNodeGateways(e.Previous, q.External, q.Local)) || !ed25519.Verify(e.Reporter[:], NodeGatewaysEvidenceBytes(*e), e.Signature) {
		return false
	}
	owner, err := p.workNodeOwner(s, q.Node)
	return err == nil && owner == e.Reporter
}
func (p Policy) authorizeIngressOperation(s state.State, c access.Catalog, op UserOperation) error {
	if c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return access.ErrDenied
	}
	if op.Change.Action == "set-node-gateways" {
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
	}
	var tenant, app, node string
	if op.Change.Action == "set-ingress-balance" {
		var q IngressBalanceChange
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		tenant, app = q.Tenant, q.App
	} else {
		var q IngressDrainChange
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		tenant, app, node = q.Tenant, q.App, q.Node
	}
	if !validID(tenant) || !validID(app) || node != "" && !validID(node) {
		return access.ErrInvalid
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, tenant, access.ManageNetwork, node)
}
func (p Policy) reduceIngressOperation(s state.State, book *IngressManagement, op UserOperation) (IngressHistoryRecord, state.Code) {
	h := IngressHistoryRecord{Order: book.Revision + 1, Origin: op}
	switch op.Change.Action {
	case "set-node-gateways":
		var q NodeGatewaysChange
		if canonical(op.Change.Payload, &q) != nil || !validID(q.Node) || q.External == nil && q.Local == nil || !p.validNodeGatewaysEvidence(s, op, q) {
			return h, state.Invalid
		}
		old, found := book.NodeGateways(q.Node)
		if found && (old.Revision != op.Change.Expected || !buildJSONEqual(old.Configuration, q.Evidence.Previous)) || !found && op.Change.Expected != 0 {
			return h, state.ConditionFailed
		}
		next := NodeGatewaysRecord{q.Node, q.Evidence.Configuration, op.Change.Expected + 1, op}
		if next.Revision == 0 {
			return h, state.ConditionFailed
		}
		candidate, err := nodeGatewayHostPortUse(q.Node, q.Evidence.Reporter, next.Configuration)
		if err != nil {
			return h, state.Invalid
		}
		projection, err := p.ProjectResources(s)
		if err != nil {
			return h, state.Invalid
		}
		uses := projection.HostPorts
		if found {
			var original NodeGatewaysChange
			if canonical(old.Origin.Change.Payload, &original) != nil || original.Node != q.Node || original.Evidence == nil || !p.ownsResource(s, q.Evidence.Reporter, original.Evidence.Reporter) {
				return h, state.Forbidden
			}
			previous, err := nodeGatewayHostPortUse(q.Node, original.Evidence.Reporter, old.Configuration)
			if err != nil {
				return h, state.Invalid
			}
			// CAS and current node evidence authorize replacing only this exact
			// original gateway claim. Its accepted old owner remains reserved in
			// every other projection, including after an identity rotation.
			uses = make([]deployment.HostPortUse, 0, len(projection.HostPorts))
			matched := len(previous.Ports) == 0
			for _, use := range projection.HostPorts {
				if use.Key == previous.Key && use.Node == previous.Node && use.Owner == previous.Owner && slices.Equal(use.Ports, previous.Ports) {
					matched = true
					continue
				}
				uses = append(uses, use)
			}
			if !matched {
				return h, state.Invalid
			}
		}
		if deployment.CheckHostPortUses(uses, candidate) != nil {
			return h, state.Invalid
		}
		if found {
			for i := range book.NodeGatewaysRecords {
				if book.NodeGatewaysRecords[i].Node == q.Node {
					book.NodeGatewaysRecords[i] = next
				}
			}
		} else {
			book.NodeGatewaysRecords = append(book.NodeGatewaysRecords, next)
		}
		h.Node = q.Node
		h.Detail, _ = json.Marshal(next.Configuration)
		h.Previous, _ = json.Marshal(q.Evidence.Previous)
	case "set-ingress-balance":
		var q IngressBalanceChange
		if canonical(op.Change.Payload, &q) != nil || !validID(q.Route) || q.Balance.Validate() != nil {
			return h, state.Invalid
		}
		projection, err := p.ProjectResources(s)
		if err != nil {
			return h, state.Invalid
		}
		found := false
		var previous *ingress.Balance
		for _, g := range projection.Goals {
			if g.Ingress == nil || g.Goal.Tenant != q.Tenant || g.Goal.App != q.App {
				continue
			}
			for _, route := range g.Ingress.Routes {
				if route.ID == q.Route {
					found = true
					previous = route.Balance
					candidate := *g.Ingress
					candidate.Routes = slices.Clone(candidate.Routes)
					for i := range candidate.Routes {
						if candidate.Routes[i].ID == q.Route {
							candidate.Routes[i].Balance = &q.Balance
						}
					}
					if _, err = ingress.DecodeSpec(jsonString(candidate)); err != nil {
						return h, state.Invalid
					}
				}
			}
		}
		if !found {
			return h, state.Invalid
		}
		old, exists := book.Balance(q.Tenant, q.App, q.Route)
		if exists {
			previous = &old.Balance
		}
		if exists && old.Revision != op.Change.Expected || !exists && op.Change.Expected != 0 || op.Change.Expected == math.MaxUint64 {
			return h, state.ConditionFailed
		}
		row := IngressBalanceRecord{q, op.Change.Expected + 1, op}
		if exists {
			for i := range book.Balances {
				r := book.Balances[i]
				if r.Tenant == q.Tenant && r.App == q.App && r.Route == q.Route {
					book.Balances[i] = row
				}
			}
		} else {
			book.Balances = append(book.Balances, row)
		}
		h.Tenant, h.App, h.Route = q.Tenant, q.App, q.Route
		h.Detail, _ = json.Marshal(q.Balance)
		h.Previous, _ = json.Marshal(previous)
	case "drain-ingress", "undrain-ingress":
		var q IngressDrainChange
		if canonical(op.Change.Payload, &q) != nil || q.DrainSeconds > 3600 || op.Change.Action == "undrain-ingress" && q.DrainSeconds != 0 {
			return h, state.Invalid
		}
		projection, err := p.ProjectResources(s)
		if err != nil {
			return h, state.Invalid
		}
		selected, remaining := 0, 0
		for _, g := range projection.Goals {
			if g.Ingress != nil && g.Goal.Tenant == q.Tenant && g.Goal.App == q.App {
				if q.Node == "" || g.Goal.Node == q.Node {
					selected++
				} else {
					prior, found := book.Drain(q.Tenant, q.App, g.Goal.Node)
					if !g.Ingress.Lifecycle.Drain && (!found || !prior.Draining) {
						remaining++
					}
				}
			}
		}
		if selected == 0 {
			return h, state.Invalid
		}
		index := -1
		for i, r := range book.Drains {
			if r.Tenant == q.Tenant && r.App == q.App && r.Node == q.Node {
				index = i
			}
		}
		revision := uint64(0)
		if index >= 0 {
			revision = book.Drains[index].Revision
			h.Previous, _ = json.Marshal(book.Drains[index].IngressDrainChange)
		}
		if op.Change.Expected != revision || revision == math.MaxUint64 {
			return h, state.ConditionFailed
		}
		row := IngressDrainRecord{IngressDrainChange: q, Revision: revision + 1, Order: book.Revision + 1, Draining: op.Change.Action == "drain-ingress", LastMapping: op.Change.Action == "drain-ingress" && remaining == 0, Origin: op}
		if row.Draining {
			if row.DrainSeconds == 0 {
				row.DrainSeconds = 30
			}
			row.StartedAt = uint64(op.At)
			row.Deadline = row.StartedAt + row.DrainSeconds
		}
		if index >= 0 {
			book.Drains[index] = row
		} else {
			book.Drains = append(book.Drains, row)
		}
		h.Tenant, h.App, h.Node = q.Tenant, q.App, q.Node
		h.Detail, _ = json.Marshal(struct {
			Draining, LastMapping  bool
			DrainSeconds, Deadline uint64
		}{row.Draining, row.LastMapping, row.DrainSeconds, row.Deadline})
	default:
		return h, state.Invalid
	}
	return h, state.Applied
}
func jsonString(v any) string { raw, _ := json.Marshal(v); return string(raw) }
func validateIngressOperations(b IngressManagement) bool {
	seen := map[string]bool{}
	for _, r := range b.NodeGatewaysRecords {
		var q NodeGatewaysChange
		if !validID(r.Node) || r.Revision == 0 || seen["g/"+r.Node] || !validGatewayConfiguration(r.Configuration) || r.Origin.VerifyOriginal(b.Cluster) != nil || r.Origin.Change.Action != "set-node-gateways" || r.Origin.Change.Expected+1 != r.Revision || canonical(r.Origin.Change.Payload, &q) != nil || q.Node != r.Node || q.Evidence == nil || !buildJSONEqual(q.Evidence.Configuration, r.Configuration) || !ed25519.Verify(q.Evidence.Reporter[:], NodeGatewaysEvidenceBytes(*q.Evidence), q.Evidence.Signature) {
			return false
		}
		seen["g/"+r.Node] = true
	}
	for _, r := range b.Balances {
		var q IngressBalanceChange
		k := "b/" + r.Tenant + "/" + r.App + "/" + r.Route
		if seen[k] || r.Revision == 0 || r.Balance.Validate() != nil || r.Origin.VerifyOriginal(b.Cluster) != nil || r.Origin.Change.Action != "set-ingress-balance" || r.Origin.Change.Expected+1 != r.Revision || canonical(r.Origin.Change.Payload, &q) != nil || !buildJSONEqual(q, r.IngressBalanceChange) {
			return false
		}
		seen[k] = true
	}
	for _, r := range b.Drains {
		var q IngressDrainChange
		k := "d/" + r.Tenant + "/" + r.App + "/" + r.Node
		if seen[k] || r.Revision == 0 || r.Order == 0 || r.Order > b.Revision || r.Origin.VerifyOriginal(b.Cluster) != nil || r.Origin.Change.Expected+1 != r.Revision || canonical(r.Origin.Change.Payload, &q) != nil || q.Tenant != r.Tenant || q.App != r.App || q.Node != r.Node || r.Draining != (r.Origin.Change.Action == "drain-ingress") || !r.Draining && r.Origin.Change.Action != "undrain-ingress" || r.Draining && (r.DrainSeconds == 0 || r.DrainSeconds > 3600 || r.StartedAt != uint64(r.Origin.At) || r.Deadline != r.StartedAt+r.DrainSeconds) {
			return false
		}
		seen[k] = true
	}
	var order uint64
	for _, h := range b.History {
		if h.Order <= order || h.Order > b.Revision || h.Origin.VerifyOriginal(b.Cluster) != nil || !validIngressHistoryScope(h) {
			return false
		}
		order = h.Order
	}
	return len(b.History) <= 4096 && len(b.NodeGatewaysRecords) <= 256 && len(b.Balances) <= 4096 && len(b.Drains) <= 4096
}

type ingressHistoryCursor struct {
	Before uint64
	Scope  [32]byte
}

func ingressHistoryBasis(revision uint64, session access.Session, q IngressQuery) [32]byte {
	basis := struct {
		Catalog           uint64
		Session           [32]byte
		Tenant, App, Node string
	}{revision, sha256.Sum256(access.SessionBytes(session)), q.Tenant, q.App, q.Node}
	raw, _ := json.Marshal(basis)
	return sha256.Sum256(raw)
}

func (b IngressManagement) historyPage(q IngressQuery, scope [32]byte, visible func(IngressHistoryRecord) bool) ([]IngressHistoryView, string, error) {
	before := b.Revision + 1
	if q.After != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.After)
		var cursor ingressHistoryCursor
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.Scope != scope || cursor.Before == 0 || cursor.Before > before {
			return nil, "", access.ErrInvalid
		}
		before = cursor.Before
	}
	var out []IngressHistoryView
	bytesUsed := 0
	for i := len(b.History) - 1; i >= 0; i-- {
		h := b.History[i]
		if h.Order >= before || q.Tenant != "" && h.Tenant != q.Tenant || q.App != "" && h.App != q.App && !slices.Contains(h.AffectedApps, q.App) || q.Node != "" && h.Node != "" && h.Node != q.Node || !visible(h) {
			continue
		}
		view := IngressHistoryView{At: h.Origin.At, Actor: h.Origin.Session.User, Action: h.Origin.Change.Action, Request: h.Origin.RequestID, Tenant: h.Tenant, App: h.App, Node: h.Node, Route: h.Route, Gateway: h.Gateway, Detail: slices.Clone(h.Detail), Previous: slices.Clone(h.Previous)}
		encoded, _ := json.Marshal(view)
		if len(out) == 8 || len(out) > 0 && bytesUsed+len(encoded) > 80<<10 {
			raw, _ := json.Marshal(ingressHistoryCursor{Before: before, Scope: scope})
			return out, base64.RawURLEncoding.EncodeToString(raw), nil
		}
		out = append(out, view)
		bytesUsed += len(encoded)
		before = h.Order
	}
	return out, "", nil
}

func (b IngressManagement) ApplyMapping(row *IngressMapping) {
	row.Spec.Routes = slices.Clone(row.Spec.Routes)
	for i := range row.Spec.Routes {
		route := &row.Spec.Routes[i]
		if r, ok := b.Balance(row.Tenant, row.App, route.ID); ok {
			route.OriginalBalance = route.Balance
			route.Balance = &r.Balance
			route.BalanceRevision = r.Revision
		}
	}
	if r, ok := b.Drain(row.Tenant, row.App, row.Node); ok {
		row.DrainRevision, row.DrainStartedAt, row.DrainDeadline, row.LastMapping = r.Revision, r.StartedAt, r.Deadline, r.LastMapping
		row.Draining = row.Draining || r.Draining
	}
}
func (b IngressManagement) Controls(node string) []ingress.RuntimeControl {
	var out []ingress.RuntimeControl
	for _, r := range b.Balances {
		out = append(out, ingress.RuntimeControl{Tenant: r.Tenant, App: r.App, Route: r.Route, Balance: &r.Balance, Revision: r.Revision})
	}
	// Multiple matching drain scopes are resolved by the latest original intent.
	for _, r := range b.Drains {
		out = append(out, ingress.RuntimeControl{Tenant: r.Tenant, App: r.App, Node: r.Node, Revision: r.Order, Drain: &ingress.ControlDrain{Revision: r.Order, Draining: r.Draining, StartedAt: r.StartedAt, Deadline: r.Deadline}})
	}
	return out
}

func validIngressGatewayCheck(q IngressQuery) bool {
	if q.Check == nil {
		return true
	}
	c := q.Check
	return q.Part == "gateways" && q.Node == c.Node && len(c.Request) > 0 && len(c.Request) <= 512 && (c.External != nil || c.Local != nil)
}

func validIngressHistoryScope(h IngressHistoryRecord) bool {
	var tenant, app, node, route, gateway string
	switch h.Origin.Change.Action {
	case "set-node-gateways":
		var q NodeGatewaysChange
		if canonical(h.Origin.Change.Payload, &q) != nil {
			return false
		}
		node = q.Node
	case "set-ingress-balance":
		var q IngressBalanceChange
		if canonical(h.Origin.Change.Payload, &q) != nil {
			return false
		}
		tenant, app, route = q.Tenant, q.App, q.Route
	case "drain-ingress", "undrain-ingress":
		var q IngressDrainChange
		if canonical(h.Origin.Change.Payload, &q) != nil {
			return false
		}
		tenant, app, node = q.Tenant, q.App, q.Node
	case "set-ingress-host-policy":
		var q IngressHostPolicyChange
		if canonical(h.Origin.Change.Payload, &q) != nil {
			return false
		}
		tenant = q.Tenant
	case "ingress-block", "ingress-unblock", "ingress-block-extend":
		var block ingress.Block
		if json.Unmarshal(h.Detail, &block) != nil || !block.Valid() {
			return false
		}
		tenant, app, node, route, gateway = block.Tenant, block.App, block.Node, block.Route, block.Gateway
	default:
		return false
	}
	return h.Tenant == tenant && h.App == app && h.Node == node && h.Route == route && h.Gateway == gateway
}
