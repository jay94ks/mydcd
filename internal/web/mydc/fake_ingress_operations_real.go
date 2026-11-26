// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/ingress"
)

// REQ-62~65 in mydcd's real shape (docs/reference/ingress-management.md
// "Gateway·분배·drain 변경과 공개 이력", control/ingress_operations.go):
//
//   - set-node-gateways control.NodeGatewaysChange{Node, External?, Local?}
//     (*ingress.Gateway). Prepare adds the node's Evidence, as
//     userauth.Client.Prepare does with Part gateways + Check; a payload that
//     already carries Evidence is invalid.
//   - set-ingress-balance control.IngressBalanceChange{Tenant, App, Route,
//     Balance ingress.Balance}.
//   - drain-ingress / undrain-ingress control.IngressDrainChange{Tenant, App,
//     Node?, DrainSeconds?}.
//
// Expected is the record's Revision (first 0), not the Raft root revision.
// Reads are `ingresses` Part gateways (NodeGateways, system admin, one Node)
// and Part history (IngressHistoryView, newest first, 8 a page, Next →
// After). Mappings carry the balance / drain overlay (route
// BalanceRevision / OriginalBalance, DrainRevision / DrainStartedAt /
// DrainDeadline / LastMapping).

// FailNodeGateways makes the node's gateway bind fail: NodeGateways keeps
// the earlier AppliedRevision and shows msg as Error ("" = binds again).
func (f *Fake) FailNodeGateways(node, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := &f.w.ireal
	if b.gwError == nil {
		b.gwError = map[string]string{}
	}
	if msg == "" {
		delete(b.gwError, node)
		if r, ok := b.nodeGateways(node); ok {
			b.gwApplied[node] = r.Revision
		}
		return
	}
	b.gwError[node] = msg
}

func (b *ingressRealState) nodeGateways(node string) (control.NodeGatewaysRecord, bool) {
	for _, r := range b.gateways {
		if r.Node == node {
			return r, true
		}
	}
	return control.NodeGatewaysRecord{}, false
}

func (b *ingressRealState) management() control.IngressManagement {
	return control.IngressManagement{Schema: 1, Revision: b.revision, NodeGatewaysRecords: b.gateways, Balances: b.balances, Drains: b.drains}
}

// fileGateways: the node's file configuration (the seeded gateways). An
// enabled side without a shared listener gets one on its first address
// and port so the configuration validates.
func (w *world) fileGateways(node string) ingress.GatewayConfiguration {
	var c ingress.GatewayConfiguration
	for _, g := range w.ing.gateways[node] {
		out := ingress.Gateway{Enabled: g.Enabled}
		for _, a := range g.Addresses {
			if ip, err := netip.ParseAddr(a); err == nil {
				out.Addresses = append(out.Addresses, ip)
			}
		}
		for _, p := range g.Ports {
			out.Ports = append(out.Ports, uint16(p))
		}
		for _, s := range g.AllowedSources {
			if p, err := netip.ParsePrefix(s); err == nil {
				out.AllowedSources = append(out.AllowedSources, p)
			}
		}
		seen := map[string]bool{}
		for _, in := range w.ing.instances {
			for _, l := range in.Listeners {
				if in.Node == node && l.Shared && l.Gateway == g.Kind && !seen[l.ID] {
					seen[l.ID] = true
					out.Listeners = append(out.Listeners, ingress.Listener{ID: l.ID, Address: l.Address, TLS: l.TLS, HTTP3: l.HTTP3})
				}
			}
		}
		if g.Enabled && len(out.Listeners) == 0 && len(out.Addresses) > 0 && len(out.Ports) > 0 {
			out.Listeners = []ingress.Listener{{ID: fmt.Sprintf("%s-%s-%d", node, g.Kind, out.Ports[0]), Address: netip.AddrPortFrom(out.Addresses[0], out.Ports[0]).String(), TLS: true}}
		}
		if g.Kind == GatewayExternal {
			c.External = out
		} else {
			c.Local = out
		}
	}
	return ingress.NormalizeGatewayConfiguration(c)
}

func (w *world) gatewayConfiguration(node string) ingress.GatewayConfiguration {
	if r, ok := w.ireal.nodeGateways(node); ok {
		return r.Configuration
	}
	return w.fileGateways(node)
}

func (w *world) nodeGatewaysView(node string) control.NodeGatewaysView {
	b := &w.ireal
	v := control.NodeGatewaysView{Node: node, Source: "file", Configuration: w.fileGateways(node), Error: b.gwError[node]}
	if r, ok := b.nodeGateways(node); ok {
		v.Source, v.Configuration, v.Revision, v.AppliedRevision = "cluster", r.Configuration, r.Revision, b.gwApplied[node]
	}
	return v
}

// gatewayEvidence: the work owner's preflight for one set-node-gateways
// intent (CheckError "" when the merged configuration is acceptable).
func (w *world) gatewayEvidence(node, request string, user string, key [32]byte, expected uint64, at int64, external, local *ingress.Gateway) (*control.NodeGatewaysEvidence, string) {
	if w.memberIndex(node) < 0 {
		return nil, "unknown node"
	}
	prev := w.gatewayConfiguration(node)
	next := control.MergeNodeGateways(prev, external, local)
	if err := next.Validate(); err != nil || len(next.External.AllowedSources) > 0 {
		return nil, "configuration"
	}
	if have, ok := w.ing.nodeAddrs[node]; ok {
		for _, g := range []ingress.Gateway{next.External, next.Local} {
			for _, a := range g.Addresses {
				if !slices.Contains(have, a.String()) {
					return nil, a.String() + " is not an address of " + node
				}
			}
		}
	}
	e := control.NodeGatewaysEvidence{Cluster: w.cluster, Reporter: pub32(FixtureKey(node)), Node: node, Request: request, User: user, Key: key,
		Epoch: w.ledgerEpoch, Expected: expected, At: at, Previous: prev, Configuration: next}
	e.Signature = ed25519.Sign(FixtureKey(node), control.NodeGatewaysEvidenceBytes(e))
	return &e, ""
}

// prepareGatewayEvidence: fake Prepare's part of userauth.Client.Prepare.
func (c *fakeConn) prepareGatewayEvidence(change *Change, requestID string, at int64) error {
	if change.Action != ActionSetNodeGateways {
		return nil
	}
	var q control.NodeGatewaysChange
	if decodePayload(change.Payload, &q) != nil || q.Evidence != nil || q.External == nil && q.Local == nil {
		return fail("prepare", CodeInvalid, "set-node-gateways payload")
	}
	e, why := c.f.w.gatewayEvidence(q.Node, requestID, c.session.User, c.session.Key, change.Expected, at, q.External, q.Local)
	if e == nil {
		return fail("prepare", CodeInvalid, why)
	}
	q.Evidence = e
	raw, err := json.Marshal(q)
	if err != nil {
		return fail("prepare", CodeInvalid, err.Error())
	}
	change.Payload = raw
	return nil
}

func (c *fakeConn) applyIngressOperation(op UserOperation, actor string) error {
	w := c.f.w
	ch := op.Change
	book := &w.ireal
	if book.revision == math.MaxUint64 {
		return errors.New("revision")
	}
	if len(book.history) >= 4096 {
		return errCAS
	}
	h := control.IngressHistoryRecord{Order: book.revision + 1, Origin: op}
	switch ch.Action {
	case ActionSetNodeGateways:
		var q control.NodeGatewaysChange
		if decodePayload(ch.Payload, &q) != nil || q.Node == "" || q.External == nil && q.Local == nil {
			return errors.New("payload")
		}
		if !w.admin(actor) {
			return errForbidden
		}
		e := q.Evidence
		if e == nil || e.Cluster != w.cluster || e.Node != q.Node || e.Request != op.RequestID || e.User != op.Session.User || e.Key != op.Session.Key || e.Expected != ch.Expected ||
			e.At <= 0 || e.At > op.At || op.At-e.At > 30 || e.Reporter != pub32(FixtureKey(q.Node)) || !ed25519.Verify(e.Reporter[:], control.NodeGatewaysEvidenceBytes(*e), e.Signature) ||
			!jsonEqual(e.Configuration, control.MergeNodeGateways(e.Previous, q.External, q.Local)) || e.Configuration.Validate() != nil {
			return errors.New("gateway evidence")
		}
		old, found := book.nodeGateways(q.Node)
		if found && (old.Revision != ch.Expected || !jsonEqual(old.Configuration, e.Previous)) || !found && ch.Expected != 0 {
			return errCAS
		}
		next := control.NodeGatewaysRecord{Node: q.Node, Configuration: e.Configuration, Revision: ch.Expected + 1, Origin: op}
		if found {
			for i := range book.gateways {
				if book.gateways[i].Node == q.Node {
					book.gateways[i] = next
				}
			}
		} else {
			book.gateways = append(book.gateways, next)
		}
		if book.gwApplied == nil {
			book.gwApplied = map[string]uint64{}
		}
		if book.gwError[q.Node] == "" {
			book.gwApplied[q.Node] = next.Revision
		}
		w.syncGatewayRows(q.Node, next.Configuration)
		h.Node = q.Node
		h.Detail, _ = json.Marshal(next.Configuration)
		h.Previous, _ = json.Marshal(e.Previous)

	case ActionSetIngressBalance:
		var q control.IngressBalanceChange
		if decodePayload(ch.Payload, &q) != nil || q.Tenant == "" || q.App == "" || q.Route == "" || q.Balance.Validate() != nil {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		found := false
		for _, in := range w.ing.instances {
			if in.Tenant == q.Tenant && in.App == q.App && slices.ContainsFunc(in.Routes, func(r IngressRoute) bool { return r.ID == q.Route }) {
				found = true
			}
		}
		if !found {
			return errors.New("no such route")
		}
		var previous *ingress.Balance
		i := slices.IndexFunc(book.balances, func(r control.IngressBalanceRecord) bool {
			return r.Tenant == q.Tenant && r.App == q.App && r.Route == q.Route
		})
		revision := uint64(0)
		if i >= 0 {
			revision = book.balances[i].Revision
			p := book.balances[i].Balance
			previous = &p
		}
		if ch.Expected != revision || revision == math.MaxUint64 {
			return errCAS
		}
		row := control.IngressBalanceRecord{IngressBalanceChange: q, Revision: revision + 1, Origin: op}
		if i >= 0 {
			book.balances[i] = row
		} else {
			book.balances = append(book.balances, row)
		}
		h.Tenant, h.App, h.Route = q.Tenant, q.App, q.Route
		h.Detail, _ = json.Marshal(q.Balance)
		h.Previous, _ = json.Marshal(previous)

	case ActionDrainIngress, ActionUndrainIngress:
		var q control.IngressDrainChange
		if decodePayload(ch.Payload, &q) != nil || q.Tenant == "" || q.App == "" || q.DrainSeconds > 3600 || ch.Action == ActionUndrainIngress && q.DrainSeconds != 0 {
			return errors.New("payload")
		}
		if !w.canManage(actor, q.Tenant) {
			return errForbidden
		}
		mb := book.management()
		selected, remaining := 0, 0
		for _, in := range w.ing.instances {
			if in.Tenant != q.Tenant || in.App != q.App {
				continue
			}
			if q.Node == "" || in.Node == q.Node {
				selected++
			} else if prior, ok := mb.Drain(q.Tenant, q.App, in.Node); !in.Draining && (!ok || !prior.Draining) {
				remaining++
			}
		}
		if selected == 0 {
			return errors.New("no such ingress instance")
		}
		i := slices.IndexFunc(book.drains, func(r control.IngressDrainRecord) bool {
			return r.Tenant == q.Tenant && r.App == q.App && r.Node == q.Node
		})
		revision := uint64(0)
		if i >= 0 {
			revision = book.drains[i].Revision
			h.Previous, _ = json.Marshal(book.drains[i].IngressDrainChange)
		}
		if ch.Expected != revision || revision == math.MaxUint64 {
			return errCAS
		}
		drain := ch.Action == ActionDrainIngress
		row := control.IngressDrainRecord{IngressDrainChange: q, Revision: revision + 1, Order: book.revision + 1, Draining: drain, LastMapping: drain && remaining == 0, Origin: op}
		if drain {
			if row.DrainSeconds == 0 {
				row.DrainSeconds = 30
			}
			row.StartedAt = uint64(op.At)
			row.Deadline = row.StartedAt + row.DrainSeconds
		}
		if i >= 0 {
			book.drains[i] = row
		} else {
			book.drains = append(book.drains, row)
		}
		// The installed runtime follows the latest drain intent.
		for j := range w.ing.instances {
			in := &w.ing.instances[j]
			if in.Tenant == q.Tenant && in.App == q.App && (q.Node == "" || in.Node == q.Node) {
				in.Draining, in.Ready = drain, !drain
				in.DrainStartedAt, in.DrainUntil = 0, 0
				if drain {
					in.DrainStartedAt, in.DrainUntil = int64(row.StartedAt), int64(row.Deadline)
				}
			}
		}
		h.Tenant, h.App, h.Node = q.Tenant, q.App, q.Node
		h.Detail, _ = json.Marshal(struct {
			Draining, LastMapping  bool
			DrainSeconds, Deadline uint64
		}{row.Draining, row.LastMapping, row.DrainSeconds, row.Deadline})
	default:
		return errors.New("action")
	}
	book.history = append(book.history, h)
	book.revision++
	return nil
}

// syncGatewayRows keeps the seeded gateway rows (Nodes[].Gateways counters,
// the old mock) in step with an accepted cluster configuration.
func (w *world) syncGatewayRows(node string, c ingress.GatewayConfiguration) {
	var rows []IngressGateway
	for _, side := range []struct {
		kind string
		g    ingress.Gateway
	}{{GatewayExternal, c.External}, {GatewayLocal, c.Local}} {
		if !side.g.Enabled && len(side.g.Addresses) == 0 {
			continue
		}
		g := IngressGateway{Kind: side.kind, Enabled: side.g.Enabled, State: "down"}
		if g.Enabled {
			g.State = "up"
		}
		for _, a := range side.g.Addresses {
			g.Addresses = append(g.Addresses, a.String())
		}
		for _, p := range side.g.Ports {
			g.Ports = append(g.Ports, int(p))
		}
		for _, p := range side.g.AllowedSources {
			g.AllowedSources = append(g.AllowedSources, p.String())
		}
		if i := slices.IndexFunc(w.ing.gateways[node], func(x IngressGateway) bool { return x.Kind == side.kind }); i >= 0 {
			g.RejectedSources = w.ing.gateways[node][i].RejectedSources
		}
		rows = append(rows, g)
	}
	w.ing.gateways[node] = rows
}

// realIngressHistory: ingress-block / unblock / extend and host policy
// changes in the same public history (Detail = the block after, Previous
// = before; host policy Detail = the payload).
func (w *world) realIngressHistory(op UserOperation, before []control.IngressBlockRecord, beforePolicy ingress.HostPolicy) {
	book := &w.ireal
	h := control.IngressHistoryRecord{Order: book.revision, Origin: op, Detail: slices.Clone(op.Change.Payload)}
	if op.Change.Action == ActionSetIngressHostPolicy {
		var q control.IngressHostPolicyChange
		_ = json.Unmarshal(op.Change.Payload, &q)
		h.Tenant = q.Tenant
		h.Previous, _ = json.Marshal(beforePolicy)
	} else {
		for _, r := range book.blocks {
			if r.Last.RequestID != op.RequestID {
				continue
			}
			h.Tenant, h.App, h.Node, h.Route, h.Gateway = r.Block.Tenant, r.Block.App, r.Block.Node, r.Block.Route, r.Block.Gateway
			for _, old := range before {
				if old.Block.ID == r.Block.ID {
					h.Previous, _ = json.Marshal(old.Block)
				}
			}
			h.Detail, _ = json.Marshal(r.Block)
			if r.Block.Tenant != "" && r.Block.App == "" {
				for _, m := range w.realMappings() {
					if realBlockMaps(r.Block, m) && !slices.Contains(h.AffectedApps, m.App) {
						h.AffectedApps = append(h.AffectedApps, m.App)
					}
				}
				slices.Sort(h.AffectedApps)
			}
			break
		}
	}
	book.history = append(book.history, h)
}

type ingressHistoryCursor struct {
	Before                  uint64
	User, Tenant, App, Node string
}

// ingressHistoryPage: newest first, 8 rows (or about 80 KiB) a page.
func (w *world) ingressHistoryPage(user string, q control.IngressQuery, system bool) ([]control.IngressHistoryView, string, error) {
	book := &w.ireal
	before := book.revision + 1
	scope := ingressHistoryCursor{User: user, Tenant: q.Tenant, App: q.App, Node: q.Node}
	if q.After != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.After)
		var cur ingressHistoryCursor
		if err != nil || json.Unmarshal(raw, &cur) != nil || cur.Before == 0 || cur.Before > before {
			return nil, "", errors.New("cursor")
		}
		b := cur.Before
		cur.Before = 0
		if cur != scope {
			return nil, "", errors.New("cursor")
		}
		before = b
	}
	var out []control.IngressHistoryView
	used := 0
	for i := len(book.history) - 1; i >= 0; i-- {
		h := book.history[i]
		if h.Order >= before || q.Tenant != "" && h.Tenant != q.Tenant || q.App != "" && h.App != q.App && !slices.Contains(h.AffectedApps, q.App) || q.Node != "" && h.Node != "" && h.Node != q.Node {
			continue
		}
		if !system && (h.Tenant == "" || !w.canRead(user, h.Tenant)) {
			continue
		}
		v := control.IngressHistoryView{At: h.Origin.At, Actor: h.Origin.Session.User, Action: h.Origin.Change.Action, Request: h.Origin.RequestID,
			Tenant: h.Tenant, App: h.App, Node: h.Node, Route: h.Route, Gateway: h.Gateway, Detail: slices.Clone(h.Detail), Previous: slices.Clone(h.Previous)}
		enc, _ := json.Marshal(v)
		if len(out) == 8 || len(out) > 0 && used+len(enc) > 80<<10 {
			scope.Before = before
			raw, _ := json.Marshal(scope)
			return out, base64.RawURLEncoding.EncodeToString(raw), nil
		}
		out = append(out, v)
		used += len(enc)
		before = h.Order
	}
	return out, "", nil
}

func jsonEqual(a, b any) bool {
	x, e1 := json.Marshal(a)
	y, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && string(x) == string(y)
}
