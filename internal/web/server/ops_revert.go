// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
	"github.com/jay94ks/seafield/internal/workload"
)

// "Revert this change" (UI-A4). Right before an op of a known action is
// signed, the web reads its target in the shape of the action's payload and
// keeps it with the op (store.OpChange). A revert is a new change of the
// same target: it starts from the target as it is now, puts back the
// fields the person picked as they were before the op (a list field gets
// the op's additions taken out and its removals put back, so other
// changes to the same list stay), and is checked against the revision read
// now. It is signed by the person who reverts and is itself revertible.

// revField is one payload field a revert compares and can put back. Set
// marks an unordered list of rows.
type revField struct {
	Path string
	Set  bool
}

// revSpec: how one action's target is read and reverted.
type revSpec struct {
	fields []revField
	// read returns the target now as the payload that would set it (nil
	// when it is not there) and the revision a change now is checked
	// against.
	read func(ctx context.Context, c sfc.Conn, key basePayload) (state any, rev uint64, err error)
	// after is the target the op left; nil: the target before with the
	// sent payload's fields.
	after func(before, sent map[string]any) map[string]any
	// send is the change that makes want from now; nil: the same action
	// with want.
	send func(action string, want, now map[string]any) (string, any, error)
	// raw: the state is the web's own shape (not a payload sfcd takes),
	// written as is.
	raw bool
}

func valueFields(paths ...string) []revField {
	out := make([]revField, len(paths))
	for i, p := range paths {
		out[i] = revField{Path: p}
	}
	return out
}

var revertSpecs = map[string]revSpec{
	sfc.ActionConfigureNetworkDNS: {
		fields: append(valueFields("Policy.Enabled", "Policy.Reverse", "Policy.Zone", "Policy.ClientZone", "Policy.TTL", "Policy.NegativeTTL",
			"Policy.Transports", "Policy.Upstreams", "Policy.MaxQueries", "Policy.MaxCacheEntries", "Policy.MaxResponseBytes",
			"Policy.MaxConnections", "Policy.RequestTimeoutMS"), revField{"Policy.Records", true}),
		read: func(ctx context.Context, c sfc.Conn, key basePayload) (any, uint64, error) {
			tenant, name := key.str("Tenant"), key.str("Network")
			n, _, err := revNetwork(ctx, c, tenant, name)
			if err != nil || n == nil || n.DNS == nil {
				return nil, 0, err
			}
			return services.ManagedDNSDefinition{Schema: 1, Tenant: tenant, Network: name, Policy: n.DNS.Policy}, n.DNS.Revision, nil
		},
	},
	sfc.ActionSetNetworkToggle: {
		fields: valueFields("On"),
		read: func(ctx context.Context, c sfc.Conn, key basePayload) (any, uint64, error) {
			tenant, name, toggle := key.str("Tenant"), key.str("Name"), tenancy.NetworkToggle(key.str("Toggle"))
			n, collection, err := revNetwork(ctx, c, tenant, name)
			if err != nil || n == nil {
				return nil, 0, err
			}
			return control.NetworkToggleSet{Tenant: tenant, Name: name, Toggle: toggle, On: slices.Contains(n.Toggles, toggle)}, collection, nil
		},
	},
	sfc.ActionSetNodeQuota: {
		fields: valueFields("Capacity", "Networks", "MaxConsumers", "PacketQueuePackets", "PacketQueueBytes", "MaxIngressInstances",
			"MaxIngressListeners", "MaxIngressRequests", "MaxIngressConnections", "IngressBufferBytes", "Swap"),
		read: func(ctx context.Context, c sfc.Conn, key basePayload) (any, uint64, error) {
			tenant, node := key.str("Tenant"), key.str("Node")
			mine, err := nodeLimits(ctx, c, tenant)
			l, ok := mine[node]
			if err != nil || !ok {
				return nil, 0, err
			}
			return tenancy.NodeLimit{Tenant: tenant, Node: node, Capacity: workload.Resources{CPU: cpuOf(l.CPUs), Memory: l.MemoryBytes},
				Networks: l.Networks, MaxConsumers: l.MaxConsumers, PacketQueuePackets: l.PacketQueuePackets, PacketQueueBytes: l.PacketQueueBytes,
				MaxIngressInstances: l.MaxIngressInstances, MaxIngressListeners: l.MaxIngressListeners, MaxIngressRequests: l.MaxIngressRequests,
				MaxIngressConnections: l.MaxIngressConnections, IngressBufferBytes: l.IngressBufferBytes}, l.Revision, nil
		},
	},
	sfc.ActionSetNodeShellPolicy: {
		fields: valueFields("Enabled", "MaxSessions", "IdleSeconds"),
		read: func(ctx context.Context, c sfc.Conn, _ basePayload) (any, uint64, error) {
			p, err := c.NodeShellPolicy(ctx)
			return sfc.SetNodeShellPolicy{Enabled: p.Enabled, MaxSessions: p.MaxSessions, IdleSeconds: p.IdleSeconds}, p.Revision, err
		},
	},
	sfc.ActionSetNodeShellNode: {
		fields: valueFields("Shell", "Sudo"),
		read: func(ctx context.Context, c sfc.Conn, key basePayload) (any, uint64, error) {
			node := key.str("Node")
			p, err := c.NodeShellPolicy(ctx)
			if err != nil {
				return nil, 0, err
			}
			i := slices.IndexFunc(p.Nodes, func(n control.NodeShellNodeView) bool { return n.Node == node })
			if i < 0 {
				return nil, 0, nil
			}
			return sfc.SetNodeShellNode{Node: node, Shell: p.Nodes[i].Shell, Sudo: p.Nodes[i].Sudo}, p.Revision, nil
		},
	},
	sfc.ActionSetNodeShellGrant: {
		fields: []revField{{"Nodes", true}},
		read: func(ctx context.Context, c sfc.Conn, key basePayload) (any, uint64, error) {
			user := key.str("User")
			p, err := c.NodeShellPolicy(ctx)
			if err != nil {
				return nil, 0, err
			}
			nodes := []string{} // no grant is a grant of no servers
			if i := slices.IndexFunc(p.Grants, func(g access.NodeShellGrant) bool { return g.User == user }); i >= 0 {
				nodes = append(nodes, p.Grants[i].Nodes...)
			}
			return sfc.SetNodeShellGrant{User: user, Nodes: nodes}, p.Revision, nil
		},
	},
	// The account's action ceiling and key-only flag. set-account-scope
	// takes a change (Add, Remove, Unlimited, KeyOnly), so the state is the
	// web's own {User, Operations, KeyOnly} and a revert sends the change
	// from now to want.
	sfc.ActionSetAccountScope: {
		fields: []revField{{"Operations", true}, {Path: "KeyOnly"}},
		raw:    true,
		read: func(ctx context.Context, c sfc.Conn, key basePayload) (any, uint64, error) {
			user := key.str("User")
			v, err := c.AccountScope(ctx, user)
			if err != nil {
				return nil, 0, err
			}
			return map[string]any{"User": user, "Operations": append([]string{}, v.Actions...), "KeyOnly": v.KeyOnly}, v.Revision, nil
		},
		after: accountScopeAfter,
		send:  accountScopeSend,
	},
	sfc.ActionSetNodeCLIPolicy: {
		fields: valueFields("disable_node_cli_operation"),
		read: func(ctx context.Context, c sfc.Conn, _ basePayload) (any, uint64, error) {
			v, err := c.NodeCLIPolicy(ctx)
			return control.NodeCLIChange{DisableNodeCLIOperation: v.DisableNodeCLIOperation}, v.Revision, err
		},
	},
	sfc.ActionSetMembership: {
		fields: valueFields("Role", "Enabled"),
		read: func(ctx context.Context, c sfc.Conn, key basePayload) (any, uint64, error) {
			tenant, user := key.str("Tenant"), key.str("User")
			b, err := findBase(func(after string) ([]sfc.TenantMember, string, error) {
				pg, err := c.TenantMembers(ctx, tenant, after)
				return pg.Items, pg.Next, err
			}, func(m sfc.TenantMember) (bool, uint64) { return m.User == user && !m.Implicit, m.Revision })
			if err != nil || !b.Found {
				return nil, 0, err
			}
			m := b.Current.(sfc.TenantMember)
			return access.Membership{Tenant: tenant, User: user, Role: m.Role, Enabled: m.Enabled}, m.Revision, nil
		},
	},
	// The servers a tenant may use. set-nodes takes a change (Add, Remove),
	// so the state is the web's own {Tenant, Nodes} and a revert sends the
	// change from now to want.
	sfc.ActionSetNodes: {
		fields: []revField{{"Nodes", true}},
		raw:    true,
		read: func(ctx context.Context, c sfc.Conn, key basePayload) (any, uint64, error) {
			tenant := key.str("Tenant")
			b, err := tenantBase(ctx, c, key)
			if err != nil || !b.Found {
				return nil, 0, err
			}
			return map[string]any{"Tenant": tenant, "Nodes": append([]string{}, b.Current.(sfc.TenantView).AllowedNodes...)}, b.Expected, nil
		},
		after: func(before, sent map[string]any) map[string]any {
			nodes := append(minus(rows(before["Nodes"]), rows(sent["Remove"])), rows(sent["Add"])...)
			return map[string]any{"Tenant": before["Tenant"], "Nodes": nodes}
		},
		send: func(action string, want, now map[string]any) (string, any, error) {
			q := control.NodeChangeTo(strOf(want["Tenant"]), names(rows(now["Nodes"])), names(rows(want["Nodes"])))
			if len(q.Add)+len(q.Remove) == 0 {
				return "", nil, invalidCode("nothing", "the picked fields are as they were before already")
			}
			return action, q, nil
		},
	},
	// A cluster app's routes: put sets the whole declaration, remove takes
	// it away, so a revert is a put of the declaration before or a remove.
	sfc.ActionPutClusterAppRoute:    clusterAppRouteSpec,
	sfc.ActionRemoveClusterAppRoute: clusterAppRouteSpec,
}

var clusterAppRouteSpec = revSpec{
	fields: valueFields("Ingress"),
	read: func(ctx context.Context, c sfc.Conn, key basePayload) (any, uint64, error) {
		app := key.str("App")
		v, err := clusterAppRoute(ctx, c, app)
		if err != nil {
			return nil, 0, err
		}
		if v.Removed || v.Revision == 0 {
			return map[string]any{"App": app, "Ingress": nil}, v.Revision, nil
		}
		return control.ClusterAppRouteChange{App: app, Ingress: v.Ingress}, v.Revision, nil
	},
	after: func(before, sent map[string]any) map[string]any {
		out := map[string]any{"App": before["App"], "Ingress": sent["Ingress"]} // a remove sends no Ingress
		return out
	},
	send: func(_ string, want, _ map[string]any) (string, any, error) {
		if want["Ingress"] == nil {
			return sfc.ActionRemoveClusterAppRoute, control.ClusterAppRouteSelection{App: strOf(want["App"])}, nil
		}
		return sfc.ActionPutClusterAppRoute, want, nil
	},
}

// accountScopeAfter applies the sent change to the ceiling before it.
func accountScopeAfter(before, sent map[string]any) map[string]any {
	ops := rows(before["Operations"])
	if whole, ok := sent["Operations"]; ok { // a whole ceiling
		ops = rows(whole)
	}
	if sent["Unlimited"] == true {
		ops = []any{}
	}
	ops = append(minus(ops, rows(sent["Remove"])), rows(sent["Add"])...)
	out := map[string]any{"User": before["User"], "Operations": ops, "KeyOnly": before["KeyOnly"]}
	if k, ok := sent["KeyOnly"].(bool); ok {
		out["KeyOnly"] = k
	}
	return out
}

// accountScopeSend is the change from the ceiling now to want: Remove
// what want lacks, Add what it gains, Unlimited when want has none, and
// KeyOnly only when it changes.
func accountScopeSend(action string, want, now map[string]any) (string, any, error) {
	q := sfc.AccountScopeChange{User: strOf(want["User"])}
	have, next := rows(now["Operations"]), rows(want["Operations"])
	if len(next) == 0 && len(have) > 0 {
		q.Unlimited = true
	} else {
		q.Add, q.Remove = names(minus(next, have)), names(minus(have, next))
	}
	if k, _ := want["KeyOnly"].(bool); k != (now["KeyOnly"] == true) {
		q.KeyOnly = &k
	}
	if !q.Unlimited && len(q.Add)+len(q.Remove) == 0 && q.KeyOnly == nil {
		return "", nil, invalidCode("nothing", "the picked fields are as they were before already")
	}
	return action, q, nil
}

// names: action-name rows as strings (nil when none, so the change omits it).
func names(rs []any) []string {
	var out []string
	for _, r := range rs {
		out = append(out, strOf(r))
	}
	return out
}

// irreversible: changes whose effect a later change cannot undo (data
// gone, keys revoked, history rotated).
var irreversible = []string{
	"delete-volume", "delete-retained-volume", "delete-volume-backup", "volume-file-delete",
	"rotate-ledger", "rotate-app-history", "raft-compact",
	"vault-revoke", "vault-retire", "revoke-session", "disable-credential",
	"delete-registry-image", "gc-registry", "prune-registry-images", "prune-node-images", "prune-build-cache",
	"delete-build-version", "delete-image-build-job",
	"force-remove-node", "remove-node", "remove-node-storage", "finish-tenant-retirement",
}

func cpuOf(cpus float64) uint64 { return uint64(math.Round(cpus * cpuUnit)) }

func strOf(v any) string { s, _ := v.(string); return s }

// revNetwork is findNetwork with "no such network" as nil.
func revNetwork(ctx context.Context, c sfc.Conn, tenant, name string) (*sfc.Network, uint64, error) {
	n, collection, err := findNetwork(ctx, c, tenant, name)
	var he *httpErr
	if errors.As(err, &he) && he.status == http.StatusNotFound {
		return nil, 0, nil
	}
	return n, collection, err
}

// canonState writes a target state in the canonical payload form sfcd
// takes (what the sent payload is), so the two compare field by field.
func canonState(action string, v any) (json.RawMessage, error) {
	if v == nil {
		return json.RawMessage("null"), nil
	}
	raw, err := json.Marshal(v)
	if err != nil || revertSpecs[action].raw {
		return raw, err
	}
	doc, _ := json.Marshal(control.ChangeDocument{Schema: 1, Action: action, Payload: raw})
	if ch, err := control.InputChange(doc, "web"); err == nil {
		return ch.Payload, nil
	}
	return raw, nil // e.g. a removed cluster app route
}

func decodeState(raw json.RawMessage) map[string]any {
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&m) != nil {
		return nil
	}
	return m
}

func getPath(m map[string]any, path string) any {
	var v any = m
	for _, p := range strings.Split(path, ".") {
		o, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = o[p]
	}
	return v
}

func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		o, ok := m[p].(map[string]any)
		if !ok {
			o = map[string]any{}
			m[p] = o
		}
		m = o
	}
	m[parts[len(parts)-1]] = v
}

func rows(v any) []any {
	l, _ := v.([]any)
	return l
}

func rowKey(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// minus returns the rows of a not in b (as multisets).
func minus(a, b []any) []any {
	left := map[string]int{}
	for _, x := range b {
		left[rowKey(x)]++
	}
	out := []any{}
	for _, x := range a {
		k := rowKey(x)
		if left[k] > 0 {
			left[k]--
			continue
		}
		out = append(out, x)
	}
	return out
}

func containsRow(l []any, x any) bool {
	k := rowKey(x)
	return slices.ContainsFunc(l, func(y any) bool { return rowKey(y) == k })
}

// recordChange reads the target of ch before it is signed. A failed read
// leaves the op without a record (its revert answers no-record); it never
// stops the change.
func (s *Server) recordChange(ctx context.Context, c sfc.Conn, o *store.Op, ch sfc.Change) {
	spec, ok := revertSpecs[ch.Action]
	if !ok {
		return
	}
	var key basePayload
	if json.Unmarshal(ch.Payload, &key) != nil {
		return
	}
	st, _, err := spec.read(ctx, c, key)
	if err != nil {
		s.log.Info("revert record", "action", ch.Action, "op", o.ID, "err", err)
		return
	}
	before, err := canonState(ch.Action, st)
	if err != nil {
		return
	}
	o.Change = &store.OpChange{Before: before, Sent: append(json.RawMessage{}, ch.Payload...)}
}

// revertLink: an op another screen undoes.
type revertLink struct {
	Kind   string `json:"kind"` // app-revisions / archived-apps
	Tenant string `json:"tenant,omitempty"`
	App    string `json:"app,omitempty"`
}

func linkOf(o *store.Op) *revertLink {
	switch {
	case o.Deploy != nil && o.Deploy.Move == nil && o.Deploy.Standalone == nil && o.Deploy.Local == nil:
		return &revertLink{Kind: "app-revisions", Tenant: o.Deploy.Tenant, App: o.Deploy.App}
	case o.Action == sfc.ActionDownApp:
		return &revertLink{Kind: "archived-apps", Tenant: o.Tenant, App: o.Target}
	}
	return nil
}

// revertKind is the op row's hint for its menu: here, link or no.
func revertKind(o *store.Op) string {
	if o.State != store.OpApplied || o.Parent != "" {
		return "no"
	}
	if _, ok := revertSpecs[o.Action]; ok && o.Change != nil {
		return "here"
	}
	if linkOf(o) != nil {
		return "link"
	}
	return "no"
}

// revertPlan is GET /ops/{id}/revert.
type revertPlan struct {
	Revert   string         `json:"revert"` // here / link / no
	Reason   string         `json:"reason,omitempty"`
	Link     *revertLink    `json:"link,omitempty"`
	Action   string         `json:"action,omitempty"`
	Target   string         `json:"target,omitempty"`
	Expected uint64         `json:"expected,omitempty"`
	Fields   []revFieldPlan `json:"fields,omitempty"`
	spec     revSpec
	now      map[string]any
	before   map[string]any
	byPath   map[string]bool // path → set field
}

// revFieldPlan is one field the op changed. Value fields show before,
// after (what the op left) and now; set fields the rows the op added and
// removed, and now.
type revFieldPlan struct {
	Path         string `json:"path"`
	Kind         string `json:"kind"` // value / set
	Before       any    `json:"before"`
	After        any    `json:"after"`
	Now          any    `json:"now"`
	Added        []any  `json:"added,omitempty"`
	Removed      []any  `json:"removed,omitempty"`
	ChangedSince bool   `json:"changedSince"`
}

func notHere(reason string) revertPlan { return revertPlan{Revert: "no", Reason: reason} }

// plan reads the op's target now and lists what a revert puts back.
func (s *Server) revertPlanOf(ctx context.Context, c sfc.Conn, o *store.Op) (revertPlan, error) {
	switch {
	case o.State == store.OpPending || o.State == store.OpUnknown || o.State == store.OpRunning:
		return notHere("unsettled"), nil
	case o.State != store.OpApplied:
		return notHere("not-applied"), nil
	case o.Parent != "":
		return notHere("unsupported"), nil
	}
	spec, ok := revertSpecs[o.Action]
	if !ok {
		if l := linkOf(o); l != nil {
			return revertPlan{Revert: "link", Link: l}, nil
		}
		if slices.Contains(irreversible, o.Action) {
			return notHere("irreversible"), nil
		}
		return notHere("unsupported"), nil
	}
	if o.Change == nil {
		return notHere("no-record"), nil
	}
	before, sent := decodeState(o.Change.Before), decodeState(o.Change.Sent)
	if sent == nil {
		return notHere("no-record"), nil
	}
	if before == nil {
		return notHere("created"), nil
	}
	var key basePayload
	_ = json.Unmarshal(o.Change.Sent, &key)
	st, rev, err := spec.read(ctx, c, key)
	if err != nil {
		return revertPlan{}, err
	}
	if st == nil {
		return notHere("target-gone"), nil
	}
	raw, err := canonState(o.Action, st)
	if err != nil {
		return revertPlan{}, err
	}
	now := decodeState(raw)
	var after map[string]any
	if spec.after != nil {
		after = spec.after(before, sent)
	} else {
		after = decodeState(o.Change.Before)
		for _, f := range spec.fields {
			setPath(after, f.Path, getPath(sent, f.Path))
		}
	}
	p := revertPlan{Revert: "here", Action: o.Action, Target: o.Target, Expected: rev, spec: spec, now: now, before: before, byPath: map[string]bool{}}
	for _, f := range spec.fields {
		b, a, n := getPath(before, f.Path), getPath(after, f.Path), getPath(now, f.Path)
		fp := revFieldPlan{Path: f.Path, Kind: "value", Before: b, After: a, Now: n}
		if f.Set {
			fp.Kind = "set"
			fp.Added, fp.Removed = minus(rows(a), rows(b)), minus(rows(b), rows(a))
			if len(fp.Added) == 0 && len(fp.Removed) == 0 {
				continue
			}
			for _, x := range fp.Added {
				fp.ChangedSince = fp.ChangedSince || !containsRow(rows(n), x)
			}
			for _, x := range fp.Removed {
				fp.ChangedSince = fp.ChangedSince || containsRow(rows(n), x)
			}
		} else {
			if reflect.DeepEqual(b, a) {
				continue
			}
			fp.ChangedSince = !reflect.DeepEqual(n, a)
		}
		p.Fields = append(p.Fields, fp)
		p.byPath[f.Path] = f.Set
	}
	if len(p.Fields) == 0 {
		return notHere("nothing"), nil
	}
	return p, nil
}

// want is the target a revert of the picked fields makes: now, with each
// value field as it was before and each set field without the op's
// additions and with its removals.
func (p revertPlan) want(picked []string) map[string]any {
	want := decodeState(mustJSON(p.now))
	for _, path := range picked {
		if !p.byPath[path] {
			setPath(want, path, getPath(p.before, path))
			continue
		}
		var f revFieldPlan
		for _, x := range p.Fields {
			if x.Path == path {
				f = x
			}
		}
		l := minus(rows(getPath(p.now, path)), f.Added)
		for _, x := range f.Removed {
			if !containsRow(l, x) {
				l = append(l, x)
			}
		}
		setPath(want, path, l)
	}
	return want
}

// GET /ops/{id}/revert
func (s *Server) handleOpRevertPlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	o := s.loadOp(w, r, ws)
	if o == nil {
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var p revertPlan
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		p, err = s.revertPlanOf(ctx, c, o)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// opPayload is a change sharedCreate sends for a route that names no
// tenant: the payload, the tenant, and the op it reverts or the deleted
// item it restores.
type opPayload struct {
	payload  any
	tenant   string
	revertOf string
	restores string
}

// POST /ops/{id}/revert {opId, expected, fields}
func (s *Server) handleOpRevert(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string   `json:"opId"`
		Expected *uint64  `json:"expected"`
		Fields   []string `json:"fields"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	o := s.loadOp(w, r, ws)
	if o == nil {
		return
	}
	if req.Expected == nil || len(req.Fields) == 0 {
		writeError(w, http.StatusBadRequest, "bad-request", "expected and fields are required")
		return
	}
	body := struct {
		Of       string
		Expected uint64
		Fields   []string
	}{o.ID, *req.Expected, req.Fields}
	s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		p, err := s.revertPlanOf(ctx, c, o)
		if err != nil {
			return "", nil, 0, "", err
		}
		if p.Revert != "here" {
			return "", nil, 0, "", &httpErr{http.StatusUnprocessableEntity, "not-revertible", "this change is not reverted here: " + p.Reason}
		}
		for _, f := range req.Fields {
			if _, ok := p.byPath[f]; !ok {
				return "", nil, 0, "", invalid("fields: " + f + " is not a field this change changed")
			}
		}
		if p.Expected != *req.Expected {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "stale", "the target changed since the plan was read; read it again"}
		}
		action, payload := o.Action, any(p.want(req.Fields))
		if p.spec.send != nil {
			if action, payload, err = p.spec.send(o.Action, p.want(req.Fields), p.now); err != nil {
				return "", nil, 0, "", err
			}
		}
		return action, opPayload{payload: payload, tenant: o.Tenant, revertOf: o.ID}, p.Expected, o.Target, nil
	})
}
