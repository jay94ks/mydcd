// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// REQ-51/52 (RQ12, real shape: docs/protocol/sfcp.md 노드 운영,
// control/node_*.go): the advanced server actions of UI-12 '고급 ▾' and the
// removal check (system admin). Each plan is sfcd's: the web shows it and
// signs the op with a fresh plan only when it says the same as the one shown
// (the plan token), and never decides itself whether a server may be
// drained, demoted or removed.

// planToken: a hex digest of what a plan says (not when it was read), the
// value a screen sends back to act on that plan.
func planToken(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// samePlan checks a plan token as shown against the current one.
func samePlan(given, cur, what string) error {
	raw, err := hex.DecodeString(given)
	if err != nil || len(raw) != 32 {
		return invalid("plan: the plan value as shown (64 hex)")
	}
	if strings.ToLower(given) != cur {
		return &httpErr{http.StatusConflict, "plan-changed", "the " + what + " changed; read the plan again"}
	}
	return nil
}

// nodeOperation is a node lifecycle operation ID: given, or prefix-<opId>.
func nodeOperation(given, prefix, opID string) (string, error) {
	op := given
	if op == "" {
		op = prefix + "-" + strings.ToLower(opID)
	}
	if !lifecycle.ValidID(op) {
		return "", invalid("operation: lowercase letters, digits and -, starting with a letter, at most 63")
	}
	return op, nil
}

// planOperation: the ?operation= of a plan read, or a new one (prefix-<12
// hex>) the screen sends back with the plan.
func planOperation(r *http.Request, prefix string) (string, error) {
	op := r.URL.Query().Get("operation")
	if op == "" {
		var b [6]byte
		_, _ = rand.Read(b[:])
		op = prefix + "-" + hex.EncodeToString(b[:])
	}
	if !lifecycle.ValidID(op) {
		return "", invalid("operation: lowercase letters, digits and -, starting with a letter, at most 63")
	}
	return op, nil
}

func memberOr404(ctx context.Context, c sfc.Conn, node string) (*memberView, error) {
	m, err := findMember(ctx, c, node)
	if err == nil && m == nil {
		err = &httpErr{http.StatusNotFound, "not-found", "no such server"}
	}
	return m, err
}

func blockersShape(bs []control.NodeBlocker) []map[string]any {
	out := []map[string]any{}
	for _, b := range bs {
		x := map[string]any{"code": b.Code}
		if b.Detail != "" {
			x["detail"] = b.Detail
		}
		out = append(out, x)
	}
	return out
}

// firstBlocker: the code sfcd refuses with first ("" = none).
func firstBlocker(bs []control.NodeBlocker) any {
	if len(bs) == 0 {
		return nil
	}
	return bs[0].Code
}

func planTasksShape(ts []control.NodePlanTask) []map[string]any {
	out := []map[string]any{}
	for _, t := range ts {
		x := map[string]any{"tenant": t.Tenant, "app": t.App, "service": t.Service, "task": t.Task, "node": t.Node, "movable": t.Movable,
			"generation": t.Generation, "revision": t.Revision}
		for k, v := range map[string]string{"standalone": t.Standalone, "target": t.Target, "reason": t.Reason} {
			if v != "" {
				x[k] = v
			}
		}
		out = append(out, x)
	}
	return out
}

// removePlanShape: control.NodeRemovePlan for the screens.
func removePlanShape(p control.NodeRemovePlan) map[string]any {
	storage := []map[string]any{}
	for _, s := range p.Storage {
		storage = append(storage, map[string]any{"id": s.ID, "path": s.Path, "generation": s.Generation, "revision": s.Revision,
			"volumes": s.Volumes, "retained": s.Retained, "draining": s.Draining, "closed": s.Closed})
	}
	volumes := []map[string]any{}
	for _, v := range p.Volumes {
		x := map[string]any{"tenant": v.Tenant, "id": v.ID, "fixed": v.Fixed, "retained": v.Retained, "generation": v.Generation}
		if v.App != "" {
			x["app"] = v.App
		}
		if v.Move != "" {
			x["move"] = v.Move
		}
		volumes = append(volumes, x)
	}
	a := p.Activity
	out := map[string]any{"node": p.Node, "epoch": p.Epoch, "expected": p.Expected, "removable": p.Removable, "blockers": blockersShape(p.Blockers),
		"votersBefore": p.VotersBefore, "votersAfter": p.VotersAfter, "quorumAfter": p.QuorumAfter, "faultToleranceAfter": p.FaultToleranceAfter,
		"tasks": planTasksShape(p.Tasks), "storage": storage, "volumes": volumes, "nativeClosed": p.NativeClosed,
		"activity": map[string]any{"resources": a.Resources, "flows": a.Flows, "writers": a.Writers, "leases": a.Leases, "cdJobs": a.CDJobs}}
	if p.PendingOperation != "" {
		out["pendingOperation"] = p.PendingOperation
	}
	return out
}

// GET /nodes/{node}/drain-plan?operation= → {node, operation, expected,
// plan, tasks, blockers, jobs:[{tenant, app, operation, target, services,
// tasks}]}. Without operation the web picks drain-<12 hex>; send it back.
func (s *Server) handleNodeDrainPlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	op, err := planOperation(r, "drain")
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		p, err := c.PlanNodeDrain(ctx, control.NodeDrainQuery{Node: r.PathValue("node"), Operation: op})
		if err != nil {
			return nil, err
		}
		jobs := []map[string]any{}
		for _, j := range p.Jobs {
			services := j.Services
			if services == nil {
				services = []string{}
			}
			jobs = append(jobs, map[string]any{"tenant": j.Tenant, "app": j.App, "operation": j.Operation, "target": j.Target, "services": services,
				"tasks": len(j.Tasks), "moveVolume": j.Move != nil || len(j.AdditionalMoves) > 0})
		}
		return map[string]any{"node": p.Node, "operation": p.Operation, "expected": p.Expected, "plan": drainToken(p),
			"tasks": planTasksShape(p.Tasks), "blockers": blockersShape(p.Blockers), "code": firstBlocker(p.Blockers), "jobs": jobs}, nil
	})
}

// drainToken: what a drain plan says, without when it was read.
func drainToken(p control.NodeDrainPlan) string {
	p.At, p.Digest, p.RootRevision, p.Index = 0, [32]byte{}, 0, 0
	return planToken(p)
}

// POST /nodes/{node}/drain {opId, plan, operation, leaveBlocked?} →
// drain-node (control.NodeDrainChange of a fresh plan that says the same,
// Expected = its Expected; sfcd takes a plan read in the last 30 s).
// Progress: GET /nodes/{node}/drain-status?operation=.
func (s *Server) handleDrainNode(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID         string `json:"opId"`
		Plan         string `json:"plan"`
		LeaveBlocked bool   `json:"leaveBlocked,omitempty"`
		Operation    string `json:"operation,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node := r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, actionBody{sfc.ActionDrainNode, req}, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		op, err := nodeOperation(req.Operation, "drain", req.OpID)
		if err != nil {
			return "", nil, 0, "", err
		}
		if _, err := memberOr404(ctx, c, node); err != nil {
			return "", nil, 0, "", err
		}
		p, err := c.PlanNodeDrain(ctx, control.NodeDrainQuery{Node: node, Operation: op})
		if err != nil {
			return "", nil, 0, "", err
		}
		if err := samePlan(req.Plan, drainToken(p), "server's tasks"); err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionDrainNode, control.NodeDrainChange{At: p.At, ID: node, Operation: op, LeaveBlocked: req.LeaveBlocked, AppsRoot: p.AppsRoot,
			Plan: p.Digest, Jobs: p.Jobs}, p.Expected, "node/" + node, nil
	})
}

// GET /nodes/{node}/drain-status?operation= → {node, operation, state,
// total, moved, blocked, jobs}. Without operation: the server's newest
// drain, whoever started it (REQ-70; 404 when there is none). Fields:
// total, moved, blocked, jobs:[{tenant, app, operation, state, total,
// moved}]}.
func (s *Server) handleNodeDrainStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	op := r.URL.Query().Get("operation")
	if op != "" && !lifecycle.ValidID(op) {
		writeError(w, http.StatusBadRequest, "bad-request", "operation: the drain's operation")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (control.NodeDrainStatus, error) {
		st, err := c.NodeDrainStatus(ctx, control.NodeDrainQuery{Node: r.PathValue("node"), Operation: op})
		if st.Jobs == nil {
			st.Jobs = []control.NodeDrainJobStatus{}
		}
		return st, err
	})
}

// GET /nodes/{node}/voter-plan → {node, epoch, expected, demotable, code?,
// blockers, votersBefore, votersAfter, quorumAfter, faultToleranceAfter,
// pendingOperation?} (node-demote-plan). quorum / tolerates repeat
// quorumAfter / faultToleranceAfter for older screens.
func (s *Server) handleNodeVoterPlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		p, err := c.PlanNodeDemotion(ctx, r.PathValue("node"))
		if err != nil {
			return nil, err
		}
		out := map[string]any{"node": p.Node, "epoch": p.Epoch, "expected": p.Expected, "demotable": p.Demotable, "blockers": blockersShape(p.Blockers),
			"code": firstBlocker(p.Blockers), "votersBefore": p.VotersBefore, "votersAfter": p.VotersAfter, "quorumAfter": p.QuorumAfter,
			"faultToleranceAfter": p.FaultToleranceAfter, "quorum": p.QuorumAfter, "tolerates": p.FaultToleranceAfter}
		if p.PendingOperation != "" {
			out["pendingOperation"] = p.PendingOperation
		}
		return out, nil
	})
}

// POST /nodes/{node}/demote {opId, expected?} → demote-node
// (control.NodeSelection{ID}, Expected default the plan's). A refusal is
// sfcd's and comes back as the op result.
func (s *Server) handleDemoteNode(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node := r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, actionBody{sfc.ActionDemoteNode, req}, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if _, err := memberOr404(ctx, c, node); err != nil {
			return "", nil, 0, "", err
		}
		p, err := c.PlanNodeDemotion(ctx, node)
		if err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionDemoteNode, control.NodeSelection{ID: node}, expectedOr(req.Expected, p.Expected), "node/" + node, nil
	})
}

// POST /nodes/{node}/rotate-identity {opId, operation?, expected?} →
// rotate-node-identity (control.NodeIdentityChange; operation defaults to
// rotate-<opId>, expected to the server's revision).
func (s *Server) handleRotateNodeIdentity(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string `json:"opId"`
		Operation string `json:"operation,omitempty"`
		Expected  uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node := r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, actionBody{sfc.ActionRotateNodeIdentity, req}, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		op, err := nodeOperation(req.Operation, "rotate", req.OpID)
		if err != nil {
			return "", nil, 0, "", err
		}
		m, err := memberOr404(ctx, c, node)
		if err != nil {
			return "", nil, 0, "", err
		}
		// the membership entry's revision (as `sfcli node rotate-key`), not the
		// lifecycle row's
		return sfc.ActionRotateNodeIdentity, control.NodeIdentityChange{ID: node, Operation: op}, expectedOr(req.Expected, m.JoinRevision), "node/" + node, nil
	})
}

// forceToken: what a forced-removal plan says, without its probe and read
// position.
func forceToken(p control.NodeForcePlan) string {
	p.Probe, p.Index, p.RootRevision = nil, 0, 0
	return planToken(p)
}

// GET /nodes/{node}/force-remove-plan?operation= → removePlanShape plus
// {operation, forceable, code?, plan, probe?:{responding, startedAt,
// finishedAt}} (node-force-remove-plan: sfcd probes the server). Without
// operation the web picks force-<12 hex>; send it back.
func (s *Server) handleNodeForceRemovePlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	op, err := planOperation(r, "force")
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		p, err := c.PlanNodeForceRemoval(ctx, control.NodeForceQuery{Node: r.PathValue("node"), Operation: op})
		if err != nil {
			return nil, err
		}
		out := removePlanShape(p.NodeRemovePlan)
		out["operation"], out["forceable"], out["code"], out["plan"] = p.Operation, p.Forceable, firstBlocker(p.Blockers), forceToken(p)
		if pr := p.Probe; pr != nil {
			out["probe"] = map[string]any{"responding": pr.Responding, "startedAt": unixTime(pr.StartedAt), "finishedAt": unixTime(pr.FinishedAt)}
		}
		return out, nil
	})
}

// POST /nodes/{node}/force-remove {opId, plan, operation} →
// force-remove-node (control.NodeForceChange with a fresh plan's probe,
// Expected = its Expected). 409 not-forceable when sfcd gives no probe.
func (s *Server) handleForceRemoveNode(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string `json:"opId"`
		Plan      string `json:"plan"`
		Operation string `json:"operation,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node := r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, actionBody{sfc.ActionForceRemoveNode, req}, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		op, err := nodeOperation(req.Operation, "force", req.OpID)
		if err != nil {
			return "", nil, 0, "", err
		}
		p, err := c.PlanNodeForceRemoval(ctx, control.NodeForceQuery{Node: node, Operation: op})
		if err != nil {
			return "", nil, 0, "", err
		}
		if err := samePlan(req.Plan, forceToken(p), "removal plan"); err != nil {
			return "", nil, 0, "", err
		}
		if p.Probe == nil {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "not-forceable", "sfcd gave no removal probe for this server"}
		}
		return sfc.ActionForceRemoveNode, control.NodeForceChange{ID: node, Operation: op, Epoch: p.Epoch, Probe: *p.Probe}, p.Expected, "node/" + node, nil
	})
}

// GET /nodes/{node}/remove-plan → removePlanShape (node-remove-plan, the
// check before remove-node). A blocker code is the code remove-node
// refuses with.
func (s *Server) handleNodeRemovePlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		p, err := c.PlanNodeRemoval(ctx, r.PathValue("node"))
		if err != nil {
			return nil, err
		}
		return removePlanShape(p), nil
	})
}

var diagTimeRE = regexp.MustCompile(`[^0-9A-Za-z]+`)

// GET /nodes/{node}/diagnostics → sfcd's diagnostics bundle (tar+gzip, at
// most 64 KiB) as a download. The web checks its digest, relays it and
// keeps no copy.
func (s *Server) handleNodeDiagnostics(w http.ResponseWriter, r *http.Request, ws *webSession) {
	node := r.PathValue("node")
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var d control.NodeDiagnosticsBundle
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		d, err = c.ReadNodeDiagnostics(ctx, node)
		if err == nil && !d.Valid(node) {
			err = &httpErr{http.StatusBadGateway, "bad-bundle", "the diagnostics bundle does not match its digest or limits"}
		}
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	name := "sfcd-diag-" + node + "-" + strings.Trim(diagTimeRE.ReplaceAllString(d.CreatedAt, ""), "-") + ".tar.gz"
	s.log.Info("node diagnostics", "user", ws.user.Username, "node", node, "bytes", len(d.Data))
	h := w.Header()
	h.Set("Content-Type", "application/gzip")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Content-Length", strconv.Itoa(len(d.Data)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-SFC-Created-At", d.CreatedAt)
	h.Set("X-SFC-Digest", hex.EncodeToString(d.Digest[:]))
	if d.Truncated {
		h.Set("X-SFC-Truncated", "true")
		h.Set("X-SFC-Omitted", strings.Join(d.Omitted, ","))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(d.Data)
}
