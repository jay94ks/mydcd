// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// REQ-29 standalone containers in mydcd's shape (docs/reference/standalone.md):
//
//   - up: app-plan-stream with AppPlanRequest.Standalone plans the one
//     compose service; the planned artifact is uploaded under the internal
//     scope (begin-app-upload, put-app-part) and accepted by standalone-up
//     control.AppBegin{Standalone, Target}. Target is the absent target
//     (control.AppCreateTarget) for a new name, the row's Target for a
//     change; Expected = the row's Revision (0 new). Protected Group
//     approvals bind to that original like a deploy's begin-app. This is a
//     deploy job (store.DeployJob.Standalone) under one web opId.
//   - pin / remove: control.StandaloneChange{..., Operation, Target}.
//   - extend: control.StandaloneExtendChange from the row.
//   - stop / start / restart: task-restart-plan, then
//     control.TaskRestartChange with the plan's Target and ManagementTarget,
//     Expected = plan.StandaloneRevision.
//
// Every change signs the row's management Target read just before, so a
// change made meanwhile is refused by mydcd, not decided here.

// splitStandalone turns the web's flat definition (name, lifetime,
// restart|ttl/grace, mode and one service's fields at the same level) into
// mydcd's StandaloneDefinition and a compose document with that one
// service. ttl/grace are Go durations ("1h") or seconds.
func splitStandalone(flat []byte) (control.StandaloneDefinition, []byte, error) {
	var def control.StandaloneDefinition
	var root yaml.Node
	if err := yaml.Unmarshal(flat, &root); err != nil || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return def, nil, invalid("yaml: a mapping with name and one service's fields")
	}
	m := root.Content[0]
	svc := &yaml.Node{Kind: yaml.MappingNode}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		var err error
		switch k.Value {
		case "name":
			def.Name = v.Value
		case "lifetime":
			def.Lifetime = v.Value
		case "mode":
			def.Mode = v.Value
		case "restart":
			def.Restart = v.Value
		case "ttl":
			def.TTLSeconds, err = seconds(v.Value)
		case "grace":
			def.GraceSeconds, err = seconds(v.Value)
		default:
			svc.Content = append(svc.Content, k, v)
		}
		if err != nil {
			return def, nil, invalid(k.Value + ": a duration such as 1h or a number of seconds")
		}
	}
	if !lifecycle.ValidID(def.Name) {
		return def, nil, invalid("name: starts with a lowercase letter; lowercase letters, digits and -, at most 63")
	}
	doc := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "services"},
		{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: def.Name}, svc}},
	}}
	out, err := yaml.Marshal(doc)
	return def, out, err
}

func seconds(s string) (int64, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
		return n, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 || d%time.Second != 0 {
		return 0, errors.New("duration")
	}
	return int64(d / time.Second), nil
}

// standaloneAppPlan plans the flat definition (nothing is changed).
func standaloneAppPlan(ctx context.Context, c mydc.Conn, tenant string, flat []byte) (control.StandaloneDefinition, mydc.AppPlan, error) {
	def, doc, err := splitStandalone(flat)
	if err != nil {
		return def, mydc.AppPlan{}, err
	}
	p, err := c.AppPlan(ctx, mydc.AppPlanRequest{Tenant: tenant, Document: doc, Standalone: &def})
	var me *mydc.Error
	if errors.As(err, &me) {
		if code := mydc.LimitInputCode(me.InputCode); code != "" {
			// a count limit (temp per user / tenant / server) is its own code
			return def, p, &httpErr{http.StatusConflict, code, "the standalone container limit is reached (" + me.InputCode + ")"}
		}
		if me.InputCode == "HOST_PORT_CONFLICT" {
			return def, p, &httpErr{http.StatusConflict, "host-port-conflict", "another container on that server already publishes the same host port"}
		}
	}
	if err != nil {
		return def, p, err
	}
	if p.App == "" {
		return def, p, &httpErr{http.StatusBadGateway, "plan-invalid", "the plan names no internal scope"}
	}
	return def, p, nil
}

// planDeployment: the deployment the artifact is planned for (the
// blueprint's scope). "" when the artifact is not a blueprint this build
// decodes (the fake adapter plans the YAML itself).
func planDeployment(art []byte) string {
	b, err := deployment.DecodeBlueprint(art)
	if err != nil {
		return ""
	}
	return b.Scope().Deployment
}

// standaloneRow reads the row of name; found=false when there is none.
func standaloneRow(ctx context.Context, c mydc.Conn, tenant, name string) (mydc.StandaloneView, bool, error) {
	v, err := c.Standalone(ctx, tenant, name)
	if isMydcCode(err, mydc.CodeMissing) {
		return v, false, nil
	}
	return v, err == nil, err
}

// standaloneOperation: the mydcd operation ID of a web op (lifecycle.ValidID).
func standaloneOperation(opID string) string { return "op-" + opID }

// POST /t/{t}/standalone/plan {yaml}
func (s *Server) handleStandalonePlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		YAML string `json:"yaml"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.YAML == "" || len(req.YAML) > 1<<20 {
		writeError(w, http.StatusBadRequest, "bad-request", "yaml: 1 byte .. 1 MiB")
		return
	}
	tenant := r.PathValue("t")
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		def, p, err := standaloneAppPlan(ctx, c, tenant, []byte(req.YAML))
		if err != nil {
			return nil, err
		}
		row, found, err := standaloneRow(ctx, c, tenant, def.Name)
		if err != nil {
			return nil, err
		}
		out := map[string]any{"name": def.Name, "scope": p.App, "digest": hex.EncodeToString(p.Digest[:]), "revision": uint64(0), "create": !found,
			"recreate": false, "changes": []map[string]any{}, "impact": []map[string]any{}, "services": p.Services}
		if found {
			out["revision"] = row.Revision
		}
		if sp := p.Standalone; sp != nil {
			changes, impact := []map[string]any{}, []map[string]any{}
			for _, ch := range sp.Changes {
				changes = append(changes, map[string]any{"field": ch.Field, "before": ch.Before, "after": ch.After})
			}
			for _, im := range sp.Impact {
				v := map[string]any{"kind": im.Kind, "target": im.Target, "detail": im.Detail, "blocking": im.Blocking}
				if im.Code != "" {
					v["code"] = im.Code
				}
				impact = append(impact, v)
			}
			out["recreate"], out["changes"], out["impact"] = sp.Recreate, changes, impact
			out["limits"] = map[string]int{"mine": sp.Limits.Mine, "mineMax": sp.Limits.MineMax, "tenant": sp.Limits.Tenant, "tenantMax": sp.Limits.TenantMax,
				"node": sp.Limits.Node, "nodeMax": sp.Limits.NodeMax}
		}
		return out, nil
	})
}

type standaloneUpReq struct {
	OpID     string `json:"opId"`
	YAML     string `json:"yaml"`
	Expected uint64 `json:"expected,omitempty"`
	Imported *struct {
		App        string   `json:"app"`
		Deployment string   `json:"deployment,omitempty"`
		Service    string   `json:"service"`
		Items      []string `json:"items,omitempty"`
	} `json:"importedFrom,omitempty"`
}

func (q *standaloneUpReq) digest(tenant string) string {
	h := sha256.Sum256(fmt.Appendf(nil, "standalone-up\x00%s\x00%d\x00%s", tenant, q.Expected, q.YAML))
	return hex.EncodeToString(h[:])
}

// POST /t/{t}/standalone/up {opId, yaml, expected?, importedFrom?}: a
// deploy job (upload, parts, standalone-up) under one opId. Sending the
// same opId again continues it; a protected Group waits on
// /t/{t}/deploy/{op}/approve like a deploy. expected (the row's revision
// as the form read it) must still be the row's revision; 0 = a new name.
func (s *Server) handleStandaloneUp(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req standaloneUpReq
	if !readJSON(w, r, &req) {
		return
	}
	if !uuidRE.MatchString(req.OpID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	if req.YAML == "" || len(req.YAML) > 1<<20 {
		writeError(w, http.StatusBadRequest, "bad-request", "yaml: 1 byte .. 1 MiB")
		return
	}
	if im := req.Imported; im != nil {
		ok := validName(im.App) && validName(im.Service) && (im.Deployment == "" || validName(im.Deployment)) && len(im.Items) <= len(importItems)
		for _, it := range im.Items {
			ok = ok && slices.Contains(importItems, it)
		}
		if !ok {
			writeError(w, http.StatusBadRequest, "bad-request", "importedFrom: app and service names, items from imageCmd, netEnv, volumes, secrets, ingress")
			return
		}
	}
	tenant := r.PathValue("t")
	dg := req.digest(tenant)
	parent, err := s.opt.Store.GetOp(ws.user.ID, req.OpID)
	switch {
	case err == nil:
		if parent.Digest != dg || parent.Deploy == nil || parent.Deploy.Standalone == nil || parent.Deploy.Tenant != tenant {
			writeError(w, http.StatusConflict, "op-conflict", "this opId was already used for a different change")
			return
		}
	case errors.Is(err, store.ErrNotFound):
		parent = nil
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		if parent == nil {
			var err error
			if parent, err = s.newStandaloneUp(ctx, c, ws, tenant, &req, dg); err != nil {
				return err
			}
		}
		return s.runDeploy(ctx, c, ws, parent, false)
	})
	if err != nil {
		var he *httpErr
		if errors.As(err, &he) {
			writeError(w, he.status, he.code, he.msg)
			return
		}
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, opStatus(parent), map[string]any{"op": viewOp(parent)})
}

// newStandaloneUp plans the definition, fixes the standalone-up begin
// (Target, Expected) and stores the job and the web's origin record.
func (s *Server) newStandaloneUp(ctx context.Context, c mydc.Conn, ws *webSession, tenant string, req *standaloneUpReq, dg string) (*store.Op, error) {
	def, p, err := standaloneAppPlan(ctx, c, tenant, []byte(req.YAML))
	if err != nil {
		return nil, err
	}
	art := p.Data
	if len(art) == 0 || len(art) > 4<<20 || p.Length != len(art) || sha256.Sum256(art) != p.Digest {
		return nil, &httpErr{http.StatusBadGateway, "plan-invalid", "the plan artifact does not match its digest"}
	}
	row, found, err := standaloneRow(ctx, c, tenant, def.Name)
	if err != nil {
		return nil, err
	}
	dep := planDeployment(art)
	var target [32]byte
	var expected uint64
	if found {
		target, expected = row.Target, row.Revision
	} else {
		who, err := c.Whoami(ctx)
		if err != nil {
			return nil, err
		}
		target = control.AppCreateTarget(who.Session.Cluster, tenant, p.App, dep)
	}
	// the form's revision, when given, is what is signed: mydcd refuses a
	// stale one, not the web
	expected = expectedOr(req.Expected, expected)
	upload := "web-" + req.OpID
	begin := control.AppBegin{Standalone: &def, Target: &target, Tenant: tenant, App: p.App, Deployment: dep, Upload: upload, Operation: standaloneOperation(req.OpID)}
	raw, err := json.Marshal(begin)
	if err != nil {
		return nil, err
	}
	// recorded before anything is sent so the op's settling finds it
	e := store.StandaloneOrigin{OpID: req.OpID, State: store.OpPending, User: ws.user.ID, Username: ws.user.Username, At: time.Now()}
	if im := req.Imported; im != nil {
		e.App, e.Deployment, e.Service, e.Items = im.App, im.Deployment, im.Service, im.Items
	}
	if err := s.opt.Store.AddStandaloneOrigin(tenant, def.Name, e); err != nil {
		return nil, err
	}
	now := s.now()
	parent := &store.Op{ID: req.OpID, User: ws.user.ID, Username: ws.user.Username, Action: mydc.ActionStandaloneUp, Tenant: tenant, Target: def.Name,
		Digest: dg, State: store.OpRunning, SubmittedAt: now, UpdatedAt: now,
		Deploy: &store.DeployJob{Tenant: tenant, App: p.App, Deployment: dep, UploadID: upload, Document: art, Digest: hex.EncodeToString(p.Digest[:]),
			Parts: (len(art) + mydc.AppPartBytes - 1) / mydc.AppPartBytes, Standalone: &store.StandaloneUpJob{Name: def.Name, Begin: raw, Expected: expected}}}
	existing, err := s.opt.Store.CreateOp(parent)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return existing, nil
	}
	return parent, nil
}

// standaloneChangeReq is the body of the per-container changes.
type standaloneChangeReq struct {
	OpID       string `json:"opId"`
	Expected   uint64 `json:"expected,omitempty"` // the row's revision as shown; 0 = the current one (stop/start/restart: the plan's)
	NewName    string `json:"newName,omitempty"`  // pin
	Restart    string `json:"restart,omitempty"`  // pin
	TTLSeconds int64  `json:"ttlSeconds,omitempty"`
}

// POST /t/{t}/standalone/{name}/{pin|extend|stop|start|restart|remove}
func (s *Server) handleStandaloneChange(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req standaloneChangeReq
	if !readJSON(w, r, &req) {
		return
	}
	tenant, name, verb := r.PathValue("t"), r.PathValue("name"), r.PathValue("verb")
	action := "standalone-" + verb
	switch action {
	case mydc.ActionStandalonePin, mydc.ActionStandaloneExtend, mydc.ActionStandaloneStop, mydc.ActionStandaloneStart,
		mydc.ActionStandaloneRestart, mydc.ActionStandaloneRemove:
	default:
		writeError(w, http.StatusNotFound, "not-found", "no such standalone change")
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, struct {
		Verb string
		Req  standaloneChangeReq
	}{verb, req}, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		row, found, err := standaloneRow(ctx, c, tenant, name)
		if err != nil {
			return "", nil, 0, "", err
		}
		if !found {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such standalone container"}
		}
		rev := expectedOr(req.Expected, row.Revision) // a stale one is mydcd's to refuse
		op := standaloneOperation(req.OpID)
		display := "standalone/" + name
		switch action {
		case mydc.ActionStandalonePin:
			if req.NewName != "" && !lifecycle.ValidID(req.NewName) {
				return "", nil, 0, "", invalid("newName: starts with a lowercase letter; lowercase letters, digits and -, at most 63")
			}
			if !slices.Contains([]string{"", "no", "on-failure", "always"}, req.Restart) {
				return "", nil, 0, "", invalid("restart: no, on-failure or always")
			}
			t := row.Target
			return action, control.StandaloneChange{Tenant: tenant, Name: name, NewName: req.NewName, Restart: req.Restart, Operation: op, Target: &t}, rev, display, nil
		case mydc.ActionStandaloneRemove:
			t := row.Target
			return action, control.StandaloneChange{Tenant: tenant, Name: name, Operation: op, Target: &t}, rev, display, nil
		case mydc.ActionStandaloneExtend:
			if req.TTLSeconds <= 0 {
				return "", nil, 0, "", invalid("ttlSeconds: the new time left, in seconds")
			}
			return action, control.StandaloneExtendChange{Tenant: tenant, Name: name, Scope: row.Scope, Operation: op, CreatedAt: row.CreatedAt,
				PreviousExpiresAt: row.ExpiresAt, TTLSeconds: req.TTLSeconds, Target: row.Target}, rev, display, nil
		}
		p, err := c.TaskRestartPlan(ctx, tenant, control.TaskRestartQuery{Action: action, Selection: containerops.Selection{Standalone: name}})
		if err != nil {
			return "", nil, 0, "", err
		}
		q := control.TaskRestartChange{Tenant: tenant, Standalone: name, Operation: op, Target: p.Target, ManagementTarget: p.ManagementTarget}
		q.Selection.Service, q.Selection.Instance = p.Container.Service, p.Container.Instance
		return action, q, expectedOr(req.Expected, p.StandaloneRevision), display, nil
	})
}
