// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// CD (UI-40..43 '자동 배포' tab): the apps row's CD view, the CD actions of
// `sfcli cd`, the policy and the field overrides of `sfcli cd override`.
// sfcd plans, fetches sources and judges permissions; the web only builds
// the same signed changes the CLI builds:
//   - every action's Expected is the row's CD revision (cd.revision);
//   - sync/recover/configure also carry the execution intent target the
//     row shows (AppCDChange.Target), unless the caller sends expected,
//     which selects strict revision CAS as --expected-revision does;
//   - sync/recover choose the row's candidate and registration;
//   - configure carries the policy revision;
//   - override/release carry the field's target and revision from
//     app-cd-field and the override's own revision (0 for a new one).

// cdRow is the app's CD view; 404 not-cd when the app is not a CD app.
func cdRow(ctx context.Context, c sfc.Conn, tenant, app string) (sfc.AppView, *sfc.AppCD, error) {
	apps, err := allApps(ctx, c, tenant)
	if err != nil {
		return sfc.AppView{}, nil, err
	}
	for _, a := range apps {
		if a.App == app && a.CD != nil {
			return a, a.CD, nil
		}
	}
	return sfc.AppView{}, nil, &httpErr{http.StatusNotFound, "not-cd", "no such app with automatic deployment"}
}

// GET /t/{t}/apps/{app}/cd → {app, deployment, health, operation, cd}: the
// row's CD view (the same object as apps[].cd).
func (s *Server) handleCD(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		a, cd, err := cdRow(ctx, c, r.PathValue("t"), r.PathValue("app"))
		if err != nil {
			return nil, err
		}
		out := map[string]any{"app": a.App, "deployment": a.Deployment, "health": a.Health, "operation": a.Operation, "cd": cd}
		// webhook: the newest check (post-sync once it ran); checks: both.
		checks := s.cdCheckView(r.PathValue("t"), r.PathValue("app"), hex.EncodeToString(cd.CandidateDigest[:]))
		var newest map[string]any
		for _, k := range []string{"pre-sync", "post-sync"} {
			if v, ok := checks[k].(map[string]any); ok {
				if newest == nil || v["atUnix"].(int64) >= newest["atUnix"].(int64) {
					newest = v
				}
			}
		}
		for _, v := range checks {
			delete(v.(map[string]any), "atUnix")
		}
		if newest != nil {
			out["webhook"], out["checks"] = newest, checks
		}
		return out, nil
	})
}

var cdActions = map[string]string{
	"sync": sfc.ActionSyncApp, "recover": sfc.ActionRecoverApp, "replan": sfc.ActionReplanApp,
	"pause": sfc.ActionPauseAppCD, "resume": sfc.ActionResumeAppCD, "abandon": sfc.ActionAbandonAppSync,
}

// POST /t/{t}/apps/{app}/cd/{sync|recover|replan|pause|resume|abandon}
// {opId, operation?, candidate?, expected?} → the CD action. sync/recover
// take the row's candidate; candidate (cd.candidateDigest as shown) makes
// the request fail with 409 candidate-changed when the row moved on.
// operation is the deployment operation ID (default "sync-<opId>").
func (s *Server) handleCDAction(verb string) func(http.ResponseWriter, *http.Request, *webSession) {
	action := cdActions[verb]
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) { s.cdAction(w, r, ws, action) }
}

func (s *Server) cdAction(w http.ResponseWriter, r *http.Request, ws *webSession, action string) {
	var req struct {
		OpID      string `json:"opId"`
		Operation string `json:"operation,omitempty"`
		Candidate string `json:"candidate,omitempty"`
		Expected  uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	choose := action == sfc.ActionSyncApp || action == sfc.ActionRecoverApp
	if choose && req.Operation == "" {
		req.Operation = "sync-" + req.OpID
	}
	body := struct {
		Action string
		Req    any
	}{action, req}
	s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if choose && deployment.ResourceKey("task", "tenant", app, req.Operation) == "" {
			return "", nil, 0, "", invalid("operation: lowercase letters, digits and -, starting with a letter, at most 63")
		}
		if !choose && (req.Operation != "" || req.Candidate != "") {
			return "", nil, 0, "", invalid("operation and candidate are for sync and recover only")
		}
		_, cd, err := cdRow(ctx, c, tenant, app)
		if err != nil {
			return "", nil, 0, "", err
		}
		q := control.AppCDChange{Tenant: tenant, App: app}
		if choose {
			if cd.Candidate == "" || cd.CandidateDigest == ([32]byte{}) {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "no-candidate", "there is no source candidate to deploy"}
			}
			if req.Candidate != "" && req.Candidate != hex.EncodeToString(cd.CandidateDigest[:]) {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "candidate-changed", "the source candidate changed; read the app again"}
			}
			q.Choice = &control.AppDeliveryChoice{Operation: req.Operation, Candidate: cd.CandidateDigest, Registration: cd.Registration}
			if err := cdTarget(&q, cd, req.Expected); err != nil {
				return "", nil, 0, "", err
			}
		}
		return action, q, expectedOr(req.Expected, cd.Revision), "app/" + app, nil
	})
}

// cdTarget sets the execution intent target unless expected selects
// strict revision CAS (as the CLI's freezeCDTarget).
func cdTarget(q *control.AppCDChange, cd *sfc.AppCD, expected uint64) error {
	if expected != 0 {
		return nil
	}
	if cd.Target == ([32]byte{}) {
		return &httpErr{http.StatusConflict, "no-target", "the app shows no execution intent target; send expected (cd.revision) instead"}
	}
	t := cd.Target
	q.Target = &t
	return nil
}

// PUT /t/{t}/apps/{app}/cd/policy {opId, policy, expected?} →
// configure-app-cd. policy is the CD policy object in the shape apps[].cd.
// policy shows (enabled, source{kind, repository, ref, path, credential},
// poll, sync{mode, drift, prune, allowEmpty}, runtime{mode, expiry},
// limits{fetch, bytes, queued, active}); unknown fields are refused.
func (s *Server) handleCDPolicy(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string          `json:"opId"`
		Policy   json.RawMessage `json:"policy"`
		Expected uint64          `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		policy, err := cdPolicy(req.Policy)
		if err != nil {
			return "", nil, 0, "", invalid("policy: not a valid CD policy object (at most 32 KiB, known fields only)")
		}
		_, cd, err := cdRow(ctx, c, tenant, app)
		if err != nil {
			return "", nil, 0, "", err
		}
		q := control.AppCDChange{Tenant: tenant, App: app, Policy: &policy, PolicyRevision: cd.PolicyRevision}
		if err := cdTarget(&q, cd, req.Expected); err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionConfigureAppCD, q, expectedOr(req.Expected, cd.Revision), "app/" + app, nil
	})
}

// cdPolicy reads the camelCase policy (field names match the Go names
// case-insensitively), then checks its canonical form as sfcli cd configure
// checks a policy file.
func cdPolicy(raw json.RawMessage) (deployment.DeliveryDeclaration, error) {
	var p deployment.DeliveryDeclaration
	if len(raw) == 0 || len(raw) > 32<<10 {
		return p, schema.ErrInput
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	canonical, _ := json.Marshal(p)
	return schema.Input[deployment.DeliveryDeclaration](canonical)
}

// cdPath checks an override path (deployment.AllowedAppOverride).
func cdPath(path []string) error {
	if !deployment.AllowedAppOverride(path) {
		return invalid("path: services.<service>.<field> (image, command, entrypoint, user, stop_signal, stop_grace_period, cpus, mem_limit, dns, dns_search, logging), services.<service>.environment.<KEY> or services.<service>.healthcheck.<field>")
	}
	return nil
}

// GET /t/{t}/apps/{app}/cd/field?path=services&path=web&path=image →
// app-cd-field {target, revision, path, override?{revision, actor,
// anchors}, refs}: one overridable field and its current override.
func (s *Server) handleCDField(w http.ResponseWriter, r *http.Request, ws *webSession) {
	path := r.URL.Query()["path"]
	if err := cdPath(path); err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (sfc.AppCDField, error) {
		return c.AppDeliveryField(ctx, r.PathValue("t"), control.AppCDFieldRequest{App: r.PathValue("app"), Path: path})
	})
}

// PUT /t/{t}/apps/{app}/cd/overrides {opId, path, value} → override-app;
// DELETE /t/{t}/apps/{app}/cd/overrides {opId, path} → release-app-override.
// Both read app-cd-field first (Expected = its revision, Target = its
// target); value is the field's JSON value. 409 no-override when releasing
// a field without one, 409 no-ref when the field's service has no object
// to pin the override to.
func (s *Server) handleCDOverride(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID  string          `json:"opId"`
		Path  []string        `json:"path"`
		Value json.RawMessage `json:"value,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	release := r.Method == http.MethodDelete
	action := sfc.ActionOverrideApp
	if release {
		action = sfc.ActionReleaseOverride
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	body := struct {
		Action string
		Req    any
	}{action, req}
	s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if err := cdPath(req.Path); err != nil {
			return "", nil, 0, "", err
		}
		switch {
		case release && len(req.Value) > 0:
			return "", nil, 0, "", invalid("value: not for a release")
		case !release && (len(req.Value) == 0 || !json.Valid(req.Value) || string(req.Value) == "null"):
			return "", nil, 0, "", invalid("value: the field's JSON value")
		}
		f, err := c.AppDeliveryField(ctx, tenant, control.AppCDFieldRequest{App: app, Path: req.Path})
		if err != nil {
			return "", nil, 0, "", err
		}
		t := f.Target
		q := control.AppOverrideChange{Target: &t, Tenant: tenant, App: app, Path: slices.Clone(req.Path)}
		if f.Override != nil {
			q.Revision = f.Override.Revision
		}
		if release {
			if f.Override == nil {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "no-override", "this field has no override"}
			}
		} else {
			if len(f.Refs) != 1 {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "no-ref", "the field's service has no deployed object to pin the override to"}
			}
			q.Value, q.Refs = req.Value, f.Refs
		}
		return action, q, f.Revision, "app/" + app, nil
	})
}
