// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
)

// REQ-29 parts already in mydcd's shape (docs/reference/standalone.md;
// mydcd picks the management-target CAS from the Change):
//
//   - StandaloneView.Target: the management target (digest32). It changes
//     when an accepted management intent changes (up, pin, extend,
//     stop/start/restart, remove) and not on connection samples.
//   - standalone-pin / standalone-remove take control.StandaloneChange
//     {Tenant, Name, NewName, Restart, Operation, Target}; Expected =
//     StandaloneView.Revision. A Target other than the current one is
//     ConditionFailed.
//   - standalone-stop/start/restart: TaskRestartPlan(tenant,
//     TaskRestartQuery{Action, Selection{Standalone}}) gives the plan; sign
//     control.TaskRestartChange{Tenant, Standalone, Operation, Selection,
//     Target: plan.Target, ManagementTarget: plan.ManagementTarget} with
//     Expected = plan.StandaloneRevision; TaskRestartStatus(tenant,
//     TaskRestartQuery{Selection{Standalone}, Operation}) reads it back.
//
// restart-task of an app Task uses the same plan/status with
// Selection{App, Service, Instance} and control.TaskRestartChange{Tenant,
// App, Operation, Selection, Target}, Expected = plan.InventoryRevision.

func standaloneScope(tenant, name string) string { return deployment.StandaloneScopeName(tenant, name) }

// managementTarget: the fake's digest of the accepted management intent.
func (e *standaloneEntry) managementTarget() [32]byte {
	raw, _ := json.Marshal(struct {
		Scope, Name, Lifetime, Restart string
		Intent                         uint64
		Removed                        bool
	}{e.scope, e.view.Name, e.view.Lifetime, e.view.RestartPolicy, e.intent, e.removed()})
	return sha256.Sum256(append([]byte("mydc-web-fake-standalone-target-1\x00"), raw...))
}

var standaloneControls = map[string]checker.ContainerAction{
	ActionStandaloneStop:    checker.StopContainer,
	ActionStandaloneStart:   checker.StartContainer,
	ActionStandaloneRestart: checker.RestartContainer,
}

// controlPlan: the TaskRestartPlan of action on e now, or why it does not
// apply ("" = it does).
func (w *world) controlPlan(e *standaloneEntry, action string) (control.TaskRestartPlan, string) {
	v := e.view
	mt := e.managementTarget()
	scope := e.scope
	p := control.TaskRestartPlan{ManagementTarget: &mt, Action: standaloneControls[action], StandaloneRevision: v.Revision, Schema: 1,
		Tenant: v.Tenant, App: scope, InventoryRevision: v.Revision, Registration: sha256.Sum256([]byte("registration\x00" + scope)),
		Container: containerops.Target{Standalone: v.Name, Cluster: w.cluster, Owner: fakeNodeKey(v.Node), Binding: sha256.Sum256([]byte("binding\x00" + scope)),
			Tenant: v.Tenant, App: scope, Service: v.Name, Node: v.Node, Instance: "1", Generation: max(1, v.Generation), Revision: max(v.Revision, v.Generation)},
		OwnerBoot: "boot-" + v.Node, StopGraceSeconds: 10, PreserveNative: true, PreserveWritableLayer: true, PreserveLogs: true}
	raw, _ := json.Marshal(p)
	p.Target = sha256.Sum256(append([]byte("mydc-web-fake-task-restart-1\x00"), raw...))
	switch {
	case e.removed():
		return p, "removed"
	case action == ActionStandaloneStart && (v.Lifetime == LifetimeTemp || v.State == "running"):
		return p, "start: stopped fixed container only"
	case action != ActionStandaloneStart && v.State != "running":
		return p, "not running"
	}
	return p, ""
}

func (c *fakeConn) TaskRestartPlan(ctx context.Context, tenant string, q control.TaskRestartQuery) (control.TaskRestartPlan, error) {
	const m = "task-restart-plan"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.TaskRestartPlan{}, err
	}
	defer c.unlock()
	if !q.Valid(true) {
		return control.TaskRestartPlan{}, fail(m, CodeInvalid, "")
	}
	w := c.f.w
	if q.Selection.Standalone == "" {
		// restart-task of an app Task.
		a := w.apps[tenant+"/"+q.Selection.App]
		if a == nil || a.view.Retiring {
			return control.TaskRestartPlan{}, fail(m, CodeMissing, "")
		}
		i := slices.IndexFunc(a.tasks, func(t Task) bool { return t.Service == q.Selection.Service && t.Instance == q.Selection.Instance })
		if i < 0 {
			return control.TaskRestartPlan{}, fail(m, CodeMissing, "")
		}
		return w.appControlPlan(a, a.tasks[i]), nil
	}
	if standaloneControls[q.Action] == "" {
		return control.TaskRestartPlan{}, fail(m, CodeInvalid, "standalone-stop/-start/-restart")
	}
	w.expireStandalones(c.f.now().Unix())
	e := w.standalones[tenant+"/"+q.Selection.Standalone]
	if e == nil || !w.standaloneVisible(c.session.User, e) {
		return control.TaskRestartPlan{}, fail(m, CodeMissing, "")
	}
	p, why := w.controlPlan(e, q.Action)
	if why != "" {
		return control.TaskRestartPlan{}, fail(m, CodeInvalid, why)
	}
	return p, nil
}

// appControlPlan: the restart-task plan of one app Task. Expected =
// InventoryRevision (the app's revision in the fake).
func (w *world) appControlPlan(a *fakeApp, t Task) control.TaskRestartPlan {
	v := a.view
	p := control.TaskRestartPlan{Schema: 1, Tenant: v.Tenant, App: v.App, InventoryRevision: v.Revision, Registration: sha256.Sum256([]byte("registration\x00" + v.Tenant + "/" + v.App)),
		Container: containerops.Target{Cluster: w.cluster, Owner: fakeNodeKey(t.Node), Binding: sha256.Sum256([]byte("binding\x00" + v.Tenant + "/" + v.App + "/" + t.Service + "/" + t.Instance)),
			Tenant: v.Tenant, App: v.App, Service: t.Service, Node: t.Node, Instance: t.Instance, Generation: max(1, t.Generation), Revision: max(v.Revision, t.Generation), NativeID: nativeIDOf(t)},
		OwnerBoot: "boot-" + t.Node, StopGraceSeconds: 10, PreserveNative: true, PreserveWritableLayer: true, PreserveLogs: true}
	raw, _ := json.Marshal(struct {
		P         control.TaskRestartPlan
		StartedAt int64
	}{p, t.StartedAt})
	p.Target = sha256.Sum256(append([]byte("mydc-web-fake-task-restart-1\x00"), raw...))
	return p
}

func (c *fakeConn) TaskRestartStatus(ctx context.Context, tenant string, q control.TaskRestartQuery) (control.TaskRestartStatus, error) {
	const m = "task-restart-status"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return control.TaskRestartStatus{}, err
	}
	defer c.unlock()
	if !q.Valid(false) {
		return control.TaskRestartStatus{}, fail(m, CodeInvalid, "")
	}
	s, ok := c.f.w.saControls[controlKey(tenant, q.Selection, q.Operation)]
	if !ok {
		return control.TaskRestartStatus{}, fail(m, CodeMissing, "")
	}
	if s.Plan.ManagementTarget != nil {
		t := *s.Plan.ManagementTarget
		s.Plan.ManagementTarget = &t
	}
	return s, nil
}

// controlKey: saControls key of an app's or a standalone's operation.
func controlKey(tenant string, sel containerops.Selection, operation string) string {
	if sel.Standalone != "" {
		return tenant + "/standalone/" + sel.Standalone + "/" + operation
	}
	return tenant + "/app/" + sel.App + "/" + operation
}

// realStandaloneControl checks a signed TaskRestartChange against e now.
func (w *world) realStandaloneControl(e *standaloneEntry, action string, q control.TaskRestartChange) error {
	p, why := w.controlPlan(e, action)
	if q.ManagementTarget == nil || *q.ManagementTarget != *p.ManagementTarget || q.Target != p.Target {
		return errCAS
	}
	if why != "" {
		return errCAS
	}
	return nil
}

func (w *world) recordControl(sel containerops.Selection, actor string, q control.TaskRestartChange, p control.TaskRestartPlan, next uint64, now int64) {
	if w.saControls == nil {
		w.saControls = map[string]control.TaskRestartStatus{}
	}
	w.saControls[controlKey(q.Tenant, sel, q.Operation)] = control.TaskRestartStatus{Operation: q.Operation, Status: "completed", User: actor, Plan: p, Revision: next, At: uint64(now)}
}

// volumeConflict: mydcd's VOLUME_WRITER_CONFLICT for one mount of a
// standalone named self: writing beside any other attached user, or reading
// beside another attached writer. Readers share.
func (w *world) volumeConflict(tenant, self string, vol volumeRow, rw bool) bool {
	others, selfAttached := 0, 0
	otherWriter := false
	for _, u := range w.volumeUsers(tenant, vol.Name, "") {
		if !u.Attached {
			continue
		}
		if u.Kind == NetworkUserStandalone && u.Standalone == self {
			selfAttached++
			continue
		}
		others++
		otherWriter = otherWriter || !u.ReadOnly
	}
	if rw {
		return others > 0 || vol.Consumers > selfAttached
	}
	return otherWriter
}

// --- standalone-up in mydcd's shape ---------------------------------------
//
// AppPlan with AppPlanRequest.Standalone plans one compose service (the
// upload document) as a standalone container; App is the internal scope
// (deployment.StandaloneScopeName). The upload goes by begin-app-upload /
// put-app-part with that App, then standalone-up control.AppBegin
// {Standalone, Target, Tenant, App, Deployment, Upload, Operation}:
// Target = control.AppCreateTarget(cluster, tenant, App, Deployment) for a
// new name, the row's Target for a change; Expected = the row's Revision
// (0 new). Secret Group approvals bind to that original like begin-app.
// StandaloneOperation(tenant, name, Operation) reads the result.

// standaloneFlat turns a definition plus a one-service compose document
// into the fake's flat definition. mydcd's defaults: temp, entrypoint,
// TTL 3600 s, grace 600 s.
func standaloneFlat(def control.StandaloneDefinition, compose []byte) ([]byte, error) {
	var d map[string]any
	if err := yaml.Unmarshal(compose, &d); err != nil {
		return nil, &inputError{code: "APP_DOCUMENT_INVALID", detail: err.Error()}
	}
	svcs, _ := d["services"].(map[string]any)
	if n, _ := d["name"].(string); len(svcs) != 1 || n != "" && n != def.Name || d["x-mydc"] != nil {
		return nil, &inputError{code: "STANDALONE_SINGLE_SERVICE_REQUIRED", detail: "services"}
	}
	var flat map[string]any
	for id, v := range svcs {
		flat, _ = v.(map[string]any)
		if flat == nil {
			return nil, &inputError{code: "APP_DOCUMENT_INVALID", detail: "services." + id}
		}
		x, _ := flat["x-mydc"].(map[string]any)
		if flat["depends_on"] != nil || x != nil && (x["nodes"] != nil || x["per_node"] != nil || x["instance"] != nil) {
			return nil, &inputError{code: "STANDALONE_SERVICE_REFERENCE", detail: "services." + id}
		}
	}
	lifetime, mode := def.Lifetime, def.Mode
	if lifetime == "" {
		lifetime = LifetimeTemp
	}
	if mode == "" {
		mode = ModeEntrypoint
	}
	flat["name"], flat["lifetime"], flat["mode"] = def.Name, lifetime, mode
	if def.Restart != "" {
		flat["restart"] = def.Restart
	}
	if lifetime == LifetimeTemp {
		ttl, grace := def.TTLSeconds, def.GraceSeconds
		if ttl == 0 {
			ttl = 3600
		}
		if grace == 0 {
			grace = 600
		}
		flat["ttl"], flat["grace"] = fmt.Sprintf("%ds", ttl), fmt.Sprintf("%ds", grace)
	}
	return yaml.Marshal(flat)
}

// standalonePlan: AppPlan for req.Standalone. Data is the document to upload.
func (w *world) standaloneAppPlan(user string, req AppPlanRequest) (AppPlan, error) {
	const m = "app-plan-stream"
	def := *req.Standalone
	if !lifecycle.ValidID(def.Name) {
		return AppPlan{}, &Error{Code: CodeInvalid, Method: m, InputCode: "STANDALONE_SINGLE_SERVICE_REQUIRED", Detail: "name"}
	}
	flat, err := standaloneFlat(def, req.Document)
	if err != nil {
		ie := err.(*inputError)
		return AppPlan{}, &Error{Code: CodeInvalid, Method: m, InputCode: ie.code, Detail: ie.detail}
	}
	sp, s, err := w.planStandalone(req.Tenant, user, flat)
	if err != nil {
		return AppPlan{}, &Error{Code: CodeInvalid, Method: m, InputCode: "APP_DOCUMENT_INVALID", Detail: err.Error()}
	}
	if old := w.standalones[req.Tenant+"/"+def.Name]; old != nil && !w.standaloneVisible(user, old) {
		return AppPlan{}, fail(m, CodeDenied, "")
	}
	var d standaloneDef
	if yaml.Unmarshal(flat, &d) == nil {
		if err := w.hostPortCheck(s.Node, "standalone:"+req.Tenant+"/"+def.Name, def.Name, parseHostPorts(d.Ports)); err != nil {
			return AppPlan{}, &Error{Code: CodeInvalid, Method: m, InputCode: err.code, Detail: err.detail}
		}
	}
	// mydcd checks the count limits only for a new name and refuses the
	// plan with the limit's code.
	for _, im := range sp.Impact {
		if sp.Create && im.Blocking && im.Kind == "limit" {
			return AppPlan{}, &Error{Code: CodeInvalid, Method: m, InputCode: limitInputCodes[im.Target], Detail: "standalone"}
		}
	}
	change := "add"
	if !sp.Create {
		change = "update"
	}
	return AppPlan{Digest: digestOf(req.Document), Length: len(req.Document), Data: append([]byte(nil), req.Document...), App: standaloneScope(req.Tenant, def.Name),
		Services: []PlannedService{{Name: def.Name, Image: s.Image, Node: s.Node, Change: change}}, Standalone: &sp}, nil
}

var limitInputCodes = map[string]string{LimitUserTemp: StandaloneUserLimit, LimitTenant: StandaloneTenantLimit, LimitNode: StandaloneNodeLimit}

// uploadedStandalone: the flat definition of a standalone-up's upload.
func (w *world) uploadedStandalone(b control.AppBegin) ([]byte, error) {
	u := w.uploads[b.Tenant+"/"+b.Upload]
	if u == nil || len(u.missing()) != 0 || u.view.App != b.App || b.App != standaloneScope(b.Tenant, b.Standalone.Name) {
		return nil, errors.New("upload incomplete")
	}
	flat, err := standaloneFlat(*b.Standalone, u.document())
	if err != nil {
		return nil, errors.New(err.(*inputError).code)
	}
	return flat, nil
}

// checkStandaloneBegin: the Target CAS and Group approvals of a real up.
func (w *world) checkStandaloneBegin(op UserOperation, b control.AppBegin, old *standaloneEntry) error {
	want := control.AppCreateTarget(w.cluster, b.Tenant, b.App, b.Deployment)
	if old != nil {
		want = old.managementTarget()
	}
	if *b.Target != want {
		return errCAS
	}
	if len(w.missingApprovals(op)) > 0 {
		return errors.New("group approval required")
	}
	return nil
}

func (w *world) finishStandaloneBegin(e *standaloneEntry, b control.AppBegin, actor string, now int64) {
	delete(w.uploads, b.Tenant+"/"+b.Upload)
	if e.ops == nil {
		e.ops = map[string]*AppOperation{}
	}
	e.ops[b.Operation] = &AppOperation{Tenant: b.Tenant, App: b.App, ID: b.Operation, Status: "succeeded", Submitter: w.users[actor].rec.Username, StartedAt: now, CompletedAt: now, Steps: []string{"reserve", "start"}}
}

// StandaloneOperation: `app-operation` with AppOperationRequest{Standalone,
// ID}, the result of a standalone-up original.
func (c *fakeConn) StandaloneOperation(ctx context.Context, tenant, name, id string) (AppOperation, error) {
	const m = "app-operation"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return AppOperation{}, err
	}
	defer c.unlock()
	e := c.f.w.standalones[tenant+"/"+name]
	if e == nil || !c.f.w.standaloneVisible(c.session.User, e) || e.ops[id] == nil {
		return AppOperation{}, fail(m, CodeMissing, "")
	}
	return *e.ops[id], nil
}

// extensionPreflight: control.CheckStandaloneExtensionSubmission. A new
// standalone-extend (no receipt yet) after the current expiry is refused
// before commit, with no result.
func (c *fakeConn) extensionPreflight(m string, op UserOperation) error {
	if op.Change.Action != ActionStandaloneExtend {
		return nil
	}
	var q control.StandaloneExtendChange
	if decodePayload(op.Change.Payload, &q) != nil {
		return nil // decide refuses it as Invalid
	}
	now := c.f.now().Unix()
	e := c.f.w.standalones[q.Tenant+"/"+q.Name]
	if e != nil && !e.removed() && e.view.Lifetime == LifetimeTemp && now >= e.view.ExpiresAt {
		return fail(m, CodeConflict, StandaloneTTLExpired)
	}
	return nil
}
