// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"io"
)

type standaloneOptions struct {
	passwordFDs                                                                                      groupPasswordFDs
	noInput                                                                                          bool
	method                                                                                           string
	name, tenant, file, node, deployment, operation, newName, restart, lifetime, mode, output, after onceString
	ttl, grace                                                                                       int64
	preview                                                                                          bool
	container                                                                                        *containerCLIOptions
}

func parseStandaloneOptions(args []string, out io.Writer) (standaloneOptions, error) {
	var o standaloneOptions
	f := flag.NewFlagSet("standalone", flag.ContinueOnError)
	f.SetOutput(out)
	f.Var(&o.tenant, "tenant", "tenant")
	f.Var(&o.file, "f", "single-service declaration")
	f.Var(&o.node, "node", "owner node")
	f.Var(&o.deployment, "deployment-id", "stable workload deployment")
	f.Var(&o.operation, "operation", "original operation ID")
	f.Var(&o.newName, "name", "new name for pin")
	f.Var(&o.restart, "restart", "fixed restart policy")
	f.Var(&o.lifetime, "lifetime", "temp or fixed")
	f.Var(&o.mode, "mode", "shell or entrypoint")
	f.Var(&o.output, "out", "private plan output")
	f.Var(&o.after, "after", "list cursor")
	f.Var(&o.passwordFDs, "group-password-fd", "explicit REALM/GROUP=FD (cluster: /GROUP), repeat per required group")
	f.BoolVar(&o.noInput, "no-input", false, "use existing approvals/explicit FDs without a terminal prompt")
	f.Int64Var(&o.ttl, "ttl-seconds", 0, "temporary TTL, default 3600, maximum 86400")
	f.Int64Var(&o.grace, "grace-seconds", 0, "disconnection grace, default 600")
	f.BoolVar(&o.preview, "preview", false, "read-only exact target plan")
	o.container = addContainerReadFlags(f)
	if len(args) == 0 {
		return o, errors.New("standalone requires a subcommand")
	}
	o.method = args[0]
	if err := f.Parse(expandContainerExecFlags(args[1:])); err != nil {
		return o, err
	}
	rest := f.Args()
	if o.method != "list" {
		if len(rest) == 0 || !lifecycle.ValidID(rest[0]) {
			return o, errors.New("standalone requires NAME")
		}
		o.name.value = rest[0]
		o.name.set = true
		rest = rest[1:]
		if err := f.Parse(rest); err != nil {
			return o, err
		}
		rest = f.Args()
	}
	if o.method == "exec" {
		o.container.argv = rest
	} else if len(rest) != 0 {
		return o, errors.New("unexpected standalone arguments")
	}
	definition := o.file.set || o.node.set || o.deployment.set || o.lifetime.set || o.mode.set || o.ttl != 0 || o.grace != 0
	switch o.method {
	case "plan", "up":
		if !o.file.set || o.newName.set || o.after.set || o.preview || o.method == "up" && !lifecycle.ValidID(o.operation.value) || o.method == "plan" && o.operation.set {
			return o, errors.New("plan/up requires -f FILE and up requires --operation ID")
		}
	case "resume":
		if definition || o.newName.set || o.restart.set || o.output.set || o.after.set || !lifecycle.ValidID(o.operation.value) {
			return o, errors.New("resume requires original --operation ID only")
		}
	case "list", "get":
		if definition || o.operation.set || o.newName.set || o.restart.set || o.preview || o.output.set || o.method == "get" && o.after.set {
			return o, errors.New("invalid standalone query options")
		}
	case "pin", "remove":
		if definition || o.output.set || o.after.set || o.preview || !lifecycle.ValidID(o.operation.value) || o.newName.set && !lifecycle.ValidID(o.newName.value) {
			return o, errors.New("pin requires --operation ID")
		}
	case "extend":
		if o.file.set || o.node.set || o.deployment.set || o.lifetime.set || o.mode.set || o.grace != 0 || o.ttl <= 0 || o.newName.set || o.restart.set || o.output.set || o.after.set || o.preview || !lifecycle.ValidID(o.operation.value) {
			return o, errors.New("extend requires NAME --ttl-seconds N --operation ID only")
		}
	case "stop", "start", "restart":
		if definition || o.newName.set || o.restart.set || o.output.set || o.after.set || o.preview == o.operation.set || o.operation.set && !lifecycle.ValidID(o.operation.value) {
			return o, errors.New("control requires --preview or --operation ID")
		}
	case "control-status":
		if definition || o.newName.set || o.restart.set || o.output.set || o.after.set || o.preview || !lifecycle.ValidID(o.operation.value) {
			return o, errors.New("control-status requires --operation ID")
		}
	case "logs", "top", "stats", "inspect":
		if definition || o.newName.set || o.restart.set || o.output.set || o.after.set || o.preview || o.operation.set {
			return o, errors.New("invalid standalone observation options")
		}
		o.container.service = "standalone"
		if err := o.container.finish(o.method, "standalone"); err != nil {
			return o, err
		}
		o.container.query.Selection = containerops.Selection{Standalone: o.name.value, Instance: o.container.instance.value}
	case "exec", "exec-status", "attach":
		if definition || o.newName.set || o.restart.set || o.output.set || o.after.set || o.preview || !lifecycle.ValidID(o.operation.value) {
			return o, errors.New("exec requires --operation ID")
		}
		if o.method == "attach" && len(rest) != 0 {
			return o, errors.New("attach takes no command")
		}
		if o.method == "exec" && o.container.execSpec().Validate() != nil {
			return o, errors.New("exec requires -- ARG [ARG ...]")
		}
	default:
		return o, errors.New("unknown standalone subcommand")
	}
	if o.method != "up" && o.method != "resume" && (o.noInput || len(o.passwordFDs.values) != 0) {
		return o, errors.New("Group input options require up or resume")
	}
	if o.restart.set && o.restart.value != "no" && o.restart.value != "on-failure" && o.restart.value != "always" || o.lifetime.set && o.lifetime.value != "temp" && o.lifetime.value != "fixed" || o.mode.set && o.mode.value != "shell" && o.mode.value != "entrypoint" || o.ttl < 0 || o.ttl > 86400 || o.grace < 0 || o.grace > 86400 {
		return o, errors.New("invalid standalone lifetime/mode/restart")
	}
	return o, nil
}
func runStandalone(ctx context.Context, args []string, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, home string, defaults cliprofile.Selection, out, diagnostic io.Writer) int {
	o, err := parseStandaloneOptions(args, io.Discard)
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	tenant, err := defaults.CheckTenant(o.tenant.value, "", false)
	if err != nil {
		return failure(diagnostic, err, 2)
	}
	if tenant == "" {
		tenant = stored.Tenant
	}
	if _, err = (cliprofile.Selection{Tenant: stored.TargetTenant}).CheckTenant(tenant, "", true); err != nil {
		return failure(diagnostic, err, 2)
	}
	if o.method == "list" || o.method == "get" {
		reply, e := c.StandalonePage(ctx, peer, stored.Session, tenant, o.name.value, o.after.value)
		if e != nil {
			return userFailure(diagnostic, e)
		}
		if o.method == "get" && len(reply.Standalones) == 1 {
			body, _, x := c.ReadAppSource(ctx, peer, stored.Session, tenant, control.AppSourceSelection{Standalone: o.name.value})
			if x != nil {
				return userFailure(diagnostic, x)
			}
			if reply.Standalones[0].Definition != nil {
				reply.Standalones[0].Definition.Body = body
			}
		}
		return userOutput(out, diagnostic, map[string]any{"standalones": reply.Standalones, "next": reply.StandaloneNext, "revision": reply.AppsRootRevision})
	}
	if containerReadMethod(o.method) || o.method == "exec" || o.method == "exec-status" || o.method == "attach" {
		co := composeOptions{method: o.method, container: o.container, standalone: &control.StandaloneDefinition{Name: o.name.value}, operation: o.operation}
		co.project.value = o.name.value
		if composeStreaming(co) || o.method == "attach" {
			return runContainerStream(ctx, co, tenant, c, peer, stored, home, out, diagnostic)
		}
		return runContainerRead(ctx, co, tenant, c, peer, stored, out, diagnostic)
	}
	if o.method == "plan" || o.method == "up" || o.method == "resume" {
		return runStandaloneUp(ctx, o, tenant, c, peer, stored, home, out, diagnostic)
	}
	if o.method == "extend" {
		return runStandaloneExtend(ctx, o, tenant, c, peer, stored, home, out, diagnostic)
	}
	if o.method == "pin" || o.method == "remove" {
		id := "standalone/" + o.method + "/" + tenant + "/" + o.operation.value
		if old, x := userauth.LoadOperation(home, c, stored.Session, id); x == nil {
			var q control.StandaloneChange
			if json.Unmarshal(old.Operation.Change.Payload, &q) != nil || old.Operation.Change.Action != "standalone-"+o.method || q.Tenant != tenant || q.Name != o.name.value || q.NewName != o.newName.value || q.Restart != o.restart.value {
				return failure(diagnostic, errors.New("operation belongs to another original change"), 2)
			}
			return standaloneMutation(ctx, c, peer, stored, home, id, old.Operation.Change.Action, old.Operation.Change.Expected, old.Operation.Epoch, q, out, diagnostic)
		} else if !errors.Is(x, userauth.ErrOperationMissing) {
			return failure(diagnostic, x, 2)
		}
		reply, e := c.StandalonePage(ctx, peer, stored.Session, tenant, o.name.value, "")
		if e != nil {
			return userFailure(diagnostic, e)
		}
		if len(reply.Standalones) != 1 {
			return failure(diagnostic, errors.New("standalone not found"), 3)
		}
		target := reply.Standalones[0].Target
		if target == ([32]byte{}) {
			return failure(diagnostic, errors.New("standalone management target unavailable"), 3)
		}
		q := control.StandaloneChange{Target: &target, Tenant: tenant, Name: o.name.value, NewName: o.newName.value, Restart: o.restart.value, Operation: o.operation.value}
		return standaloneMutation(ctx, c, peer, stored, home, "standalone/"+o.method+"/"+tenant+"/"+o.operation.value, "standalone-"+o.method, reply.Standalones[0].Metadata.Revision, max(reply.ModuleEpoch, 1), q, out, diagnostic)
	}
	return runStandaloneControl(ctx, o, tenant, c, peer, stored, home, out, diagnostic)
}
func standaloneMutation(ctx context.Context, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, home, id, action string, expected, epoch uint64, payload any, out, diagnostic io.Writer) int {
	r, e := managementMutation(ctx, c, peer, stored, home, id, action, expected, epoch, payload, false)
	code := 4
	if r != nil {
		code = 3
		if r.Code == state.Applied {
			code = 0
		}
	}
	v := map[string]any{"request": id, "result": r, "original_intent_preserved": true}
	addMutationIdentity(v, home, c, stored, id)
	if action == "standalone-extend" {
		if record, loadErr := userauth.LoadOperation(home, c, stored.Session, id); loadErr == nil {
			standaloneExtensionOutput(v, record.Operation, r)
		}
	}
	if userOutput(out, diagnostic, v) != 0 {
		return 1
	}
	if e != nil {
		return failure(diagnostic, e, 4)
	}
	return code
}
func runStandaloneControl(ctx context.Context, o standaloneOptions, tenant string, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, home string, out, diagnostic io.Writer) int {
	q := control.TaskRestartQuery{Selection: containerops.Selection{Standalone: o.name.value, Instance: o.container.instance.value}}
	if o.method == "control-status" {
		q.Operation = o.operation.value
		q.Selection.Instance = ""
		r, e := c.QueryTaskRestart(ctx, peer, stored.Session, tenant, false, q)
		if e != nil {
			return userFailure(diagnostic, e)
		}
		return userOutput(out, diagnostic, r.TaskRestartStatus)
	}
	q.Action = "standalone-" + o.method
	id := "standalone/control/" + tenant + "/" + o.operation.value
	if !o.preview {
		if old, e := userauth.LoadOperation(home, c, stored.Session, id); e == nil {
			var p control.TaskRestartChange
			if old.Operation.Change.Action != q.Action || json.Unmarshal(old.Operation.Change.Payload, &p) != nil || p.Tenant != tenant || p.Standalone != o.name.value {
				return failure(diagnostic, errors.New("operation belongs to another original target"), 2)
			}
			return standaloneMutation(ctx, c, peer, stored, home, id, q.Action, old.Operation.Change.Expected, old.Operation.Epoch, p, out, diagnostic)
		} else if !errors.Is(e, userauth.ErrOperationMissing) {
			return failure(diagnostic, e, 2)
		}
	}
	r, e := c.QueryTaskRestart(ctx, peer, stored.Session, tenant, true, q)
	if e != nil {
		return userFailure(diagnostic, e)
	}
	if o.preview {
		return userOutput(out, diagnostic, r.TaskRestartPlan)
	}
	p := r.TaskRestartPlan
	change := control.TaskRestartChange{Tenant: tenant, Standalone: o.name.value, Operation: o.operation.value, Target: p.Target, ManagementTarget: p.ManagementTarget}
	change.Selection.Service = p.Container.Service
	change.Selection.Instance = p.Container.Instance
	return standaloneMutation(ctx, c, peer, stored, home, id, q.Action, p.StandaloneRevision, max(r.ModuleEpoch, 1), change, out, diagnostic)
}
func runStandaloneUp(ctx context.Context, o standaloneOptions, tenant string, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, home string, out, diagnostic io.Writer) int {
	id := o.operation.value
	intent, e := userauth.LoadCompose(home, c, stored.Session, id)
	if e == nil {
		if intent.Standalone == nil || intent.Standalone.Name != o.name.value || intent.Scope.Tenant != tenant {
			return failure(diagnostic, errors.New("operation belongs to another original workload"), 2)
		}
		if o.method != "resume" {
			r, x := c.AppOperation(ctx, peer, stored.Session, tenant, control.AppOperationRequest{Standalone: o.name.value, ID: id})
			if x != nil {
				return userFailure(diagnostic, x)
			}
			return userOutput(out, diagnostic, r.AppOperation)
		}
	} else if !errors.Is(e, userauth.ErrOperationMissing) && o.method != "plan" {
		return failure(diagnostic, e, 2)
	}
	if errors.Is(e, userauth.ErrOperationMissing) || o.method == "plan" {
		if o.method == "resume" {
			return failure(diagnostic, e, 2)
		}
		definition := control.StandaloneDefinition{Name: o.name.value, Lifetime: o.lifetime.value, Mode: o.mode.value, Restart: o.restart.value, TTLSeconds: o.ttl, GraceSeconds: o.grace}
		co := composeOptions{standalone: &definition, method: o.method, file: o.file, node: o.node, deployment: o.deployment, operation: o.operation}
		co.project.value = o.name.value
		var artifact []byte
		var x error
		if o.method == "plan" {
			var raw []byte
			raw, x = composeDocument(co.file.value)
			if x == nil {
				artifact, x = fetchComposePlan(ctx, c, peer, stored, tenant, co, raw)
			}
		} else {
			artifact, x = prepareComposeArtifact(ctx, co, tenant, home, c, peer, stored)
		}
		if x != nil {
			return composeSourceFailure(out, diagnostic, x)
		}
		plan, x := deployment.DecodeBlueprint(artifact)
		if x != nil || plan.CheckStandaloneInput() != nil {
			return failure(diagnostic, deployment.ErrInputs, 2)
		}
		if o.method == "plan" {
			if o.output.set {
				if x = saveComposePlan(o.output.value, artifact); x != nil {
					return failure(diagnostic, x, 1)
				}
			}
			return userOutput(out, diagnostic, json.RawMessage(artifact))
		}
		existing, x := c.StandalonePage(ctx, peer, stored.Session, tenant, o.name.value, "")
		if x != nil {
			return userFailure(diagnostic, x)
		}
		expected := uint64(0)
		target := control.AppCreateTarget(c.Cluster, tenant, plan.Scope().App, plan.Scope().Deployment)
		if len(existing.Standalones) == 1 {
			expected = existing.Standalones[0].Workload.Revision
			target = existing.Standalones[0].Target
			if target == ([32]byte{}) || expected == 0 {
				return failure(diagnostic, errors.New("current standalone management target unavailable"), 2)
			}
		} else if len(existing.Standalones) != 0 {
			return failure(diagnostic, userauth.ErrPrivateState, 2)
		}
		window, x := c.Whoami(ctx, peer, stored.Session)
		if x != nil {
			return userFailure(diagnostic, x)
		}
		intent, x = userauth.StageStandaloneTarget(home, c, stored.Session, id, artifact, expected, max(1, window.ModuleEpoch), definition, target)
		if x != nil {
			return failure(diagnostic, x, 2)
		}
	}
	if intent.Standalone == nil {
		return failure(diagnostic, userauth.ErrPrivateState, 2)
	}
	phase := func(name, action string, expected uint64, payload any) int {
		request := "standalone/" + intent.ID + "/" + name
		var before []func(control.UserOperation) error
		if name == "accept" {
			co := composeOptions{standalone: intent.Standalone, passwordFDs: o.passwordFDs, noInput: o.noInput}
			before = append(before, func(origin control.UserOperation) error {
				return ensureComposeApprovals(ctx, co, intent, origin, tenant, home, c, peer, stored, diagnostic)
			})
		}
		r, x := managementMutation(ctx, c, peer, stored, home, request, action, expected, intent.Epoch, payload, o.method == "resume", before...)
		if x != nil {
			return failure(diagnostic, x, 4)
		}
		if r == nil {
			return failure(diagnostic, errors.New("original result unknown"), 4)
		}
		if r.Code != state.Applied {
			if userOutput(out, diagnostic, r) != 0 {
				return 1
			}
			return 3
		}
		return 0
	}
	if code := phase("upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: tenant, App: intent.Scope.App, Deployment: intent.Scope.Deployment, ID: intent.ID, Length: intent.Length, Digest: intent.Digest}); code != 0 {
		return code
	}
	for index, start := 0, 0; start < intent.Length; index, start = index+1, start+deployment.ArtifactPartBytes {
		if code := phase(fmt.Sprintf("part-%03d", index), "put-app-part", uint64(index+1), control.AppUploadPart{Tenant: tenant, ID: intent.ID, Index: index, Data: intent.Artifact[start:min(intent.Length, start+deployment.ArtifactPartBytes)]}); code != 0 {
			return code
		}
	}
	begin := control.AppBegin{Standalone: intent.Standalone, Target: intent.Target, Tenant: tenant, App: intent.Scope.App, Deployment: intent.Scope.Deployment, Upload: intent.ID, Operation: intent.ID}
	if blueprint, x := deployment.DecodeBlueprint(intent.Artifact); x == nil {
		begin.DefaultNode = blueprint.CDDefaultNode()
	}
	if code := phase("accept", "standalone-up", intent.Expected, begin); code != 0 {
		return code
	}
	r, x := c.AppOperation(ctx, peer, stored.Session, tenant, control.AppOperationRequest{Standalone: o.name.value, ID: intent.ID})
	if x != nil {
		return userFailure(diagnostic, x)
	}
	return userOutput(out, diagnostic, r.AppOperation)
}
