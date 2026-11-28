// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

func fetchComposePlan(ctx context.Context, c userauth.Client, target sfcp.Peer, stored userauth.Stored, tenant string, o composeOptions, raw []byte) ([]byte, error) {
	return fetchComposePlanSources(ctx, c, target, stored, tenant, o, raw, nil)
}

func fetchComposePlanSources(ctx context.Context, c userauth.Client, target sfcp.Peer, stored userauth.Stored, tenant string, o composeOptions, raw []byte, facts map[string]checker.SourceFact) ([]byte, error) {
	parse := deployment.ParseApp
	if o.standalone != nil {
		parse = deployment.ParseStandalone
	}
	document, err := parse(raw)
	if err != nil {
		return nil, err
	}
	if _, err := (cliprofile.Selection{Tenant: tenant}).CheckTenant("", document.Sfc.Tenant, true); err != nil {
		return nil, err
	}
	request := control.AppPlanRequest{Standalone: o.standalone, Document: raw, Project: o.project.value, Deployment: o.deployment.value, Node: o.node.value, Diff: o.method == "diff", Force: o.force}
	request.CheckerSources = facts
	artifact, err := c.StreamAppPlan(ctx, target, stored.Session, tenant, request)
	if err != nil {
		return nil, err
	}
	if request.Diff {
		if d, err := control.DecodeAppDiff(artifact); err != nil || d.Tenant != tenant {
			return nil, errors.New("invalid app diff")
		}
	} else {
		if _, err := deployment.DecodeBlueprint(artifact); err != nil {
			return nil, err
		}
	}
	return artifact, nil
}

func composeInventory(ctx context.Context, c userauth.Client, target sfcp.Peer, stored userauth.Stored, tenant, app string) (control.AppView, bool, error) {
	var found control.AppView
	exists := false
	cursor := ""
	var revision, catalogRevision uint64
	for {
		page, err := c.AppPage(ctx, target, stored.Session, tenant, cursor)
		if err != nil {
			return found, false, err
		}
		if cursor == "" {
			revision, catalogRevision = page.AppsRootRevision, page.RootRevision
		} else if revision != page.AppsRootRevision || catalogRevision != page.RootRevision {
			return found, false, errors.New("app inventory or authority changed between pages")
		}
		for _, row := range page.Apps {
			if row.Tenant != tenant {
				return found, false, errors.New("app inventory scope mismatch")
			}
			if row.App == app {
				if exists {
					return found, false, errors.New("duplicate app inventory")
				}
				found, exists = row, true
			}
		}
		if page.AppsNext == "" {
			return found, exists, nil
		}
		if page.AppsNext <= cursor {
			return found, false, errors.New("invalid app inventory cursor")
		}
		cursor = page.AppsNext
	}
}

func runComposeUp(ctx context.Context, o composeOptions, tenant, home string, c userauth.Client, target sfcp.Peer, stored userauth.Stored, out, diagnostic io.Writer) int {
	intent, err := userauth.LoadCompose(home, c, stored.Session, o.operation.value)
	if err == nil && o.retrySource.set {
		return failure(diagnostic, errors.New("source preparation already completed; retry-source cannot replay an app operation"), 2)
	}
	if errors.Is(err, userauth.ErrOperationMissing) && o.method == "resume" {
		if _, sourceErr := userauth.LoadComposeSources(home, c, stored.Session, o.operation.value); errors.Is(sourceErr, userauth.ErrOperationMissing) {
			return runComposeDown(ctx, o, tenant, home, c, target, stored, out, diagnostic)
		} else if sourceErr != nil {
			return failure(diagnostic, sourceErr, 1)
		}
	}
	if errors.Is(err, userauth.ErrOperationMissing) && (o.method == "up" || o.method == "resume") {
		if _, old := userauth.LoadOperation(home, c, stored.Session, "compose-down/"+o.operation.value); old == nil {
			return failure(diagnostic, errors.New("operation ID already belongs to an original down request"), 2)
		} else if !errors.Is(old, userauth.ErrOperationMissing) {
			return failure(diagnostic, old, 1)
		}
		var artifact []byte
		if o.plan.set {
			if _, sourceErr := userauth.LoadComposeSources(home, c, stored.Session, o.operation.value); sourceErr == nil {
				return failure(diagnostic, errors.New("operation already has original source input; continue it with 'sfcli op resume ID'"), 2)
			} else if !errors.Is(sourceErr, userauth.ErrOperationMissing) {
				return failure(diagnostic, sourceErr, 1)
			}
			artifact, err = composeDocument(o.plan.value)
			if err == nil {
				var plan deployment.Blueprint
				plan, err = deployment.DecodeBlueprint(bytes.TrimSpace(artifact))
				if err == nil {
					artifact, err = plan.Encode()
				}
			}
		} else {
			artifact, err = prepareComposeArtifact(ctx, o, tenant, home, c, target, stored)
		}
		if err != nil {
			var pending *composeSourceWait
			if errors.As(err, &pending) {
				return composeSourceFailure(out, diagnostic, err)
			}
			return failure(diagnostic, err, 2)
		}
		plan, err := deployment.DecodeBlueprint(artifact)
		if err != nil {
			return failure(diagnostic, err, 2)
		}
		if err := plan.CheckAppInput(); err != nil {
			return failure(diagnostic, err, 2)
		}
		if plan.Scope().Tenant != tenant || plan.Scope().Cluster != c.Cluster || plan.Scope().Actor != stored.Session.User {
			return failure(diagnostic, errors.New("plan scope does not match current cluster/user/tenant"), 2)
		}
		current, exists, err := composeInventory(ctx, c, target, stored, tenant, plan.Scope().App)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		window, err := c.Whoami(ctx, target, stored.Session)
		if err != nil {
			return userFailure(diagnostic, err)
		}
		if !exists {
			createTarget := control.AppCreateTarget(c.Cluster, tenant, plan.Scope().App, plan.Scope().Deployment)
			intent, err = userauth.StageComposeTarget(home, c, stored.Session, o.operation.value, artifact, 0, max(1, window.ModuleEpoch), createTarget)
		} else if current.BeginTarget != nil && current.Revision > 0 {
			intent, err = userauth.StageComposeTarget(home, c, stored.Session, o.operation.value, artifact, current.Revision, max(1, window.ModuleEpoch), *current.BeginTarget)
		} else {
			intent, err = userauth.StageCompose(home, c, stored.Session, o.operation.value, artifact, current.Revision, max(1, window.ModuleEpoch))
		}
	}
	if err != nil {
		return failure(diagnostic, err, 1)
	}
	if intent.Standalone != nil {
		return failure(diagnostic, errors.New("operation belongs to standalone; use its original standalone command"), 2)
	}
	if intent.Move != nil {
		return failure(diagnostic, errors.New("operation ID belongs to an explicit Volume move; use volume move-resume"), 2)
	}
	if intent.Scope.Tenant != tenant {
		return failure(diagnostic, errors.New("original compose intent belongs to another tenant"), 2)
	}
	exact, err := c.AppOperation(ctx, target, stored.Session, tenant, control.AppOperationRequest{App: intent.Scope.App, ID: intent.ID})
	if err != nil {
		return userFailure(diagnostic, err)
	}
	// A previously accepted historical operation is result-only. In particular,
	// do not request new Group passwords or approvals for an already retired app.
	accepted, loadErr := userauth.LoadOperation(home, c, stored.Session, "compose/"+intent.ID+"/accept")
	if exact.AppOperation.Found && (errors.Is(loadErr, userauth.ErrOperationMissing) || exact.AppOperation.Operation.Plan != intent.Digest || exact.AppOperation.Operation.Epoch != intent.Epoch) {
		return failure(diagnostic, errors.New("shared original exists without matching local accept intent; check it with 'sfcli op show ID', do not create a replacement"), 4)
	}
	if loadErr == nil && accepted.Result == nil && exact.AppOperation.Found && !exact.AppOperation.Current {
		// The original accept reply may have been lost before local sync. Query
		// that signed command; historical execution never needs a fresh approval.
		reply, err := c.Result(ctx, target, stored.Session, accepted.Operation)
		if err != nil || !reply.Found || reply.Result == nil || reply.Result.Code != state.Applied {
			return failure(diagnostic, errors.New("original accept result is unconfirmed; preserve original intent without resubmission"), 4)
		}
		if err := userauth.RecordOperationResult(home, c, stored.Session, accepted.Operation, *reply.Result); err != nil {
			return failure(diagnostic, err, 4)
		}
		accepted.Result = reply.Result
	}
	if loadErr == nil && accepted.Result != nil && accepted.Result.Code == state.Applied {
		if !exact.AppOperation.Current {
			return composeOriginalResult(intent, exact.AppOperation, home, c, stored, out, diagnostic)
		}
	} else if loadErr != nil && !errors.Is(loadErr, userauth.ErrOperationMissing) {
		return failure(diagnostic, loadErr, 4)
	}
	phase := func(name, action string, expected uint64, payload any) int {
		id := "compose/" + intent.ID + "/" + name
		var before []func(control.UserOperation) error
		if name == "accept" {
			before = append(before, func(origin control.UserOperation) error {
				return ensureComposeApprovals(ctx, o, intent, origin, tenant, home, c, target, stored, diagnostic)
			})
		}
		result, err := managementMutation(ctx, c, target, stored, home, id, action, expected, intent.Epoch, payload, o.method == "resume", before...)
		status, code := "unknown", 4
		var approval *composeApprovalFailure
		if errors.As(err, &approval) {
			code, status = approval.code, "approval-required"
		}
		if err == nil && result != nil {
			status, code = "applied", 0
			if result.Code != state.Applied {
				status, code = "rejected", 3
			}
		}
		if code != 0 {
			output := map[string]any{"schema": 1, "operation": intent.ID, "tenant": tenant, "app": intent.Scope.App, "phase": name, "request": id, "status": status, "result": result, "local_intent_preserved": true}
			addMutationIdentity(output, home, c, stored, id)
			if userOutput(out, diagnostic, output) != 0 {
				return 1
			}
			if err != nil {
				_ = failure(diagnostic, err, code)
			}
		}
		return code
	}
	if code := phase("upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: tenant, App: intent.Scope.App, Deployment: intent.Scope.Deployment, ID: intent.ID, Length: intent.Length, Digest: intent.Digest}); code != 0 {
		return code
	}
	parts := (intent.Length + deployment.ArtifactPartBytes - 1) / deployment.ArtifactPartBytes
	for index := 0; index < parts; index++ {
		start := index * deployment.ArtifactPartBytes
		if code := phase(fmt.Sprintf("part-%03d", index), "put-app-part", uint64(index+1), control.AppUploadPart{Tenant: tenant, ID: intent.ID, Index: index, Data: intent.Artifact[start:min(intent.Length, start+deployment.ArtifactPartBytes)]}); code != 0 {
			return code
		}
	}
	begin := control.AppBegin{Target: intent.Target, Tenant: tenant, App: intent.Scope.App, Deployment: intent.Scope.Deployment, Upload: intent.ID, Operation: intent.ID, DisableCD: o.disableCD}
	if plan, err := deployment.DecodeBlueprint(intent.Artifact); err == nil {
		if policy, enabled := plan.DeliveryPolicy(); enabled {
			begin.Prune, begin.DefaultNode = policy.Sync.Prune, plan.CDDefaultNode()
		}
	}
	if code := phase("accept", "begin-app", intent.Expected, begin); code != 0 {
		return code
	}
	current, found, err := composeInventory(ctx, c, target, stored, tenant, intent.Scope.App)
	if err != nil {
		return userFailure(diagnostic, err)
	}
	// An app that follows Git took only the file's x-sfc.cd policy; there is
	// no new execution to follow.
	if plan, decodeErr := deployment.DecodeBlueprint(intent.Artifact); decodeErr == nil && (!found || current.Operation.ID != intent.ID) {
		if policy, enabled := plan.DeliveryPolicy(); enabled {
			if cd, cdErr := composeCDPolicy(ctx, c, target, stored, tenant, intent.Scope.App); cdErr == nil && cd != nil && reflect.DeepEqual(cd.Policy, policy) {
				return userOutput(out, diagnostic, map[string]any{"schema": 1, "operation": intent.ID, "tenant": tenant, "app": intent.Scope.App, "status": "cd-policy-changed", "policy_revision": cd.PolicyRevision})
			}
		}
	}
	if !found || current.Operation.ID != intent.ID || current.Retirement != nil && current.Retirement.Status == "Retired" {
		reply, err := c.AppOperation(ctx, target, stored.Session, tenant, control.AppOperationRequest{App: intent.Scope.App, ID: intent.ID})
		if err != nil {
			return userFailure(diagnostic, err)
		}
		return composeOriginalResult(intent, reply.AppOperation, home, c, stored, out, diagnostic)
	}
	return userOutput(out, diagnostic, map[string]any{"schema": 1, "operation": intent.ID, "tenant": tenant, "app": intent.Scope.App, "status": "accepted", "observed": current, "local_intent_preserved": true})
}

// composeCDPolicy is the app's CD view from the app list (nil without CD).
func composeCDPolicy(ctx context.Context, c userauth.Client, target sfcp.Peer, stored userauth.Stored, tenant, app string) (*control.AppCDView, error) {
	after := ""
	for range 4096 {
		page, err := c.AppPage(ctx, target, stored.Session, tenant, after)
		if err != nil {
			return nil, err
		}
		for _, row := range page.Apps {
			if row.Tenant == tenant && row.App == app {
				return row.CD, nil
			}
		}
		if page.AppsNext == "" || page.AppsNext <= after {
			break
		}
		after = page.AppsNext
	}
	return nil, nil
}

func composeOriginalResult(intent userauth.ComposeIntent, operation *control.AppOperationView, home string, c userauth.Client, stored userauth.Stored, out, diagnostic io.Writer) int {
	if operation == nil || !operation.Found || operation.Operation == nil {
		return failure(diagnostic, errors.New("original accepted operation is unavailable; intent and receipts retained, outcome remains unknown"), 4)
	}
	accept, err := userauth.LoadOperation(home, c, stored.Session, "compose/"+intent.ID+"/accept")
	if err != nil {
		return failure(diagnostic, err, 4)
	}
	command, err := accept.Operation.Command()
	if err != nil || operation.Tenant != intent.Scope.Tenant || operation.App != intent.Scope.App || operation.ID != intent.ID || operation.Operation.ID != intent.ID || operation.Deployment != intent.Scope.Deployment || operation.Operation.Plan != intent.Digest || operation.Operation.Epoch != intent.Epoch || operation.Operation.Submitter != command.Actor || accept.Result == nil || accept.Result.Code != state.Applied {
		return failure(diagnostic, errors.New("original operation does not match frozen intent/accept receipt"), 4)
	}
	return userOutput(out, diagnostic, map[string]any{"schema": 1, "operation": intent.ID, "tenant": intent.Scope.Tenant, "app": intent.Scope.App, "status": "original-result", "original": operation, "local_intent_preserved": true})
}
