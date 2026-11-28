// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

type composeSourceWait struct {
	operation, alias, request, module, status string
	cause                                     error
}

func (e *composeSourceWait) Error() string {
	if e.cause != nil {
		return "original compose source preparation awaits explicit resume: " + e.cause.Error()
	}
	return "original compose source preparation awaits explicit resume"
}
func (e *composeSourceWait) Unwrap() error { return e.cause }

func composeSourceFailure(out, diagnostic io.Writer, err error) int {
	var pending *composeSourceWait
	if !errors.As(err, &pending) {
		return failure(diagnostic, err, 1)
	}
	if code := userOutput(out, diagnostic, map[string]any{"schema": 1, "operation": pending.operation, "status": pending.status,
		"source_alias": pending.alias, "source_request": pending.request, "module": pending.module, "original_intent_preserved": true}); code != 0 {
		return code
	}
	return failure(diagnostic, err, 4)
}

func sourceComposeOptions(o composeOptions, p userauth.ComposeSourcePreparation) composeOptions {
	o.standalone = p.Standalone
	o.project.value, o.deployment.value, o.node.value = p.Project, p.Deployment, p.Node
	return o
}

func composeSourceOptionsMatch(o composeOptions, p userauth.ComposeSourcePreparation, tenant string) bool {
	return sameCLIDefinition(o.standalone, p.Standalone) && tenant == p.Tenant && !o.plan.set && (!o.project.set || o.project.value == p.Project) && (!o.deployment.set || o.deployment.value == p.Deployment) && (!o.node.set || o.node.value == p.Node)
}

// metadataComposeSources reads retained local facts only. It never sends bytes,
// recovers remote caches, creates child intents or registers a named script.
func metadataComposeSources(home string, c userauth.Client, stored userauth.Stored, parent userauth.ComposeSourcePreparation) (map[string]checker.SourceFact, error) {
	facts := map[string]checker.SourceFact{}
	for _, alias := range parent.Aliases() {
		child, err := userauth.LoadCheckerScript(home, c, stored.Session, parent.SourceID(alias))
		if err != nil || !userauth.ComposeCheckerSourceMatches(parent, alias, child) {
			return nil, &composeSourceWait{operation: parent.ID, alias: alias, request: parent.SourceID(alias), status: "source-prepared", cause: err}
		}
		if child.Fact == nil {
			return nil, &composeSourceWait{operation: parent.ID, alias: alias, request: child.ID, status: "source-unknown"}
		}
		facts[alias] = child.Fact.Clone()
	}
	return facts, nil
}

func advanceComposeSources(ctx context.Context, home string, c userauth.Client, stored userauth.Stored, parent userauth.ComposeSourcePreparation, proceed, retry bool) (map[string]checker.SourceFact, error) {
	facts := map[string]checker.SourceFact{}
	for _, alias := range parent.Aliases() {
		wait := func(status, module string, err error) error {
			return &composeSourceWait{operation: parent.ID, alias: alias, request: parent.SourceID(alias), module: module, status: status, cause: err}
		}
		child, err := userauth.LoadCheckerScript(home, c, stored.Session, parent.SourceID(alias))
		if errors.Is(err, userauth.ErrOperationMissing) && proceed {
			child, err = userauth.StageComposeCheckerSource(home, c, stored.Session, parent, alias)
		}
		if err != nil {
			return nil, wait("source-prepared", "", err)
		}
		if !userauth.ComposeCheckerSourceMatches(parent, alias, child) {
			return nil, wait("source-unknown", "", userauth.ErrPrivateState)
		}
		child, status, err := advanceCheckerSource(ctx, c, stored.Session, home, child, proceed, retry)
		if err != nil || child.Fact == nil {
			return nil, wait(status, "", err)
		}
		for _, pin := range child.Descriptor.Modules {
			progress := child.ModuleProgress[pin.Path]
			if progress.Fact != nil {
				continue
			}
			provider, err := userauth.CheckerProviderPeer(c, child.Provider)
			if err != nil {
				return nil, wait("module-unknown", pin.Path, err)
			}
			fact, err := c.WithCheckerUpload(child).RecoverCheckerModule(ctx, provider, stored.Session, child.Descriptor, pin)
			if err != nil {
				status := "module-unknown"
				if progress.Sequence == 0 && positiveSourceMissing(err) {
					status = "module-prepared"
				}
				return nil, wait(status, pin.Path, err)
			}
			progress.Fact = &fact
			child, err = userauth.ReplaceCheckerModule(home, c, stored.Session, child, pin.Path, progress)
			if err != nil {
				return nil, wait("module-unknown", pin.Path, err)
			}
		}
		facts[alias] = child.Fact.Clone()
	}
	return facts, nil
}

// prepareComposeArtifact loads original source preparation before opening any
// supplied file. Ordinary repeated up observes it; only fresh up/resume sends.
func prepareComposeArtifact(ctx context.Context, o composeOptions, tenant, home string, c userauth.Client, target sfcp.Peer, stored userauth.Stored) ([]byte, error) {
	parent, err := userauth.LoadComposeSources(home, c, stored.Session, o.operation.value)
	fresh := false
	if errors.Is(err, userauth.ErrOperationMissing) {
		if o.method == "resume" {
			return nil, err
		}
		raw, err := composeDocument(o.file.value)
		if err != nil {
			return nil, err
		}
		parse := deployment.ParseApp
		if o.standalone != nil {
			parse = deployment.ParseStandalone
		}
		doc, err := parse(raw)
		if err != nil {
			return nil, err
		}
		program, _, err := doc.LifecycleProgram()
		if err != nil {
			return nil, err
		}
		inline := 0
		for _, script := range program.Scripts {
			if script.Ref == nil {
				inline++
			}
		}
		if inline == 0 {
			return fetchComposePlan(ctx, c, target, stored, tenant, o, raw)
		}
		// No persistent source work or bytes are sent until the live adapter
		// advertises lifecycle and verifies the CURRENT provider permissions.
		provider := [32]byte(target.Key)
		preflight, err := c.StreamAppPlan(ctx, target, stored.Session, tenant, control.AppPlanRequest{Standalone: o.standalone, Document: raw,
			Project: o.project.value, Deployment: o.deployment.value, Node: o.node.value, PrepareSources: true, SourceProvider: &provider, Force: o.force})
		if err != nil {
			return nil, err
		}
		requirements, err := control.DecodeAppSourcePlan(preflight)
		if err != nil || requirements.Check(raw, c.Cluster, stored.Session.User, tenant) != nil {
			return nil, userauth.ErrPrivateState
		}
		parent, err = userauth.StageComposeSources(home, c, stored.Session, o.operation.value, tenant, o.project.value, o.deployment.value, o.node.value, target, raw, o.standalone)
		if err != nil {
			return nil, err
		}
		fresh = true
	} else if err != nil {
		return nil, err
	}
	if !composeSourceOptionsMatch(o, parent, tenant) {
		return nil, errors.New("compose options differ from original source preparation")
	}
	facts, err := advanceComposeSources(ctx, home, c, stored, parent, fresh || o.method == "resume", o.retrySource.value)
	if err != nil {
		return nil, err
	}
	if !fresh && o.method != "resume" {
		return nil, &composeSourceWait{operation: parent.ID, status: "source-stored"}
	}
	return fetchComposePlanSources(ctx, c, target, stored, tenant, sourceComposeOptions(o, parent), parent.Document, facts)
}

func sameCLIDefinition(a, b *control.StandaloneDefinition) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
