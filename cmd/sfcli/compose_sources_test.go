// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"gopkg.in/yaml.v3"
)

func TestComposeSourceOptionsKeepPlanReadOnlyAndResumeExplicit(t *testing.T) {
	for _, args := range [][]string{
		{"plan", "--source-operation", "original"},
		{"diff", "--source-operation", "original", "--tenant", "tenant"},
		{"resume", "--operation", "original", "--retry-source"},
	} {
		if _, err := parseComposeOptions(args, io.Discard); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{
		{"plan", "--source-operation", "original", "-f", "changed.yaml"},
		{"diff", "--source-operation", "original", "--node", "other"},
		{"up", "--operation", "original", "--source-operation", "other"},
		{"up", "--operation", "original", "--retry-source"},
		{"status", "-p", "app", "--retry-source"},
		{"plan", "--source-operation", ""},
	} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("ambiguous source command", args)
		}
	}
}

// Called inside the actual Runtime/DB/User-SFCP fixture after its module ZIP
// was cached. This exercises source staging and current authenticated recovery,
// not live app planning/acceptance, Yaegi, a compiler or a native lifecycle run.
func testActualComposeSourcePreparation(t *testing.T, ctx context.Context, home string, c userauth.Client, peer sfcp.Peer, stored userauth.Stored, pin checker.ModulePin, invoke func(int, ...string) string) {
	t.Helper()
	doc := deployment.Compose{Name: "inline-source-demo", Sfc: deployment.AppExtension{Schema: 1, Tenant: "tenant", Deployment: "inline-source-demo",
		Lifecycle: &deployment.LifecycleDeclaration{Scripts: map[string]checker.Script{"inline": {Source: "package checker\n// compose source original\n", Modules: []checker.ModulePin{pin}}}}},
		Services: map[string]deployment.ComposeService{"web": {Image: "docker.io/library/php@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Sfc: deployment.ServiceExtension{Lifecycle: &deployment.ServiceLifecycle{Checks: []deployment.LifecycleCheck{{ID: "custom", Phase: "readiness", LifecycleTemplate: deployment.LifecycleTemplate{Script: "inline"}}}}}}}}
	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := userauth.StageComposeSources(home, c, stored.Session, "inline-sources", "tenant", "", "", "", peer, raw)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := advanceComposeSources(ctx, home, c, stored, parent, true, false)
	if err != nil || len(facts) != 1 || facts["inline"].Verify() != nil {
		t.Fatal("actual source staging/module cache recovery", err)
	}
	child, err := userauth.LoadCheckerScript(home, c, stored.Session, parent.SourceID("inline"))
	if err != nil || child.Sequence != 1 || child.Fact == nil || child.ModuleProgress[pin.Path].Fact == nil || child.ModuleProgress[pin.Path].Sequence != 0 {
		t.Fatal("source/retained module fact progress", err)
	}
	readOnly, err := metadataComposeSources(home, c, stored, parent)
	if err != nil || readOnly["inline"].ContentDigest() != facts["inline"].ContentDigest() {
		t.Fatal("read-only source metadata", err)
	}
	output := invoke(4, "compose", "up", "--operation", parent.ID, "--tenant", "tenant", "-f", "/missing-original-must-not-be-reopened.yaml")
	if !bytes.Contains([]byte(output), []byte("source-stored")) {
		t.Fatal("ordinary repeated up advanced or lost preparation")
	}
	after, err := userauth.LoadCheckerScript(home, c, stored.Session, child.ID)
	if err != nil || after.Sequence != child.Sequence || !bytes.Equal(after.Signature, child.Signature) || after.Fact.ContentDigest() != child.Fact.ContentDigest() {
		t.Fatal("repeat source preparation changed original", err)
	}
	if metadata, err := userauth.LoadCompose(home, c, stored.Session, parent.ID); !errors.Is(err, userauth.ErrOperationMissing) || len(metadata.Artifact) != 0 {
		t.Fatal("source staging was mislabeled as app acceptance", err)
	}
}
