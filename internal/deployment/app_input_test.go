// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func appInputDocument() string {
	return "name: php-mysql\nx-sfc: {}\nservices:\n  web:\n    image: docker.io/library/php@sha256:" + strings.Repeat("a", 64) + "\n    command: []\n    environment: {MODE: app}\n    networks: {app: {ipv4_address: 10.240.10.10}}\n    x-sfc: {node: node-a}\nnetworks:\n  app: {name: shared-lan}\n"
}

func TestAppInputSeparatesManagementBeforeNormalization(t *testing.T) {
	raw := appInputDocument()
	c, err := ParseApp([]byte(raw))
	if err != nil || !c.Networks["app"].External || c.Networks["app"].Name != "shared-lan" {
		t.Fatal("named app reference", err)
	}
	if c.Services["web"].Command == nil || len(*c.Services["web"].Command) != 0 || c.Services["web"].Environment["MODE"] != "app" {
		t.Fatal("container process changed")
	}
	for _, field := range []string{"nodes: {}", "nodes: null", "vault: {}", "vault: null", "routing: {}", "registries: []"} {
		t.Run(field, func(t *testing.T) {
			bad := strings.Replace(raw, "x-sfc: {}", "x-sfc: {"+field+"}", 1)
			_, err := ParseApp([]byte(bad))
			if err == nil || !strings.Contains(err.Error(), "CLUSTER_SETTING_IN_APP") {
				t.Fatal("management field not rejected before normalization", err)
			}
		})
	}
	for _, field := range []string{"driver: bridge", "driver: ''", "x-sfc: {}", "x-sfc: null", "external: false", "external: null"} {
		t.Run(field, func(t *testing.T) {
			bad := strings.Replace(raw, "name: shared-lan}", "name: shared-lan, "+field+"}", 1)
			if _, err := ParseApp([]byte(bad)); err == nil {
				t.Fatal("management network field accepted")
			}
		})
	}
	legacy := smallCompose(t)
	old, err := yaml.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseCompose(old); err != nil {
		t.Fatal("old artifact decoder removed", err)
	}
	if _, err = ParseApp(old); err == nil {
		t.Fatal("old inline network accepted as new app")
	}
	if err = legacy.ValidateApp(); err == nil {
		t.Fatal("in-memory bypass")
	}
}

func TestAppInputCompilesCurrentNamedSourceAndPreservesFrozenLegacy(t *testing.T) {
	f, c, ctx, source := externalFixture(t)
	old, err := Compile(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldRaw, err := old.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(oldRaw, []byte("InputKind")) {
		t.Fatal("legacy schema1 bytes gained a marker")
	}
	ctx.ExternalNetworks = nil
	before := ctx.Current[source]
	networks, _ := ctx.Networks.Encode()
	b, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.CheckAppInput(); err != nil {
		t.Fatal(err)
	}
	for _, s := range b.Steps() {
		if s.Kind == "bridge" || s.Kind == "tunnel" || s.Kind == "dns" {
			t.Fatal("app created managed infrastructure", s.Kind)
		}
		if s.Kind == "network-ref" {
			var ref NetworkReference
			if json.Unmarshal(s.Goal, &ref) != nil || ref.Source.Key != source || ref.Source.Generation != 17 || !ref.RetainSource {
				t.Fatal("original source not fixed")
			}
		}
	}
	after, _ := ctx.Networks.Encode()
	if !bytes.Equal(networks, after) || ctx.Current[source] != before {
		t.Fatal("planning mutated source")
	}
	raw, _ := b.Encode()
	decoded, err := DecodeBlueprint(raw)
	if err != nil || decoded.ValidateCurrent(f.c, ctx) != nil {
		t.Fatal("new artifact current validation", err)
	}
	if old.CheckAppInput() == nil {
		t.Fatal("old artifact admitted as new")
	}
	restored, err := DecodeBlueprint(oldRaw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := restored.Encode()
	if !bytes.Equal(oldRaw, again) {
		t.Fatal("frozen old plan changed")
	}
	for _, s := range b.ReleaseOrder() {
		if s.Key == source {
			t.Fatal("release deletes borrowed source")
		}
	}
	ctx.Current[ResourceKey("bridge", "tenant", "duplicate", "lan/node-a")] = before
	if _, err = CompileApp(c, f.c, ctx); err == nil {
		t.Fatal("ambiguous current source accepted")
	}
	delete(ctx.Current, ResourceKey("bridge", "tenant", "duplicate", "lan/node-a"))
	v := ctx.Current[source]
	v.Revision++
	ctx.Current[source] = v
	if decoded.ValidateCurrent(f.c, ctx) == nil {
		t.Fatal("stale immutable source admitted")
	}
	delete(ctx.Current, source)
	if _, err = CompileApp(c, f.c, ctx); err == nil {
		t.Fatal("missing source implicitly created")
	}
	// A correct marker/input cannot authorize a graph that creates a bridge.
	// Decoding proves representation; current recompiling proves authority.
	f2, c2, ctx2, _ := externalFixture(t)
	// Keep the same service/task metadata. A two-service management input
	// replaced with the one-service app input is already structurally invalid
	// and cannot exercise the separate graph/current-authority rejection.
	management := c2
	management.Networks = smallCompose(t).Networks
	inline, err := Compile(management, f2.c, contextFor(t, f2))
	if err != nil {
		t.Fatal(err)
	}
	inline.d.InputKind = "app"
	c2.Sfc.Tenant, c2.Sfc.Deployment = inline.d.Tenant, inline.d.Deployment
	inline.d.Input = c2
	inlineRaw, err := inline.Encode()
	if err != nil {
		t.Fatal("fixture task metadata must remain structurally valid", err)
	}
	injected, err := DecodeBlueprint(inlineRaw)
	if err != nil {
		t.Fatal("fixture must reach semantic validation", err)
	}
	if injected.ValidateCurrent(f2.c, ctx2) == nil {
		t.Fatal("management graph with app marker accepted")
	}
	// A caller cannot relabel an old management artifact into an app contract.
	forged := old.d
	forged.InputKind = "app"
	forged.Input = smallCompose(t)
	forgedRaw, _ := json.Marshal(forged)
	if _, err = DecodeBlueprint(forgedRaw); err == nil {
		t.Fatal("forged app input marker accepted")
	}
}

func TestAppInputDeliveryUsesSameContractAndRestoresOriginalCheckpoint(t *testing.T) {
	f, _, ctx, _ := externalFixture(t)
	ctx.ExternalNetworks = nil
	raw := []byte(appInputDocument())
	d, err := NewDelivery(f.c, ctx, raw)
	if err != nil {
		t.Fatal("new CD app", err)
	}
	encoded, err := d.Encode()
	if err != nil {
		t.Fatal("new CD encode with omitted external", err)
	}
	d, err = DecodeDelivery(encoded)
	if err != nil {
		t.Fatal("new CD restore", err)
	}
	changed := []byte(strings.Replace(string(raw), "MODE: app", "MODE: next", 1))
	d, err = d.SubmitFile(d.Revision(), f.c, ctx, "alice", changed)
	if err != nil {
		t.Fatal("new CD file", err)
	}
	if _, err = d.Encode(); err != nil {
		t.Fatal("new CD candidate normalized differently", err)
	}
	oldInput := smallCompose(t)
	oldRaw, _ := yaml.Marshal(oldInput)
	if _, err = NewDelivery(f.c, ctx, oldRaw); err == nil {
		t.Fatal("CD accepted old management input")
	}
	if _, err = d.SubmitFile(d.Revision(), f.c, ctx, "alice", oldRaw); err == nil {
		t.Fatal("CD file update accepted old management input")
	}
	selectedID, ok := d.Candidate()
	if !ok {
		t.Fatal("new app candidate missing")
	}
	d, err = d.Approve(d.Revision(), f.c, ctx, "alice", selectedID)
	if err != nil {
		t.Fatal("new app CD approval", err)
	}
	d, err = d.Start(d.Revision(), f.c, ctx, "app-sync", "submitter", 1)
	if err != nil {
		t.Fatal("new app CD shared execution", err)
	}
	active, ok := d.Inventory().Execution()
	if !ok || active.Blueprint().CheckAppInput() != nil || active.Status() != "Planned" {
		t.Fatal("CD did not use the app execution")
	}
	activeRaw, err := d.Encode()
	if err != nil {
		t.Fatal("active CD checkpoint", err)
	}
	if _, err = DecodeDelivery(activeRaw); err != nil {
		t.Fatal("active app execution restore", err)
	}
	// Restore a pre-change checkpoint constructed from frozen product records.
	// No new public constructor is used to re-authorize that historical input.
	oldCtx := contextFor(t, f)
	old, err := Compile(oldInput, f.c, oldCtx)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := NewInventory(ctx.Cluster, old.d.Tenant, old.d.App, old.d.Deployment)
	if err != nil {
		t.Fatal(err)
	}
	model := old.d.Input
	model.Sfc.Delivery = &DeliveryDeclaration{}
	if model.normalize() != nil {
		t.Fatal("fixture policy")
	}
	candidate := deliveryCandidate{Artifact: deliveryArtifact{Kind: "file", Digest: sha256.Sum256(oldRaw), Body: oldRaw}, Plan: old.d, PolicyRevision: 1, InventoryRevision: inv.Revision()}
	candidate.ID = candidateID(candidate)
	frozen := Delivery{deliveryRecord{Schema: 1, Revision: 1, PolicyRevision: 1, Principal: ctx.Actor, Policy: *model.Sfc.Delivery, Inventory: inv.d, CatalogFloor: f.c.Revision(), NetworkFloor: oldCtx.Networks.Revision(), Candidate: &candidate}}
	historical, err := frozen.Encode()
	if err != nil {
		t.Fatal("historical checkpoint", err)
	}
	restored, err := DecodeDelivery(historical)
	if err != nil {
		t.Fatal("historical restore", err)
	}
	roundtrip, _ := restored.Encode()
	if !bytes.Equal(historical, roundtrip) {
		t.Fatal("historical checkpoint rewritten")
	}
	id, _ := restored.Candidate()
	if _, err = restored.Approve(restored.Revision(), f.c, oldCtx, "alice", id); err == nil {
		t.Fatal("legacy pending candidate received a new approval")
	}
}
