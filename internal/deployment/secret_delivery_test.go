// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestComposeSecretEnvironmentPlanUsesOriginalBindingAndReplacementNotice(t *testing.T) {
	f := makeFixture(t)
	input := smallCompose(t)
	service := input.Services["web"]
	service.MyDC.SecretEnv = []SecretEnvironment{{Source: "db-password", Name: "REPORT_DB_PASS"}}
	service.Secrets[0].Target = "/etc/app/password"
	input.Services["web"] = service
	plan, err := Compile(input, f.c, contextFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	needs, err := plan.Inputs("web", "web-task", 4, public(private(30)))
	if err != nil || len(needs.Files) != 2 || needs.Files[1].Kind != "env" || needs.Files[1].Target != "REPORT_DB_PASS" {
		t.Fatal("env projection detached from original approval recipe", err)
	}
	if !slices.Equal(plan.SecretEnvironmentServices(), []string{"web"}) {
		t.Fatal("missing new Task generation notice")
	}
	raw, err := plan.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBlueprint(raw)
	if err != nil || !slices.Equal(decoded.SecretEnvironmentServices(), []string{"web"}) {
		t.Fatal("notice lost in frozen plan", err)
	}
	decoded.d.SecretEnvRequiresNewGeneration = nil
	if _, err = decoded.Encode(); err == nil {
		t.Fatal("plan removed required replacement notice")
	}
	f.approveAll(needs)
	b := f.reserve(needs).Bindings[0]
	stage, err := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(needs), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Destroy()
	if len(stage.files) != 2 || !bytes.Equal(stage.files[0].Data, stage.files[1].Data) || stage.files[1].Source != "tenant/runtime" {
		t.Fatal("same key projection merge/provenance differs")
	}
	if bytes.Contains(raw, stage.files[1].Data) {
		t.Fatal("private value entered public plan")
	}
	for _, change := range []struct {
		name   string
		modify func(*ComposeService)
		code   string
	}{
		{"literal conflict", func(s *ComposeService) { s.Environment["REPORT_DB_PASS"] = "literal" }, "SECRET_ENV_CONFLICT"},
		{"invalid name", func(s *ComposeService) { s.MyDC.SecretEnv[0].Name = "A=B" }, "INVALID_SECRET_ENV"},
		{"missing alias", func(s *ComposeService) { s.MyDC.SecretEnv[0].Source = "missing" }, "SECRET_BINDING_REQUIRED"},
	} {
		t.Run(change.name, func(t *testing.T) {
			var changed Compose
			encoded, _ := json.Marshal(input)
			if json.Unmarshal(encoded, &changed) != nil {
				t.Fatal("copy")
			}
			s := changed.Services["web"]
			change.modify(&s)
			changed.Services["web"] = s
			if err := changed.validate(); err == nil || !strings.HasPrefix(err.Error(), change.code+":") {
				t.Fatal("typed declaration rejection", err)
			}
		})
	}
}

func TestEnvironmentProjectionPrivateFileSurvivesReopenWithoutContainerUIDOwnership(t *testing.T) {
	f := makeFixture(t)
	needs := f.web()
	needs.Files = []Projection{{Key: "DB_PASSWORD", Target: "APP_PASSWORD", Mode: 0400, Kind: "env"}}
	f.approveAll(needs)
	b := f.reserve(needs).Bindings[0]
	stage, err := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(needs), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Destroy()
	root := filepath.Join(t.TempDir(), "inputs")
	gate := func(ctx context.Context, b Binding) error { return b.Check(f.bindings, f.c, f.trees, f.a, f.v, 100) }
	store, err := OpenProjections(root, f.cluster, b.d.Needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	ref, err := store.Publish(context.Background(), b, stage, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	consumer, key := projectionConsumer(t, f, b)
	lease, err := store.AcquireInputs(context.Background(), ref, consumer, key, ref.Generation)
	if err != nil || len(lease.Files) != 1 || lease.Files[0].Kind != "env" || lease.Files[0].Reference != "tenant/runtime/DB_PASSWORD" {
		t.Fatal("native env lease provenance", err)
	}
	info, err := os.Stat(lease.Files[0].Source)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private daemon-owned environment staging", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenProjections(root, f.cluster, b.d.Needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	lease2, err := store.InspectInputs(context.Background(), ref, consumer, key, ref.Generation)
	if err != nil || lease2.Pin != lease.Pin || lease2.Files[0].Reference != lease.Files[0].Reference {
		t.Fatal("original env pin/provenance lost", err)
	}
}
