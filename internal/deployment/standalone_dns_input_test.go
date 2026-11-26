// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"strings"
	"testing"
)

func TestStandaloneDNSProjectionKeepsOriginalDocumentAndTaskBytes(t *testing.T) {
	f, input, ctx := managedNetworkFixture(t)
	input.Name = ""
	delete(input.Services, "db")
	service := input.Services["web"]
	service.DependsOn = nil
	input.Services["web"] = service
	raw, err := marshalApp(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx.Project = ""
	b, err := CompileStandaloneDocument(raw, "debug", f.c, ctx, "entrypoint")
	if err != nil {
		t.Fatal("DNS-free standalone unexpectedly required managed-dns", err)
	}
	if ctx.Features["managed-dns"] {
		t.Fatal("fixture did not preserve the absent managed DNS capability")
	}
	before, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	document := b.OriginalDocument()
	effective, err := document.EffectiveInput(b.Scope())
	task, _, taskErr := b.TaskInput("web")
	if err != nil || taskErr != nil || !bytes.Equal(document.Body, raw) || len(effective.Services["web"].Networks["app"].Aliases) != 0 || len(task.Networks["app"].Aliases) != 0 || bytes.Contains(before, []byte(`"Aliases"`)) {
		t.Fatal("projection default leaked into original/effective input or Task recipe", err, taskErr)
	}
	restored, err := DecodeBlueprint(before)
	if err != nil || restored.Digest() != b.Digest() {
		t.Fatal("standalone DNS default changed schema1 restoration", err)
	}
	ctx.Project = b.Scope().App
	again, err := CompileStandaloneDocument(restored.OriginalDocument().Body, restored.StandaloneName(), f.c, ctx, "entrypoint")
	if err != nil || again.Digest() != b.Digest() {
		t.Fatal("original standalone document could not reproduce its Blueprint", err)
	}
	// Explicit aliases retain the ordinary app-service capability requirement;
	// the projection fallback must not make that syntax silently available.
	attachment := service.Networks["app"]
	attachment.Aliases = []string{"chosen"}
	service.Networks["app"] = attachment
	input.Services["web"] = service
	raw, err = marshalApp(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CompileStandaloneDocument(raw, "debug", f.c, ctx, "entrypoint"); err == nil || !strings.Contains(err.Error(), "FEATURE_UNAVAILABLE: managed-dns") {
		t.Fatal("explicit standalone aliases bypassed the common managed DNS capability", err)
	}
	ctx.Features["managed-dns"] = true
	explicit, err := CompileStandaloneDocument(raw, "debug", f.c, ctx, "entrypoint")
	if err != nil {
		t.Fatal(err)
	}
	task, _, err = explicit.TaskInput("web")
	if err != nil || len(task.Networks["app"].Aliases) != 1 || task.Networks["app"].Aliases[0] != "chosen" {
		t.Fatal("common service parser erased an explicit alias", err)
	}
}
