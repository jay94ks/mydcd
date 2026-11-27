// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/workload"
)

func TestAppLoggingPinsDeclarationAndRejectsNonStringOptions(t *testing.T) {
	base := appInputDocument()
	raw := strings.Replace(base, "  web:\n", "  web:\n    logging: {driver: local, options: {max-size: '10m', max-file: '3', compress: 'false'}}\n", 1)
	app, err := ParseApp([]byte(raw))
	if err != nil || app.Services["web"].Logging == nil || app.Services["web"].Logging.Options["max-file"] != "3" {
		t.Fatal("app logging declaration lost", err)
	}
	plain, err := ParseApp([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	old, _ := json.Marshal(plain.Services["web"])
	if bytes.Contains(old, []byte(`"Logging"`)) {
		t.Fatal("absent field changed old schema1 task bytes")
	}
	if a, _ := app.Digest(); a == ([32]byte{}) {
		t.Fatal("invalid declaration digest")
	} else if b, _ := plain.Digest(); a == b {
		t.Fatal("logging omitted from desired digest")
	}
	for _, value := range []string{"null", "{}", "{driver: syslog}", "{driver: local, options: {max-file: 3}}", "{driver: local, options: {compress: true}}", "{driver: local, options: {max-size: '-1'}}", "{driver: local, options: {env: SECRET}}", "{driver: local, unknown: true}"} {
		invalid := strings.Replace(base, "  web:\n", "  web:\n    logging: "+value+"\n", 1)
		if _, err := ParseApp([]byte(invalid)); err == nil {
			t.Fatal("invalid logging input accepted", value)
		}
	}
}
func TestTaskRecipeOwnsLoggingBeforeNativeResolution(t *testing.T) {
	_, b, material := taskMaterialFixtureWith(t, func(input *Compose) {
		s := input.Services["db"]
		s.Logging = &workload.LogPolicy{Driver: "json-file", Options: map[string]string{"max-size": "1m", "max-file": "2"}}
		input.Services["db"] = s
	})
	_, spec, err := b.taskRecipe("db", material, material.Bridge.Owner)
	if err != nil || spec.Logging == nil || spec.Logging.Driver != "json-file" {
		t.Fatal("logging not frozen in native recipe", err)
	}
	spec.Logging.Options["max-size"] = "2m"
	_, again, err := b.taskRecipe("db", material, material.Bridge.Owner)
	if err != nil || again.Logging.Options["max-size"] != "1m" {
		t.Fatal("native recipe changed original app logging", err)
	}
}
func TestLoggingOverrideUsesExistingAppOwnershipAndCAS(t *testing.T) {
	f, ctx, d, _ := completedRegisteredApp(t)
	path := []string{"services", "web", "logging"}
	key := ResourceKey("task", "tenant", d.Inventory().Scope().App, "web")
	current := ctx.Current[key]
	refs := []ObjectRef{{key, current.Revision, current.Generation}}
	artifact := bytes.Clone(d.d.Candidate.Artifact.Body)
	running := bytes.Clone(goal(d.d.Running))
	value := json.RawMessage(`{"driver":"local","options":{"max-size":"1m","max-file":"2"}}`)
	next, err := d.PutOverride(d.Revision(), 0, f.c, ctx, "alice", path, value, refs)
	if err != nil {
		t.Fatal("logging override rejected", err)
	}
	policy := next.d.Candidate.Plan.Input.Services["web"].Logging
	if policy == nil || policy.Driver != "local" || policy.Options["max-file"] != "2" || !bytes.Equal(artifact, next.d.Candidate.Artifact.Body) || !bytes.Equal(running, goal(next.d.Running)) {
		t.Fatal("override rewrote Git/running or dropped logging")
	}
	if _, err := d.PutOverride(d.Revision()+1, 0, f.c, ctx, "alice", path, value, refs); err == nil {
		t.Fatal("stale logging CAS accepted")
	}
	refs[0].Generation++
	if _, err := d.PutOverride(d.Revision(), 0, f.c, ctx, "alice", path, value, refs); err == nil {
		t.Fatal("foreign generation logging override accepted")
	}
}
