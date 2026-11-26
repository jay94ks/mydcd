// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
)

func TestComposeStopsPreservePerServicePolicyAndRejectInvalidExplicitInputs(t *testing.T) {
	raw := strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))
	raw = strings.Replace(raw, "  db:\n", "  db:\n    stop_grace_period: 120.001s\n    stop_signal: QUIT\n", 1)
	c, err := ParseCompose([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	db, web := c.Services["db"], c.Services["web"]
	p, err := engine.ParseStopPolicy(db.StopGracePeriod, db.StopSignal)
	if err != nil || p == nil || p.GraceSeconds != 121 || p.Signal != "SIGQUIT" || web.StopGracePeriod != "" || web.StopSignal != "" {
		t.Fatal("per-service stop configuration was lost/invented", err)
	}
	f := makeFixture(t)
	b, err := Compile(c, f.c, contextFor(t, f))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeBlueprint(encoded)
	if err != nil || restored.Digest() != b.Digest() {
		t.Fatal("original stop Task did not restore", err)
	}
	var frozen ComposeService
	if json.Unmarshal(stepMap(restored)[ResourceKey("task", "tenant", "php-mysql", "db")].Goal, &frozen) != nil || frozen.StopGracePeriod != db.StopGracePeriod || frozen.StopSignal != db.StopSignal {
		t.Fatal("Stop policy dropped from accepted Task metadata")
	}
	legacy, _ := json.Marshal(smallCompose(t).Services["db"])
	if bytes.Contains(legacy, []byte(`"StopGracePeriod"`)) || bytes.Contains(legacy, []byte(`"StopSignal"`)) {
		t.Fatal("new absent fields changed existing schema1 Task bytes")
	}
	for _, input := range []string{"stop_grace_period: null", "stop_grace_period: ''", "stop_grace_period: -1s", "stop_grace_period: 25h", "stop_signal: null", "stop_signal: ''", "stop_signal: 15", "stop_signal: SIGUNKNOWN", "stop_signal: ' SIGTERM'"} {
		bad := strings.Replace(strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64)), "  db:\n", "  db:\n    "+input+"\n", 1)
		if _, err := ParseCompose([]byte(bad)); err == nil {
			t.Fatal("explicit invalid stop input accepted", input)
		}
	}
}

func TestTaskRecipePinsStopPolicyBeforeNativeResolution(t *testing.T) {
	_, b, material := taskMaterialFixtureWith(t, func(input *Compose) {
		s := input.Services["db"]
		s.StopGracePeriod, s.StopSignal = "120.001s", "SIGQUIT"
		input.Services["db"] = s
	})
	_, spec, err := b.taskRecipe("db", material, material.Bridge.Owner)
	if err != nil || spec.Stop == nil || *spec.Stop != (engine.StopPolicy{GraceSeconds: 121, Signal: "SIGQUIT"}) {
		t.Fatal("stop policy dropped from original native recipe", err)
	}
	_, next, err := b.taskRecipe("db", material, material.Bridge.Owner)
	if err != nil {
		t.Fatal(err)
	}
	spec.Stop.GraceSeconds = 1
	if next.Stop.GraceSeconds != 121 {
		t.Fatal("caller rewrote original Task stop policy")
	}
}
