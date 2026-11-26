// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/workload"
)

func TestComposeHTTPReadinessDeadlineContract(t *testing.T) {
	base := strings.ReplaceAll(composeFixture, "DIGEST", strings.Repeat("a", 64))
	for _, tc := range []struct {
		value string
		want  int
	}{{"", 0}, {"1ms", 1}, {"3s", 3000}, {"30s", 30000}} {
		raw := base
		if tc.value != "" {
			raw = strings.Replace(raw, "port: 8080}", "port: 8080, timeout: "+tc.value+"}", 1)
		}
		c, err := ParseCompose([]byte(raw))
		if err != nil {
			t.Fatal(tc.value, err)
		}
		probe, err := c.Services["web"].MyDC.Readiness.httpProbe()
		if err != nil || probe.TimeoutMS != tc.want {
			t.Fatal(tc.value, probe, err)
		}
		encoded, err := json.Marshal(probe)
		var restored workload.HTTPReadiness
		if err != nil || json.Unmarshal(encoded, &restored) != nil || restored != *probe || !restored.Valid() {
			t.Fatal("immutable deadline roundtrip", tc.value)
		}
		if tc.want == 0 && strings.Contains(string(encoded), "TimeoutMS") {
			t.Fatal("legacy default JSON changed")
		}
	}
	for _, value := range []string{"0s", "-1s", "1ns", "1.0001ms", "30.001s", "bad", "999999999999999999999s"} {
		raw := strings.Replace(base, "port: 8080}", "port: 8080, timeout: "+value+"}", 1)
		if _, err := ParseCompose([]byte(raw)); err == nil {
			t.Fatal("invalid deadline accepted", value)
		}
	}
	// The exec form is the bare scalar `ready: healthcheck`, so it has no timeout to give.
	for _, form := range []string{"{timeout: 3s}", "{port: 8080}", "healthcheck-ish", "{http: /readyz, kind: exec}"} {
		raw := strings.Replace(base, "{http: /readyz, port: 8080}", form, 1)
		if _, err := ParseCompose([]byte(raw)); err == nil {
			t.Fatal("bad ready form accepted", form)
		}
	}
	raw := strings.Replace(base, "ready: {http: /readyz, port: 8080}", "ready: healthcheck", 1)
	raw = strings.Replace(raw, "    command: [php, app.php]\n", "    command: [php, app.php]\n    healthcheck: {test: [CMD, probe], interval: 5s, timeout: 3s, retries: 3}\n", 1)
	if c, err := ParseCompose([]byte(raw)); err != nil || c.Services["web"].MyDC.Readiness.Kind != "exec" {
		t.Fatal("ready: healthcheck", err)
	}
}

func TestHTTPReadinessLegacyDeclarationJSON(t *testing.T) {
	// Blueprints/Inventory retain canonical declarations from before timeout
	// existed. A missing optional field must not change their digest on decode.
	const original = `{"Kind":"http","Path":"/readyz","Port":8080}`
	var r Readiness
	if err := json.Unmarshal([]byte(original), &r); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil || string(raw) != original {
		t.Fatal("legacy declaration JSON changed", string(raw), err)
	}
}
