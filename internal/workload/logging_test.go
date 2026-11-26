// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
)

func TestLoggingPolicyPreservesInheritanceAndPinsDeclaredOptions(t *testing.T) {
	var absent *LogPolicy
	raw, err := json.Marshal(ContainerSpec{Schema: 1})
	if err != nil || strings.Contains(string(raw), "Logging") || !absent.Matches(container.LogConfig{Type: "json-file", Config: map[string]string{"max-size": "2m"}}) {
		t.Fatal("absent policy changed old task inheritance", err)
	}
	for _, driver := range []string{"local", "json-file"} {
		p := LogPolicy{Driver: driver, Options: map[string]string{"max-size": "10m", "max-file": "3", "compress": "true"}}
		if p.Validate() != nil {
			t.Fatal("reviewed Engine options rejected", driver)
		}
		actual := p.Native()
		actual.Config["max-size"] = "20m"
		if p.Options["max-size"] != "10m" || p.Matches(actual) {
			t.Fatal("native mutation rebound original logging policy")
		}
		cloned := p.Clone()
		cloned.Options["max-file"] = "4"
		if p.Options["max-file"] != "3" {
			t.Fatal("cloned task aliased declared policy")
		}
		if !p.Matches(p.Native()) || p.Matches(container.LogConfig{Type: "fluentd", Config: p.Options}) {
			t.Fatal("driver/config ownership not checked")
		}
	}
	p := LogPolicy{Driver: "json-file", Options: map[string]string{"max-size": "10m"}}
	if !p.Matches(container.LogConfig{Type: "json-file", Config: map[string]string{"max-size": "10m", "max-file": "5"}}) {
		t.Fatal("Engine default for an undeclared option became a task mismatch")
	}
}
func TestLoggingPolicyRejectsUnsupportedDriversAndRotationValues(t *testing.T) {
	for _, p := range []LogPolicy{
		{}, {Driver: "none"}, {Driver: "syslog"}, {Driver: "local", Options: map[string]string{"env": "SECRET"}},
		{Driver: "local", Options: map[string]string{"max-size": "-1"}}, {Driver: "local", Options: map[string]string{"max-size": "0m"}},
		{Driver: "local", Options: map[string]string{"max-file": "0"}}, {Driver: "local", Options: map[string]string{"max-file": "9223372036854775808"}},
		{Driver: "local", Options: map[string]string{"compress": "yes"}}, {Driver: "local", Options: map[string]string{"max-size": "10m\n"}},
	} {
		if p.Validate() == nil {
			t.Fatal("unsafe/unsupported policy accepted", p)
		}
	}
}
