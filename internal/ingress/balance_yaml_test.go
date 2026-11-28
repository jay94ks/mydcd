// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBalanceYAMLWarmup(t *testing.T) {
	var b Balance
	if err := yaml.Unmarshal([]byte("method: round-robin\nwarmup: 1500ms\nweights: {v1: 9, v2: 1}\n"), &b); err != nil || b.SlowStartMS != 1500 || b.SlowStartSeconds != 0 || b.Weights["v2"] != 1 {
		t.Fatal(b, err)
	}
	raw, err := yaml.Marshal(b)
	if err != nil || !strings.Contains(string(raw), "warmup: 1.5s") || strings.Contains(string(raw), "slow_start") {
		t.Fatal(string(raw), err)
	}
	if raw, _ := yaml.Marshal(Balance{SlowStartSeconds: 30}); !strings.Contains(string(raw), "warmup: 30s") {
		t.Fatal(string(raw))
	}
	for _, bad := range []string{"slow_start: 30\n", "slow_start_ms: 500\n", "warmup: 2h\n", "warmup: -1s\n", "warmup: 30\n", "unknown: 1\n"} {
		var b Balance
		if yaml.Unmarshal([]byte(bad), &b) == nil {
			t.Fatal("accepted", bad)
		}
	}
}
