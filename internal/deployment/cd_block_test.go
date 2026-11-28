// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCDBlockDefaultsAndRoundTrip(t *testing.T) {
	var p DeliveryDeclaration
	if err := yaml.Unmarshal([]byte("repository: https://git.example.com/shop.git\nbranch: main\npath: deploy/app.yaml\nsync: auto\nprune: true\n"), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || p.Poll != 60 || p.Sync.Mode != "automatic" || p.Sync.Drift != "report" || !p.Sync.Prune || p.Source.Kind != "git" || p.Limits.Fetch != 30 || p.Limits.Bytes != 4<<20 {
		t.Fatalf("defaults: %+v", p)
	}
	raw, err := yaml.Marshal(p)
	if err != nil || !strings.Contains(string(raw), "poll: 1m\n") || !strings.Contains(string(raw), "sync: auto\n") {
		t.Fatalf("block form: %s %v", raw, err)
	}
	var back DeliveryDeclaration
	if err := yaml.Unmarshal(raw, &back); err != nil || back != p {
		t.Fatal("round trip changed the policy", back, err)
	}
	for bad, code := range map[string]string{
		"branch: b\npath: p\n":                             "INVALID_CD",
		"repository: r\nbranch: b\npath: p\npoll: 500ms\n": "INVALID_CD",
		"repository: r\nbranch: b\npath: p\nsync: often\n": "INVALID_CD",
		"repository: r\nbranch: b\npath: p\ndrift: x\n":    "INVALID_CD",
		"repository: r\nbranch: b\npath: p\nversion: 1\n":  "INVALID_FIELD",
		"repository: r\nbranch: b\npath: p\nunknown: 1\n":  "INVALID_FIELD",
	} {
		var p DeliveryDeclaration
		err := yaml.Unmarshal([]byte(bad), &p)
		if inputCodeOf(err) != code {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func inputCodeOf(err error) string {
	var input *InputError
	if errors.As(err, &input) {
		return input.Code
	}
	return ""
}
