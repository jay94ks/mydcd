// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestManagedDNSAppAliasesKeepFrozenBytesAndRequireRealCapability(t *testing.T) {
	f, input, context := managedNetworkFixture(t)
	old, err := CompileApp(input, f.c, context)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := old.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("Aliases")) {
		t.Fatal("absent new field changed schema1 artifact")
	}
	restored, err := DecodeBlueprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := restored.Encode()
	if !bytes.Equal(raw, again) {
		t.Fatal("frozen artifact rewritten")
	}
	service := input.Services["web"]
	attachment := service.Networks["app"]
	attachment.Aliases = []string{"web"}
	service.Networks["app"] = attachment
	input.Services["web"] = service
	if _, err := CompileApp(input, f.c, context); err == nil || !strings.Contains(err.Error(), "FEATURE_UNAVAILABLE: managed-dns") {
		t.Fatal("new DNS consumer was silently enabled", err)
	}
	canonical, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseApp(canonical)
	if err != nil || len(parsed.Services["web"].Networks["app"].Aliases) != 1 {
		t.Fatal("library model erased explicit aliases", err)
	}
	encoded, _ := json.Marshal(parsed)
	if !bytes.Contains(encoded, []byte(`"Aliases":["web"]`)) {
		t.Fatal("alias lost at artifact boundary")
	}
}
