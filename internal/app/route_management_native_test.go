// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/network/services"
	"gopkg.in/yaml.v3"
)

// This reuses the actual two-owner engines and CLI wallet: DNS policies go
// through typed 'manage apply' changes over real authenticated MYDCP.
func testRouteManagementRecovery(t *testing.T, ctx context.Context, a *Runtime, root, home string, definitions []services.ManagedDNSDefinition, read func() cluster.View, cli func(int, ...string) []byte) {
	t.Helper()
	if len(definitions) != 3 || definitions[1].Tenant != definitions[2].Tenant {
		t.Fatal("original three-network DNS fixture required")
	}
	document := func(tenant string, defs []services.ManagedDNSDefinition, expected []uint64) []byte {
		t.Helper()
		changes := []map[string]any{}
		for n, definition := range defs {
			raw, err := json.Marshal(definition)
			var payload map[string]any
			if err != nil || json.Unmarshal(raw, &payload) != nil {
				t.Fatal("DNS public management payload", err)
			}
			changes = append(changes, map[string]any{"id": definition.Network, "action": "configure-network-dns", "expected": expected[n], "payload": payload})
		}
		raw, err := yaml.Marshal(map[string]any{"schema": 1, "tenant": tenant, "changes": changes})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	apply := func(args ...string) { cli(0, args...) }
	applyManagementChanges(t, root, "route-source-dns", document(definitions[0].Tenant, definitions[:1], []uint64{0}), apply)
	applyManagementChanges(t, root, "route-dns", document(definitions[1].Tenant, definitions[1:], []uint64{0, 0}), apply)
	nearKey := services.ManagedDNSKey(definitions[2].Tenant, definitions[2].Network)
	for _, definition := range definitions {
		sources, err := a.controlPolicy.ManagedDNS(read().State)
		source, exists := sources[services.ManagedDNSKey(definition.Tenant, definition.Network)]
		got, _ := json.Marshal(source.Definition)
		want, _ := json.Marshal(definition)
		if err != nil || !exists || !bytes.Equal(got, want) {
			t.Fatal("actual CLI did not apply original typed DNS source", definition.Network, err)
		}
	}
	// A confirmed CAS rejection changes nothing and keeps its result.
	view := read()
	targetKey := services.ManagedDNSKey(definitions[1].Tenant, definitions[1].Network)
	beforeNear, beforeTarget := view.State.Object(nearKey), view.State.Object(targetKey)
	badNear := definitions[2]
	badNear.Policy.TTL = 45
	encoded, err := json.Marshal(badNear)
	var payload map[string]any
	if err != nil || json.Unmarshal(encoded, &payload) != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"schema": 1, "action": "configure-network-dns", "expected": 0, "payload": payload})
	rejected := filepath.Join(root, "route-dns-rejected.json")
	if err = os.WriteFile(rejected, body, 0600); err != nil {
		t.Fatal(err)
	}
	cli(3, "manage", "apply", "--request-id", "route-dns-rejected", "--change", rejected)
	cli(3, "manage", "result", "--request-id", "route-dns-rejected")
	if read().State.Object(nearKey) != beforeNear || read().State.Object(targetKey) != beforeTarget {
		t.Fatal("rejected original CAS changed DNS policy")
	}
	t.Log("real CLI DNS settings: typed changes in order through manage apply; rejected CAS changes nothing")
}
