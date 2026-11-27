// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"

	"gopkg.in/yaml.v3"
)

// applyManagementChanges sends each change of a {schema, tenant, changes}
// document in order with the CLI's 'manage apply' (one typed change per
// request) and reads back its result. It replaces the removed partial
// cluster.yaml command in these real-boundary fixtures.
func applyManagementChanges(t *testing.T, dir, prefix string, raw []byte, cli func(args ...string)) {
	t.Helper()
	for _, c := range managementChanges(t, raw) {
		body, err := json.Marshal(map[string]any{"schema": 1, "action": c.Action, "expected": c.Expected, "payload": c.Payload})
		if err != nil {
			t.Fatal(err)
		}
		id := prefix + "-" + c.ID
		file := filepath.Join(dir, id+".json")
		if err = os.WriteFile(file, body, 0600); err != nil {
			t.Fatal(err)
		}
		cli("manage", "apply", "--request-id", id, "--change", file)
		cli("manage", "result", "--request-id", id)
	}
}

type managementChange struct {
	ID       string `yaml:"id"`
	Action   string `yaml:"action"`
	Expected uint64 `yaml:"expected"`
	Payload  any    `yaml:"payload"`
}

func managementChanges(t *testing.T, raw []byte) []managementChange {
	t.Helper()
	var doc struct {
		Schema  int                `yaml:"schema"`
		Tenant  string             `yaml:"tenant"`
		Changes []managementChange `yaml:"changes"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil || doc.Schema != 1 || len(doc.Changes) == 0 {
		t.Fatal("management change list", err)
	}
	return doc.Changes
}

// applyManagementChangesDirect sends the same typed changes through the
// fixture's own user session, for owners that plan apps without the CLI.
// Each created managed network must be observed current before an app can
// borrow it, so it waits for that too.
func applyManagementChangesDirect(t *testing.T, ctx context.Context, prefix string, raw []byte, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	for _, c := range managementChanges(t, raw) {
		change(prefix+"-"+c.ID, c.Action, c.Expected, typedManagementPayload(t, c))
	}
	waitManagementNetworks(t, ctx, raw, p, read)
}

// typedManagementPayload decodes a change's payload into its Go type. The
// server takes only the canonical JSON of that type (its field order), which
// a generic yaml map does not keep.
func typedManagementPayload(t *testing.T, c managementChange) any {
	t.Helper()
	var typed any
	switch c.Action {
	case "create-tun-network":
		typed = &tenancy.TUNDefinition{}
	case "configure-network-dns":
		typed = &services.ManagedDNSDefinition{}
	default:
		t.Fatal("no Go type for management action", c.Action)
	}
	raw, err := json.Marshal(c.Payload)
	if err == nil {
		err = json.Unmarshal(raw, typed)
	}
	if err != nil {
		t.Fatal("management payload", c.Action, err)
	}
	return typed
}

// waitManagementNetworks waits for each network a change list created.
func waitManagementNetworks(t *testing.T, ctx context.Context, raw []byte, p control.Policy, read func() cluster.View) {
	t.Helper()
	for _, c := range managementChanges(t, raw) {
		if c.Action != "create-tun-network" {
			continue
		}
		payload, _ := c.Payload.(map[string]any)
		tenant, _ := payload["Tenant"].(string)
		name, _ := payload["Name"].(string)
		waitManagedNetworkCurrent(t, ctx, p, read, tenant, name)
	}
}

// waitManagedNetworkCurrent waits until every bridge and tunnel source of a
// managed network has been observed at its committed generation, which is
// what app planning requires of a borrowed network.
func waitManagedNetworkCurrent(t *testing.T, ctx context.Context, p control.Policy, read func() cluster.View, tenant, name string) {
	t.Helper()
	for {
		view := read()
		resources, err := p.Resources(view.State)
		if err != nil {
			t.Fatal("managed network resources", err)
		}
		rows, err := resources.Networks.TUNSources(tenant, name)
		if err != nil {
			t.Fatal("managed network sources", tenant, name, err)
		}
		current := len(rows) > 0
		objects := view.State.Objects("")
		for _, row := range rows {
			for _, key := range []string{row.BridgeKey, row.TunnelKey} {
				if key == "" {
					continue
				}
				o, exists := objects[key]
				if !exists || !o.Present || o.Generation == 0 || o.Revision < o.Generation {
					current = false
				}
			}
		}
		if current {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("managed network never became current", tenant, name, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// withTenant puts the global --tenant in front of a tenant command, as the
// removed 'tenant use' default did. Account commands and commands that
// already name a tenant are left alone.
func withTenant(tenant string, args []string) []string {
	if tenant == "" || len(args) == 0 {
		return args
	}
	switch args[0] {
	case "wallet", "login", "logout", "whoami", "enroll-admin", "node", "server-version":
		return args
	}
	for _, a := range args {
		if a == "--tenant" || strings.HasPrefix(a, "--tenant=") {
			return args
		}
	}
	return append([]string{"--tenant", tenant}, args...)
}
