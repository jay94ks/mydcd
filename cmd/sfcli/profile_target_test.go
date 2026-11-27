// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func TestU0ProfileDefaultsRemainOverridableAndDoNotBecomeExplicitFlags(t *testing.T) {
	defaults := cliprofile.Selection{Project: "example", Node: "node-a"}
	options, err := parseComposeDefaults([]string{"wait", "--operation", "original"}, io.Discard, defaults)
	if err != nil || options.project.value != "example" || options.project.set || options.node.set {
		t.Fatal(options, err)
	}
	options, err = parseComposeDefaults([]string{"plan", "-p", "override", "--node", "node-b"}, io.Discard, defaults)
	if err != nil || options.project.value != "override" || options.node.value != "node-b" || !options.project.set || !options.node.set {
		t.Fatal(options, err)
	}
}

func TestU0TenantMismatchRejectsBeforeClientOrOriginalLookup(t *testing.T) {
	stored := userauth.Stored{Tenant: "selected", TargetTenant: "selected"}
	{
		var out, diagnostic bytes.Buffer
		if code := runCompose(context.Background(), []string{"ps", "--tenant", "foreign"}, userauth.Client{}, sfcp.Peer{}, stored, "", &out, &diagnostic); code != 2 || out.Len() != 0 {
			t.Fatal(code, out.String(), diagnostic.String())
		}
	}
	for _, payload := range []any{
		map[string]any{"Tenant": "foreign"},
		map[string]any{"Realm": "foreign"},
		map[string]any{"Scope": map[string]any{"Tenant": "foreign"}},
		map[string]any{"Target": map[string]any{"Scope": map[string]any{"Tenant": "foreign"}}},
		map[string]any{"Backup": map[string]any{"Scope": map[string]any{"Tenant": "foreign"}}},
		map[string]any{"Selection": map[string]any{"Scope": map[string]any{"Tenant": "foreign"}}},
		map[string]any{"Observation": map[string]any{"Tenant": "foreign"}},
	} {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkManagementTenant("selected", control.Change{Payload: raw}); err == nil {
			t.Fatal("typed metadata target bypassed global tenant", string(raw))
		}
	}
}

func TestManagementTenantDistinguishesAppDigestAndResourceScopeTargets(t *testing.T) {
	digest := [32]byte{1}
	for _, action := range []string{"configure-app-cd", "sync-app", "recover-app", "down-app", "override-app", "release-app-override"} {
		raw, err := json.Marshal(map[string]any{"Tenant": "selected", "App": "app", "Target": digest})
		if err != nil {
			t.Fatal(err)
		}
		if err := checkManagementTenant("selected", control.Change{Action: action, Payload: raw}); err != nil {
			t.Fatal("original app target digest rejected by tenant selection", action, err)
		}
		foreign, _ := json.Marshal(map[string]any{"Tenant": "foreign", "App": "app", "Target": digest})
		if err := checkManagementTenant("selected", control.Change{Action: action, Payload: foreign}); err == nil {
			t.Fatal("digest bypassed original tenant", action)
		}
		object, _ := json.Marshal(map[string]any{"Tenant": "selected", "Target": map[string]any{"Scope": map[string]any{"Tenant": "foreign"}}})
		if err := checkManagementTenant("selected", control.Change{Action: action, Payload: object}); err == nil {
			t.Fatal("resource object adopted as app digest", action)
		}
	}
	for _, target := range []any{map[string]any{"Scope": map[string]any{"Tenant": "selected"}}, map[string]any{"Tenant": "selected"}} {
		raw, _ := json.Marshal(map[string]any{"Tenant": "selected", "Target": target})
		if err := checkManagementTenant("selected", control.Change{Action: "begin-volume-move", Payload: raw}); err != nil {
			t.Fatal("original resource destination rejected", err)
		}
	}
	for _, target := range []any{nil, []int{1}, "base64-digest"} {
		raw, _ := json.Marshal(map[string]any{"Tenant": "selected", "Target": target})
		err := checkManagementTenant("selected", control.Change{Action: "configure-app-cd", Payload: raw})
		if (err == nil) != (target == nil) {
			t.Fatal("legacy/null or malformed digest boundary changed", err)
		}
	}
	for _, target := range []any{map[string]any{"Scope": map[string]any{"Tenant": "foreign"}}, digest, "invalid"} {
		raw, _ := json.Marshal(map[string]any{"Tenant": "selected", "Target": target})
		if err := checkManagementTenant("selected", control.Change{Action: "begin-volume-move", Payload: raw}); err == nil {
			t.Fatal("wrong/foreign resource target bypassed selected tenant")
		}
	}
}
