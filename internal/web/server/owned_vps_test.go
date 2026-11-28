// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
)

func TestOwnedVPSScreenStaysApart(t *testing.T) {
	f, _ := newFakeFixture(t)
	op := opSeq("ab12cdef")
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/system/owned-vps", nil); code != 403 {
		t.Fatalf("alice reads owned VPS: %d", code)
	}
	fakeLogin(t, f, "admin")
	code, out := f.do("GET", "/api/v1/system/owned-vps", nil)
	if code != 200 || len(out["accounts"].([]any)) != 0 || len(out["servers"].([]any)) != 0 {
		t.Fatalf("empty owned screen: %d %v", code, out)
	}
	accountRev := out["accountRevision"]

	if code, _ := f.do("POST", "/api/v1/system/owned-vps/accounts", map[string]any{"opId": op(), "name": "home", "vendor": "iwinv", "token": "T-1"}); code != 422 {
		t.Fatalf("managed vendor on the owned screen: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/system/vps/accounts", map[string]any{"opId": op(), "name": "home", "vendor": "hostinger", "accessKey": "A", "secretKey": "S"}); code != 422 {
		t.Fatalf("owned vendor on the managed screen: %d", code)
	}
	if code, out := f.do("POST", "/api/v1/system/owned-vps/accounts", map[string]any{"opId": op(), "name": "home", "vendor": "hostinger", "token": "TOKEN-9876"}); opState(t, code, out) != "applied" {
		t.Fatalf("add owned account: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/system/owned-vps", nil)
	if a := out["accounts"].([]any); len(a) != 1 || a[0].(map[string]any)["keyHint"] != "9876" || out["accountRevision"] == accountRev {
		t.Fatalf("owned accounts: %v", out)
	}
	if _, managed := f.do("GET", "/api/v1/system/vps", nil); len(managed["accounts"].([]any)) != 1 {
		t.Fatalf("owned account shown on the managed screen: %v", managed["accounts"])
	}

	if code, _ := f.do("POST", "/api/v1/system/owned-vps/servers", map[string]any{"opId": op(), "name": "edge-1", "account": "home", "instanceId": "101", "install": "ssh", "voter": true}); code != 422 {
		t.Fatalf("ssh voter: %d", code)
	}
	if code, out := f.do("POST", "/api/v1/system/owned-vps/servers", map[string]any{"opId": op(), "name": "edge-1", "account": "home", "instanceId": "101", "install": "manual", "port": 7443}); opState(t, code, out) != "applied" {
		t.Fatalf("attach: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/system/owned-vps", nil)
	s := out["servers"].([]any)
	if len(s) != 1 || s[0].(map[string]any)["phase"] != "installing" || s[0].(map[string]any)["protect"] != "exclude" {
		t.Fatalf("attached: %v", s)
	}
	if steps, _ := out["installSteps"].(map[string]any); steps["edge-1"] != float64(1) {
		t.Fatalf("install steps: %v", out["installSteps"])
	}
	if code, _ := f.do("DELETE", "/api/v1/system/owned-vps/accounts/home", map[string]any{"opId": op()}); code != 409 {
		t.Fatalf("remove account in use: %d", code)
	}
	if code, out := f.do("PATCH", "/api/v1/system/owned-vps/servers/edge-1", map[string]any{"opId": op(), "protect": "low-weight"}); opState(t, code, out) != "applied" {
		t.Fatalf("set: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/system/owned-vps/servers/edge-1", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("detach: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/system/owned-vps/accounts/home", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("remove account: %d %v", code, out)
	}
}

// The attach picker lists the account's VMs and marks the attached ones.
func TestOwnedVPSInstancePicker(t *testing.T) {
	f, fake := newFakeFixture(t)
	op := opSeq("ab16cdef")
	fakeLogin(t, f, "admin")
	if code, out := f.do("POST", "/api/v1/system/owned-vps/accounts", map[string]any{"opId": op(), "name": "home", "vendor": "hostinger", "token": "TOKEN-1234"}); opState(t, code, out) != "applied" {
		t.Fatalf("add account: %d %v", code, out)
	}
	if code, _ := f.do("GET", "/api/v1/system/owned-vps/accounts/nope/instances", nil); code != 404 {
		t.Fatalf("unknown account: %d", code)
	}
	if code, _ := f.do("GET", "/api/v1/system/owned-vps/accounts/home/instances", nil); code != 503 {
		t.Fatalf("vendor unavailable: %d", code)
	}
	fake.SetOwnedInstances("home", []control.OwnedVPSInstance{
		{ID: "101", Plan: "KVM 1", Zone: "us", PublicIP: "203.0.113.11", Image: "Ubuntu 24.04", Status: "active", ExpiresAt: 1_800_000_000},
		{ID: "102", Plan: "KVM 2", Zone: "nl", PublicIP: "203.0.113.12", Image: "Ubuntu 24.04", Status: "off"},
	})
	if code, out := f.do("POST", "/api/v1/system/owned-vps/servers", map[string]any{"opId": op(), "name": "edge-1", "account": "home", "instanceId": "101", "install": "manual", "port": 7443}); opState(t, code, out) != "applied" {
		t.Fatalf("attach: %d %v", code, out)
	}
	code, out := f.do("GET", "/api/v1/system/owned-vps/accounts/home/instances", nil)
	list, _ := out["instances"].([]any)
	if code != 200 || len(list) != 2 {
		t.Fatalf("instances: %d %v", code, out)
	}
	first, second := list[0].(map[string]any), list[1].(map[string]any)
	if first["attached"] != "edge-1" || first["plan"] != "KVM 1" || first["publicIP"] != "203.0.113.11" || second["attached"] != nil || second["status"] != "off" {
		t.Fatalf("picker rows: %v", list)
	}
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/system/owned-vps/accounts/home/instances", nil); code != 403 {
		t.Fatalf("alice lists instances: %d", code)
	}
}

func TestOwnedInstallStep(t *testing.T) {
	inv := &membership.Invitation{}
	for want, v := range map[int]control.OwnedVPS{
		0: {Phase: control.OwnedFailed, PublicIP: "203.0.113.1"},
		1: {Phase: control.OwnedInstalling},
		2: {Phase: control.OwnedInstalling, PublicIP: "203.0.113.1"},
		3: {Phase: control.OwnedInstalling, PublicIP: "203.0.113.1", Invitation: inv},
		4: {Phase: control.OwnedRunning, PublicIP: "203.0.113.1", Invitation: inv},
	} {
		if got := ownedInstallStep(v); got != want {
			t.Errorf("step %+v = %d, want %d", v, got, want)
		}
	}
}
