// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRQ10NetworkTargetKeepsIngressFieldsAndLegacyJSON(t *testing.T) {
	target := Target{Gateway: "external", RouteID: "route-one", Host: "shop.example", Prefix: "/api", Tenant: "tenant", App: "shop", Service: "api", Deployment: "release", Task: "task-one", Native: "container-one", Node: "node-a", Generation: 2, Revision: 3}
	// The previous schema1 field order is retained when Network is absent.
	type priorTarget struct {
		Gateway, RouteID, Host, Prefix   string `json:",omitempty"`
		Tenant, App, Service, Deployment string `json:",omitempty"`
		Task, Native, Node               string `json:",omitempty"`
		Generation, Revision             uint64 `json:",omitempty"`
		FilesystemID, PairID             string `json:",omitempty"`
		Term                             uint64 `json:",omitempty"`
	}
	prior := priorTarget{Gateway: target.Gateway, RouteID: target.RouteID, Host: target.Host, Prefix: target.Prefix, Tenant: target.Tenant, App: target.App, Service: target.Service, Deployment: target.Deployment, Task: target.Task, Native: target.Native, Node: target.Node, Generation: target.Generation, Revision: target.Revision}
	before, err := json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(target)
	if err != nil || !bytes.Equal(before, after) || !target.Valid() {
		t.Fatal("legacy ingress event target changed", err)
	}
	target.Network = "services"
	raw, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	var restored Target
	if json.Unmarshal(raw, &restored) != nil || restored != target || !restored.Valid() {
		t.Fatal("network/ingress target fields lost")
	}
	for _, change := range []func(*Target){func(v *Target) { v.Network = "../services" }, func(v *Target) { v.Tenant = "" }, func(v *Target) { v.Gateway = "unknown" }, func(v *Target) { v.Host = "bad\nvalue" }} {
		bad := target
		change(&bad)
		if bad.Valid() {
			t.Fatal("merged target skipped an existing/new validator")
		}
	}
}
