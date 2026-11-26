// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestRegistryVolumeNamespacePreservesOldBytesAndSeparatesAppAndFixed(t *testing.T) {
	f := makeFixture(t)
	app := f.s.Scope()
	// Marshal the original schema-1 field order independently of the new field.
	old, _ := json.Marshal(struct {
		Cluster         [32]byte
		Tenant, App, ID string
		Generation      uint64
	}{app.Cluster, app.Tenant, app.App, app.ID, app.Generation})
	current, _ := json.Marshal(app)
	if !bytes.Equal(old, current) {
		t.Fatal("old signed scope bytes changed")
	}
	fixed := app
	fixed.App = ""
	reg := fixed
	reg.Registry = app.App
	if !validScope(reg) || reg.TenantManaged() || !reg.RegistryManaged() || reg.Key() == app.Key() || reg.Key() == fixed.Key() || FixedNativeKey(reg) != "" {
		t.Fatal("registry namespace aliases app/fixed")
	}
	s, err := New(f.c, "admin", reg, f.source, 3)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(raw)
	if err != nil || restored.Scope() != reg || restored.Fixed() {
		t.Fatal("registry became fixed during codec", err)
	}
	spec := NativeSpec{Schema: 1, Scope: reg, Node: f.source.Node, NodeKey: f.source.Key, Materialization: "initial", UID: 10001, GID: 10001, Mode: 0700, Retain: true}
	if spec.Validate() != nil || NativeKey(spec) != "volume/"+reg.Key()+"/initial" {
		t.Fatal("registry native identity invalid")
	}
	reg.App = "app"
	if validScope(reg) {
		t.Fatal("mixed app/registry scope")
	}
	if _, err = NewFixed(f.c, "admin", spec.Scope, f.source, 3); err == nil {
		t.Fatal("registry accepted as fixed")
	}
}
