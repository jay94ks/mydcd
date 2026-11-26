// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Actual SDK over an owned fake Engine UDS and real private directory. This
// proves the new directory adapter, not actual Engine/native Volume success.
func TestEmbeddedVolumeDataRequiresOriginalNativeLeaseAndHeldDirectory(t *testing.T) {
	ctx := context.Background()
	spec := nativeTestSpec(t)
	spec.Scope.App = ""
	spec.Scope.Registry = "private"
	f := nativeSDK(t, spec)
	m, err := OpenNative(filepath.Join(t.TempDir(), "native.db"), f.client)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	key, err := m.Desired(spec, 1, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	lease, err := m.Pin(ctx, key, "registry/tenant/private/1", 1)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := m.OpenDataDirectory(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if dir.Path() != f.data || dir.Check() != nil {
		t.Fatal("not the original inspected data root")
	}
	if err = dir.Root.Mkdir("registry", 0700); err != nil {
		t.Fatal(err)
	}
	file, err := dir.Root.OpenFile("registry/marker", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	wrong := lease
	wrong.Pin.Token++
	if _, err = m.OpenDataDirectory(ctx, wrong); err == nil {
		t.Fatal("borrowed another lease")
	}
	if err = dir.Close(); err != nil {
		t.Fatal(err)
	}
	if err = dir.Check(); err == nil {
		t.Fatal("closed directory usable")
	}
	if err = m.Return(lease); err != nil {
		t.Fatal(err)
	}
	if _, err = m.OpenDataDirectory(ctx, lease); err == nil {
		t.Fatal("returned lease reopened data")
	}
	data, err := os.ReadFile(filepath.Join(f.data, "registry", "marker"))
	if err != nil || string(data) != "original" {
		t.Fatal("return removed data", err)
	}
}
