// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

func TestRealBoundaryManagedVolumeUsage(t *testing.T) {
	ctx, c, spec := realNativeVolume(t)
	db := filepath.Join(t.TempDir(), "native.db")
	m, err := OpenNative(db, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	key, err := m.Desired(spec, 1, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	owner, _, err := m.Owner(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	// Only the fixture may access the inspected path. The product method takes
	// an original journal key and never accepts a user-supplied filesystem root.
	disk, err := c.API.VolumeInspect(ctx, owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	logical := usageFiles(t, disk.Volume.Mountpoint)
	before, err := m.View(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Usage(ctx, key, UsageLimits{Entries: 8, Depth: 2})
	if err != nil || got.Scope != spec.Scope || got.Owner != owner || got.Generation != 1 || got.LogicalBytes != logical || got.Entries != 5 || got.Files != 2 || got.Directories != 2 || got.QuotaMode != "observe" || got.Snapshot || got.FilesystemAvailableBytes > got.FilesystemBytes {
		t.Fatal("actual local-driver usage", got, err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), disk.Volume.Mountpoint) || strings.Contains(string(raw), "original row") {
		t.Fatal("native usage exposed path/data")
	}
	after, err := m.View(key)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("read-only usage mutated journal/pins", err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = OpenNative(db, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.DeleteDesired(key, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	if gone, err := m.Gone(ctx, key, 2, 1); err != nil || !gone {
		t.Fatal("original explicit deletion", err)
	}
	t.Log("actual original local-driver root: sparse/hardlink unique accounting, observe-only filesystem capacity, private paths/data absent from public result, unchanged native journal/pins, explicit nonforce deletion and original Gone")
}
