// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/client"
)

func realNativeVolume(t *testing.T) (context.Context, *engine.Client, NativeSpec) {
	t.Helper()
	tag := os.Getenv("SFC_DOCKER_TEST_OWNER")
	if tag == "" || os.Geteuid() != 0 {
		t.Skip("requires owned Docker prestate and prebuilt test binary with root directory permission")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	s := nativeTestSpec(t)
	s.Scope.Cluster = sha256.Sum256([]byte(tag + "/" + t.Name()))
	s.UID = 10001
	s.GID = 10001
	owner := engine.Owner(s.Scope.Cluster, s.NodeKey)
	c, err := engine.Open(ctx, "unix:///var/run/docker.sock", owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	filter := client.Filters{}.Add("label", "org.sfc.owner="+owner)
	before, err := c.API.VolumeList(ctx, client.VolumeListOptions{Filters: filter})
	if err != nil || len(before.Items) != 0 {
		t.Fatal("owner must initially have zero volumes", err)
	}
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		v, e := c.API.VolumeList(clean, client.VolumeListOptions{Filters: filter})
		if e != nil {
			t.Error(e)
			return
		}
		for _, volume := range v.Items {
			if volume.Labels["org.sfc.owner"] != owner || volume.Labels["org.sfc.kind"] != "volume" {
				t.Error("rollback ownership mismatch")
				continue
			}
			if !t.Failed() {
				t.Error("product retained owned test volume", volume.Name)
			}
			if _, e = c.API.VolumeRemove(clean, volume.Name, client.VolumeRemoveOptions{}); e != nil {
				t.Error("rollback volume", e)
			}
		}
		v, e = c.API.VolumeList(clean, client.VolumeListOptions{Filters: filter})
		if e != nil || len(v.Items) != 0 {
			t.Error("rollback volumes remain", e)
		}
	})
	t.Logf("nativeOwner=%s", owner)
	return ctx, c, s
}

func TestRealBoundaryManagedVolumeRetainAndExplicitDelete(t *testing.T) {
	ctx, c, s := realNativeVolume(t)
	path := filepath.Join(t.TempDir(), "native.db")
	m, err := OpenNative(path, c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	key, err := m.Desired(s, 1, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal("actual named volume preparation", err)
	}
	owner, scope, err := m.Owner(ctx, key)
	if err != nil || scope != s.Scope {
		t.Fatal(err)
	}
	got, err := c.API.VolumeInspect(ctx, owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ready, err := m.Ready(ctx, key, makeFixture(t).a)
	if err != nil || ready.Verify() != nil || ready.Spec != s || ready.Owner != owner {
		t.Fatal("actual node ready fact", err)
	}
	public, err := json.Marshal(ready)
	if err != nil || bytes.Contains(public, []byte(got.Volume.Mountpoint)) {
		t.Fatal("node fact leaked host mountpoint", err)
	}
	if _, err = m.Ready(ctx, key, makeFixture(t).b); err == nil {
		t.Fatal("other node signed native readiness")
	}
	info, err := os.Stat(got.Volume.Mountpoint)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Uid != 10001 || st.Gid != 10001 || st.Mode&07777 != 0750 {
		t.Fatal("native directory permissions differ")
	}
	shared, err := New(makeFixture(t).c, "admin", scope, owner, 4)
	if err != nil || shared.Scope() != scope {
		t.Fatal("actual native identity not consumable by shared core", err)
	}
	marker := filepath.Join(got.Volume.Mountpoint, "retained-marker")
	if err = os.WriteFile(marker, []byte("retained original bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	pin, err := m.Pin(ctx, key, "original-consumer", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	// Close/reopen is a daemon lifetime event, never a Volume delete.
	m, err = OpenNative(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	again, scope, err := m.Owner(ctx, key)
	if err != nil || again != owner || scope != s.Scope {
		t.Fatal("original materialization replaced", err)
	}
	if data, e := os.ReadFile(marker); e != nil || string(data) != "retained original bytes" {
		t.Fatal("retained data lost", e)
	}
	newPin, err := m.Pin(ctx, key, "original-consumer", 1)
	if err != nil || newPin != pin {
		t.Fatal("original local pin lost", err)
	}
	if err = os.Chmod(got.Volume.Mountpoint, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.Owner(ctx, key); !errors.Is(err, ErrNativeVolume) {
		t.Fatal("published permission mutation was adopted", err)
	}
	info, err = os.Stat(got.Volume.Mountpoint)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("inspection repaired published directory", err)
	}
	if err = os.Chmod(got.Volume.Mountpoint, 0750); err != nil {
		t.Fatal("fixture permission rollback", err)
	}
	if _, err = m.Desired(s, 2, 2, 4); err == nil {
		t.Fatal("implicit retained replacement admitted")
	}
	if err = m.DeleteDesired(key, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("live pin did not block real delete", err)
	}
	if err = m.Return(pin); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal("explicit owned native removal", err)
	}
	if gone, e := m.Gone(ctx, key, 2, 1); e != nil || !gone {
		t.Fatal("actual terminal volume closure", e)
	}
	t.Log("actual local named volume -> directory UID/GID10001/mode0750/sync -> product Volume Owner; original DB/ID/pin/data retained; published mutation detected, implicit replacement rejected, live pin blocks deletion, explicit nonforce Remove and Gone")
}

func TestRealBoundaryManagedVolumeForeignIdentity(t *testing.T) {
	ctx, c, s := realNativeVolume(t)
	raw, _ := json.Marshal(s)
	target := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	id, err := c.Identity("volume", NativeKey(s), target)
	if err != nil {
		t.Fatal(err)
	}
	labels := id.Labels
	labels["org.sfc.spec"] = "foreign-spec"
	v, err := c.API.VolumeCreate(ctx, client.VolumeCreateOptions{Name: id.Name, Driver: "local", Labels: labels})
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(v.Volume.Mountpoint, "foreign-marker")
	if err = os.WriteFile(marker, []byte("foreign original"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := OpenNative(filepath.Join(t.TempDir(), "native.db"), c)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	key, err := m.Desired(s, 1, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); !errors.Is(err, engine.ErrOwnership) {
		t.Fatal("foreign native adopted", err)
	}
	record, err := m.View(key)
	if err != nil || record.State.Pending != nil || record.State.Applied.Present || record.State.LastID != 1 {
		t.Fatal("known precreate rejection stranded original operation", err)
	}
	read, err := c.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{})
	if err != nil || read.Volume.Labels["org.sfc.spec"] != "foreign-spec" {
		t.Fatal("foreign labels changed", err)
	}
	if data, e := os.ReadFile(marker); e != nil || string(data) != "foreign original" {
		t.Fatal("foreign bytes changed", e)
	}
	info, err := os.Stat(read.Volume.Mountpoint)
	if err != nil || info.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("foreign permission preparation ran", err)
	}
	// This is fixture-owned foreign data, not a product deletion. Preserve
	// that distinction and remove only its exact original ID.
	if read.Volume.Labels["org.sfc.owner"] != c.Owner {
		t.Fatal("fixture ownership changed")
	}
	if _, err = c.API.VolumeRemove(ctx, id.Name, client.VolumeRemoveOptions{}); err != nil {
		t.Fatal("foreign fixture rollback", err)
	}
	t.Log("actual same-name foreign spec rejected before permissions or data mutation; fixture cleanup is not product Apply completion")
}
