// SPDX-License-Identifier: Apache-2.0

package nodestorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"golang.org/x/sys/unix"
)

// The S1 final native runner must supply a private mount namespace and its own
// freshly created ext4 image/root. This test never formats/mounts user media.
func TestNativeStorageDirectoryIdentityReplacementAndMountLoss(t *testing.T) {
	root, owner, hostNS := os.Getenv("SFC_STORAGE_TEST_ROOT"), os.Getenv("SFC_STORAGE_TEST_OWNER"), os.Getenv("SFC_STORAGE_HOST_MOUNT_NS")
	if root == "" || owner == "" || hostNS == "" {
		t.Skip("requires S1 owned ext4/private mount namespace rollback fixture")
	}
	ns, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || ns == hostNS || os.Geteuid() != 0 {
		t.Fatal("private privileged test namespace required", err)
	}
	marker, err := os.ReadFile(filepath.Join(root, ".sfc-storage-test-owner"))
	if err != nil || string(marker) != owner {
		t.Fatal("owned test filesystem marker required", err)
	}
	data := filepath.Join(root, "data")
	if err = os.Mkdir(data, 0750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(data, "original"), []byte("original-data"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(data)
	if err != nil {
		t.Fatal(err)
	}
	r, err := OpenDirectory(root)
	if err != nil {
		t.Fatal("actual stable root identity", err)
	}
	defer r.Close()
	d, err := OpenWithin(r, data)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	saved := d.Identity()
	if saved.UUID != r.Identity().UUID || saved.MountID != r.Identity().MountID {
		t.Fatal("directory/source mount mismatch")
	}
	// Exercise the actual product A2 registration/read-back against this
	// SAME owned filesystem. No fake Directory or independent manager is
	// substituted for native identity, durable pins or same-DB reopen.
	fixture := newRootFixture(t)
	fixture.definition.Path = root
	fixture.book, err = fixture.book.Add(fixture.users, "admin", 0, fixture.definition)
	if err != nil {
		t.Fatal(err)
	}
	declared, _ := fixture.book.Root("node-a", "hdd")
	db := filepath.Join(t.TempDir(), "roots.db")
	m, err := OpenRoots(db, fixture.book.Cluster(), "node-a", fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if err = m.Desired(declared); err != nil {
		t.Fatal(err)
	}
	key := RootNativeKey(declared.Reference(fixture.book.Cluster()))
	if _, err = m.Fact(context.Background(), declared); err == nil {
		t.Fatal("desired metadata is not native Ready")
	}
	if err = m.Step(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	fact, err := m.Fact(context.Background(), declared)
	if err != nil || fact.Verify() != nil || !fact.Directory.SameMount(r.Identity()) {
		t.Fatal("actual durable root fact", err)
	}
	fixture.book, err = fixture.book.Observe(fact, fixture.definition.Key)
	if err != nil {
		t.Fatal(err)
	}
	declared, _ = fixture.book.Root("node-a", "hdd")
	if err = m.Desired(declared); err != nil {
		t.Fatal(err)
	}
	beforeSettled, err := m.View(key)
	if err != nil {
		t.Fatal(err)
	}
	if settled, err := m.Settled(context.Background(), declared); err != nil || !settled {
		t.Fatal("actual registered root no-op observation", settled, err)
	}
	afterSettled, err := m.View(key)
	beforeBytes, _ := json.Marshal(beforeSettled)
	afterBytes, _ := json.Marshal(afterSettled)
	if err != nil || !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatal("settled read changed original journal", err)
	}
	space, err := m.Space(context.Background(), declared)
	if err != nil || space.Root != declared.Reference(fixture.book.Cluster()) || space.Total == 0 || space.Available > space.Free || space.Free > space.Total {
		t.Fatal("actual original filesystem space", err)
	}
	pools, err := fixture.book.Capacities([]Space{space})
	if err != nil || len(pools) != 1 || pools[0].Roots != 1 || pools[0].Total != space.Total {
		t.Fatal("actual root space aggregation", err)
	}
	pin, err := m.Pin(context.Background(), declared, "fixed-registration")
	if err != nil || pin.Directory == nil {
		t.Fatal("actual original root pin", err)
	}
	defer pin.Directory.Close()
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedManager, err := OpenRoots(db, fixture.book.Cluster(), "node-a", fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	m = reopenedManager
	if reopened, err := m.Fact(context.Background(), declared); err != nil || !reopened.Directory.SameMount(fact.Directory) {
		t.Fatal("same DB/native root identity", err)
	}
	if err = os.Symlink(data, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if h, err := OpenWithin(r, filepath.Join(root, "alias")); err == nil {
		_ = h.Close()
		t.Fatal("symlink admitted")
	}
	if h, err := OpenWithin(r, filepath.Join(root, "missing")); err == nil {
		_ = h.Close()
		t.Fatal("missing directory created/adopted")
	}
	after, err := os.Stat(data)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatal("identity query changed original directory", err)
	}
	if err = os.Rename(data, filepath.Join(root, "held-original")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(data, 0750); err != nil {
		t.Fatal(err)
	}
	replacement, err := OpenWithin(r, data)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Identity().MatchesOriginal(saved) {
		_ = replacement.Close()
		t.Fatal("same pathname replacement adopted original identity")
	}
	_ = replacement.Close()
	raw, err := os.ReadFile(filepath.Join(root, "held-original", "original"))
	if err != nil || string(raw) != "original-data" {
		t.Fatal("original data changed", err)
	}
	if err = unix.Unmount(root, unix.MNT_DETACH); err != nil {
		t.Fatal("owned image detach", err)
	}
	if _, err = m.Fact(context.Background(), declared); err == nil {
		t.Fatal("manager adopted underlying root after mount loss")
	}
	if settled, err := m.Settled(context.Background(), declared); err == nil || settled {
		t.Fatal("settled journal hid original mount loss", settled, err)
	}
	if _, err = m.Space(context.Background(), declared); err == nil {
		t.Fatal("mount loss became zero/underlying space")
	}
	retained, err := m.View(key)
	if err != nil || len(retained.Consumers) != 1 {
		t.Fatal("mount loss erased durable dependency", err)
	}
	fixture.book, err = fixture.book.Drain(fixture.users, "admin", "node-a", "hdd", declared.Revision)
	if err != nil {
		t.Fatal(err)
	}
	declared, _ = fixture.book.Root("node-a", "hdd")
	if err = m.Desired(declared); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(context.Background(), key); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("root remove passed live pin", err)
	}
	if _, err = m.Closed(declared); err == nil {
		t.Fatal("live root claimed closure")
	}
	if _, err = m.Pin(context.Background(), declared, "late-registration"); err == nil {
		t.Fatal("Drain admitted new root pin")
	}
	if err = pin.Directory.Close(); err != nil {
		t.Fatal(err)
	}
	if err = m.Return(pin); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	closed, err := m.Closed(declared)
	if err != nil || closed.Verify() != nil {
		t.Fatal("exact original registration closure", err)
	}
	fixture.book, err = fixture.book.ObserveClosed(closed, fixture.definition.Key)
	if err != nil {
		t.Fatal(err)
	}
	declared, _ = fixture.book.Root("node-a", "hdd")
	if err = m.Desired(declared); err != nil {
		t.Fatal("closure observation rewrote/lost local tombstone", err)
	}
	if _, err = m.Closed(declared); err != nil {
		t.Fatal("same original closure after shared observation", err)
	}
	underlying, err := OpenDirectory(root)
	if err == nil {
		defer underlying.Close()
		if underlying.Identity().MatchesOriginal(r.Identity()) {
			t.Fatal("underlying empty directory adopted as mounted original")
		}
	}
	if !d.Identity().SameData(saved) {
		t.Fatal("original retained FD identity changed")
	}
	fd, err := unix.Openat(d.FD(), "original", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("original retained inode no longer reads original data", err)
	}
	f := os.NewFile(uintptr(fd), "original-pinned-data")
	raw, err = io.ReadAll(io.LimitReader(f, 64))
	_ = f.Close()
	if err != nil || string(raw) != "original-data" {
		t.Fatal("retained descriptor followed replacement/underlying directory", err)
	}
	t.Log("actual ext4 UUID/export handle; no-follow/preexisting source, replacement refused, retained original data and detached mount not replaced by underlying directory")
}
