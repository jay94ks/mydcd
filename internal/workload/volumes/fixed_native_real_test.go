// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
	"golang.org/x/sys/unix"
)

func TestNativeFixedVolumeOriginalBindJournalPinsAndDataRetained(t *testing.T) {
	imageRoot, tag, hostNS := os.Getenv("SFC_STORAGE_TEST_ROOT"), os.Getenv("SFC_STORAGE_TEST_OWNER"), os.Getenv("SFC_STORAGE_HOST_MOUNT_NS")
	if imageRoot == "" || tag == "" || hostNS == "" {
		t.Skip("requires S1 owned ext4/private namespace and Docker rollback fixture")
	}
	ns, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil || ns == hostNS || os.Geteuid() != 0 {
		t.Fatal("private privileged mount namespace required", err)
	}
	marker, err := os.ReadFile(filepath.Join(imageRoot, ".sfc-storage-test-owner"))
	if err != nil || string(marker) != tag {
		t.Fatal("exact owned image marker required", err)
	}
	ctx, c, managed := realNativeVolume(t) // actual SDK reads; no named Volume is created by this test
	f := makeFixture(t)
	scope := managed.Scope
	scope.App = ""
	scope.ID = "fixed-data"
	scope.Generation = 3
	source := filepath.Join(imageRoot, "fixed-data")
	if err = os.Mkdir(source, 0750); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(source, 10001, 10001); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(source, "original"), []byte("retained-original"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	book, err := nodestorage.New(scope.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	definition := nodestorage.Definition{Node: "node-a", Key: public(f.a), ID: "disk", Path: imageRoot, Tenants: []string{"tenant"}}
	book, err = book.Add(f.c, "admin", 0, definition)
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	roots, err := nodestorage.OpenRoots(filepath.Join(stateRoot, "roots.db"), scope.Cluster, "node-a", f.a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := roots.Close(); e != nil {
			t.Error("root journal cleanup", e)
		}
	})
	root, _ := book.Root("node-a", "disk")
	if err = roots.Desired(root); err != nil {
		t.Fatal(err)
	}
	if err = roots.Step(ctx, nodestorage.RootNativeKey(root.Reference(scope.Cluster))); err != nil {
		t.Fatal(err)
	}
	fact, err := roots.Fact(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.Observe(fact, public(f.a))
	if err != nil {
		t.Fatal(err)
	}
	root, _ = book.Root("node-a", "disk")
	if err = roots.Desired(root); err != nil {
		t.Fatal(err)
	}
	authorityCalls := 0
	authority := func(_ context.Context, ref nodestorage.Reference) (nodestorage.Root, error) {
		authorityCalls++
		r, ok := book.Root(ref.Node, ref.ID)
		if !ok || r.Reference(scope.Cluster) != ref {
			return r, nodestorage.ErrStorage
		}
		return r, nil
	}
	path := filepath.Join(stateRoot, "fixed", "journal.db")
	m, err := OpenFixed(path, c, roots, scope.Cluster, "node-a", f.a, authority)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	nativePath := filepath.Join(stateRoot, "managed.db")
	native, err := OpenNative(nativePath, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = native.Close() })
	if err = native.AttachFixed(m); err != nil {
		t.Fatal(err)
	}
	selection := nodestorage.FixedSelection{Root: fact, Path: source}
	digest := selection.Digest()
	spec := NativeSpec{Schema: 1, Scope: scope, Node: "node-a", NodeKey: public(f.a), Retain: true, Kind: "node-fixed", FixedDigest: hex.EncodeToString(digest[:])}
	key, err := m.Desired(spec, selection, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup is registered before the first actual bind effect. It returns
	// only this test's original local leases and never deletes source data.
	var live *nodestorage.DirectoryHandle
	var lease NativeLease
	t.Cleanup(func() {
		if live != nil {
			_ = live.Close()
		}
		if lease.Pin.Token != 0 {
			if e := native.Return(lease); e != nil {
				t.Error("fixed rollback pin", e)
			}
		}
		if e := m.DeleteDesired(key, 2, scope.Generation); e == nil {
			if e = m.Step(context.Background(), key); e != nil {
				t.Error("fixed rollback original mount", e)
			}
		} else {
			t.Error(e)
		}
	})
	if _, err = m.Ready(ctx, key); err == nil {
		t.Fatal("desired metadata became native Ready")
	}
	if err = m.ValidateIntent(spec, selection, true); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal("actual source checkpoint/bind", err)
	}
	ready, err := m.Ready(ctx, key)
	if err != nil || ready.Verify() != nil || ready.Generation != 3 || ready.Fixed == nil {
		t.Fatal("actual original fixed Ready", err)
	}
	checkFixedNamespaceChild(t, m.projector.path, ready)
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if err = native.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFixed(path, c, roots, scope.Cluster, "node-a", f.a, authority)
	if err != nil {
		t.Fatal(err)
	}
	m = reopened
	nextNative, openErr := OpenNative(nativePath, c)
	if openErr != nil {
		t.Fatal(openErr)
	}
	native = nextNative
	if err = native.AttachFixed(m); err != nil {
		t.Fatal(err)
	}
	again, err := native.Ready(ctx, key, f.a)
	if err != nil || !bytesEqualNative(ready, again) {
		t.Fatal("same DB changed physical fact", err)
	}
	lease, err = native.Pin(ctx, key, "owned-noncontainer", 3)
	if err != nil {
		t.Fatal(err)
	}
	projection, h, err := m.BindSource(ctx, lease)
	if err != nil {
		t.Fatal(err)
	}
	live = h
	beforeCalls := authorityCalls
	observedPath, observed, err := m.InspectBindSource(ctx, lease)
	if err != nil || observedPath != projection || !observed.Identity().SameData(ready.Fixed.Directory) {
		t.Fatal("original mount observation", err)
	}
	_ = observed.Close()
	if authorityCalls != beforeCalls {
		t.Fatal("original read requested new authority")
	}
	wrongLease := lease
	wrongLease.Pin.Token++
	if _, handle, err := m.InspectBindSource(ctx, wrongLease); err == nil {
		if handle != nil {
			_ = handle.Close()
		}
		t.Fatal("foreign pin observed original mount")
	}
	originalBinding := NativeBindingDigest(ready)
	if actual, bind, err := native.MountSource(key, scope, ready.Owner, 3, hex.EncodeToString(originalBinding[:])); err != nil || !bind || actual != projection {
		t.Fatal("generic consumer router lost original fixed source", err)
	}
	if _, _, err := native.MountSource(key, scope, ready.Owner, 3, hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("same logical native name accepted another full original fact")
	}
	if projection == source || !h.Identity().SameData(ready.Fixed.Directory) {
		t.Fatal("private source not bound to exact original")
	}
	fd, err := unix.Openat(h.FD(), "written-through-bind", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	data := os.NewFile(uintptr(fd), "owned-projection-write")
	if _, err = data.Write([]byte("one-original")); err == nil {
		err = data.Sync()
	}
	err = errors.Join(err, data.Close())
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(source, "written-through-bind")); err != nil || string(raw) != "one-original" {
		t.Fatal("bind wrote another data directory", err)
	}
	if usage, err := native.Usage(ctx, key, UsageLimits{Entries: 16, Depth: 4}); err != nil || !usage.Matches(ready) || usage.Files != 2 {
		t.Fatal("same bounded actual usage scanner/router", err, usage)
	}
	book, err = book.Drain(f.c, "admin", "node-a", "disk", root.Revision)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = book.Root("node-a", "disk")
	if err = roots.Desired(root); err != nil {
		t.Fatal(err)
	}
	if err = roots.Step(ctx, nodestorage.RootNativeKey(root.Reference(scope.Cluster))); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("root retired before source pin", err)
	}
	if err = m.DeleteDesired(key, 2, 3); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("source retired with local consumer", err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	live = nil
	if err = native.Return(lease); err != nil {
		t.Fatal(err)
	}
	lease = NativeLease{}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal("exact non-lazy unregister", err)
	}
	if gone, err := m.Gone(ctx, ready, 2); err != nil || !gone {
		t.Fatal("original closure", gone, err)
	}
	if _, err = os.Stat(projection); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private mount metadata remains", err)
	}
	after, err := os.Stat(source)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Sys().(*syscall.Stat_t).Uid != after.Sys().(*syscall.Stat_t).Uid {
		t.Fatal("source inode/permissions changed", err)
	}
	if raw, err := os.ReadFile(filepath.Join(source, "original")); err != nil || string(raw) != "retained-original" {
		t.Fatal("unregister deleted original data", err)
	}
	if err = roots.Step(ctx, nodestorage.RootNativeKey(root.Reference(scope.Cluster))); err != nil {
		t.Fatal(err)
	}
	if proof, err := roots.Closed(root); err != nil || proof.Verify() != nil {
		t.Fatal("root final closure", err)
	}
	t.Log("actual owned ext4 source/checkpoint/private bind, same DB original fact, held native consumer/FD write, Drain and pin gates, non-lazy unregister/root return, exact original inode/mode/UID/data retained; no container bind/SFCP/Raft or cross-boot success claim")
}

type fixedNamespaceProbe struct {
	Projection string
	Ready      NativeReady
}

func checkFixedNamespaceChild(t *testing.T, projection string, ready NativeReady) {
	t.Helper()
	raw, err := json.Marshal(fixedNamespaceProbe{Projection: projection, Ready: ready})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "namespace-probe.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.v", "-test.run=^TestNativeFixedNamespaceChild$")
	cmd.Env = append(os.Environ(), "SFC_FIXED_NAMESPACE_PROBE="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("same-boot actual namespace fence: %v %s", err, out)
	} else {
		t.Log(string(out))
	}
}

// Called only by the owned privileged parent; it never modifies the original
// projection/journal or treats an inherited mount in a new namespace as Gone.
func TestNativeFixedNamespaceChild(t *testing.T) {
	path := os.Getenv("SFC_FIXED_NAMESPACE_PROBE")
	if path == "" {
		t.Skip("requires owned fixed native parent")
	}
	var q fixedNamespaceProbe
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &q) != nil || q.Ready.Verify() != nil || q.Ready.Fixed == nil {
		t.Fatal("original probe input", err)
	}
	boot, ns, err := nodestorage.NativeContext()
	if err != nil || boot != q.Ready.Fixed.Directory.Boot || ns == q.Ready.Fixed.Directory.Namespace {
		t.Fatal("requires real different namespace in same boot", err)
	}
	p, err := openPrivateProjection(q.Projection, makeFixture(t).a)
	if err != nil {
		t.Fatal(err)
	}
	defer p.file.Close()
	h, err := nodestorage.OpenDirectory(p.sourcePath(q.Ready.Spec))
	if err != nil || !h.Identity().SameData(q.Ready.Fixed.Directory) {
		t.Fatal("inherited original mount disappeared", err)
	}
	defer h.Close()
	slot, err := openProjectionChild(int(p.file.Fd()), FixedNativeName(q.Ready.Spec.Scope))
	if err != nil {
		t.Fatal(err)
	}
	defer slot.Close()
	if err = p.pinProjectionEpoch(slot, projectionSpec(q.Ready.Spec), true); err == nil {
		t.Fatal("new namespace adopted existing same-boot owner")
	}
	if err = p.recoverStaging(q.Ready.Spec); err == nil {
		t.Fatal("new namespace reclaimed a live original projection")
	}
	t.Log("actual CLONE_NEWNS inherited original mount; same-boot adoption and closure rejected without changing original owner")
}

func bytesEqualNative(a, b NativeReady) bool {
	return string(NativeReadyBytes(a)) == string(NativeReadyBytes(b)) && string(a.Signature) == string(b.Signature)
}
