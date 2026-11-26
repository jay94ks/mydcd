// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

type fixedBoundaryFault struct {
	fixedDriver
	point string
}

func (d fixedBoundaryFault) ExecuteCheckpoint(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	if d.point == "before-checkpoint" {
		return d.fixedDriver.ExecuteCheckpoint(ctx, key, op, func([]byte) error { return syscall.EIO })
	}
	if d.point == "after-checkpoint" {
		return d.fixedDriver.ExecuteCheckpoint(ctx, key, op, func(raw []byte) error {
			if err := save(raw); err != nil {
				return err
			}
			return syscall.EIO
		})
	}
	out, err := d.fixedDriver.ExecuteCheckpoint(ctx, key, op, save)
	if err == nil && out == reconcile.EffectApplied {
		return reconcile.EffectUnknown, syscall.EIO
	}
	return out, err
}

func TestNativeFixedVolumeCheckpointAndBindUnknownKeepOriginalOperation(t *testing.T) {
	for _, point := range []string{"before-checkpoint", "after-checkpoint", "after-bind"} {
		t.Run(point, func(t *testing.T) {
			image, tag, hostNS := os.Getenv("MYDC_STORAGE_TEST_ROOT"), os.Getenv("MYDC_STORAGE_TEST_OWNER"), os.Getenv("MYDC_STORAGE_HOST_MOUNT_NS")
			if image == "" || tag == "" || hostNS == "" {
				t.Skip("requires S1 owned ext4/private namespace and Docker fixture")
			}
			ns, err := os.Readlink("/proc/self/ns/mnt")
			if err != nil || ns == hostNS {
				t.Fatal("private namespace required", err)
			}
			marker, err := os.ReadFile(filepath.Join(image, ".mydc-storage-test-owner"))
			if err != nil || string(marker) != tag {
				t.Fatal("owned image marker required", err)
			}
			ctx, c, managed := realNativeVolume(t)
			fixture := makeFixture(t)
			base, err := os.MkdirTemp(image, "fixed-fault-")
			if err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(base, "data")
			if err = os.Mkdir(source, 0750); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(source, "original"), []byte("exact-original"), 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(source)
			if err != nil {
				t.Fatal(err)
			}
			scope := managed.Scope
			scope.App = ""
			scope.ID = "fault-data"
			scope.Generation = 3
			book, err := nodestorage.New(scope.Cluster)
			if err != nil {
				t.Fatal(err)
			}
			book, err = book.Add(fixture.c, "admin", 0, nodestorage.Definition{Node: "node-a", Key: public(fixture.a), ID: "disk", Path: base, Tenants: []string{"tenant"}, MaxVolumes: 2})
			if err != nil {
				t.Fatal(err)
			}
			state := t.TempDir()
			roots, err := nodestorage.OpenRoots(filepath.Join(state, "roots.db"), scope.Cluster, "node-a", fixture.a)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = roots.Close() })
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
			book, err = book.Observe(fact, public(fixture.a))
			if err != nil {
				t.Fatal(err)
			}
			root, _ = book.Root("node-a", "disk")
			if err = roots.Desired(root); err != nil {
				t.Fatal(err)
			}
			authority := func(_ context.Context, ref nodestorage.Reference) (nodestorage.Root, error) {
				current, ok := book.Root(ref.Node, ref.ID)
				if !ok || current.Reference(scope.Cluster) != ref {
					return current, nodestorage.ErrStorage
				}
				return current, nil
			}
			path := filepath.Join(state, "fixed", "journal.db")
			m, err := OpenFixed(path, c, roots, scope.Cluster, "node-a", fixture.a, authority)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Close() })
			selection := nodestorage.FixedSelection{Root: fact, Path: source}
			digest := selection.Digest()
			spec := NativeSpec{Schema: 1, Scope: scope, Node: "node-a", NodeKey: public(fixture.a), Retain: true, Kind: "node-fixed", FixedDigest: hex.EncodeToString(digest[:])}
			key, err := m.Desired(spec, selection, 1, 3)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := m.DeleteDesired(key, 2, scope.Generation); err == nil {
					if err = m.Step(context.Background(), key); err != nil {
						t.Error("fixed fault original rollback", err)
					}
				} else {
					t.Error(err)
				}
			})
			err = m.journal.Step(ctx, key, fixedBoundaryFault{fixedDriver{m: m}, point})
			if !errors.Is(err, syscall.EIO) {
				t.Fatal("intended native checkpoint/bind fault not reached", err)
			}
			uncertain, err := m.View(key)
			if err != nil || uncertain.State.Pending == nil || uncertain.State.LastID != 1 || (uncertain.Checkpoint != nil) != (point != "before-checkpoint") {
				t.Fatal("fault lost original pending operation/checkpoint", err)
			}
			if err = m.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenFixed(path, c, roots, scope.Cluster, "node-a", fixture.a, authority)
			if err != nil {
				t.Fatal(err)
			}
			m = reopened
			if point == "before-checkpoint" {
				// The producer never dispatched a mount without a synced source
				// checkpoint. Retire the SAME original Apply and its private stage.
				if err = m.DeleteDesired(key, 2, scope.Generation); err != nil {
					t.Fatal(err)
				}
				if err = m.Step(ctx, key); err != nil {
					t.Fatal("pre-mount original retirement", err)
				}
			} else {
				if err = m.Step(ctx, key); err != nil {
					t.Fatal("same original checkpoint/mount recovery", err)
				}
				ready, err := m.Ready(ctx, key)
				if err != nil || ready.Verify() != nil || ready.Fixed == nil {
					t.Fatal("original recovery readiness", err)
				}
				row, err := m.View(key)
				if err != nil || row.State.LastID != 1 || row.State.Pending != nil || !row.State.Applied.Present {
					t.Fatal("Unknown recovery invented a new Apply", err)
				}
				if err = m.DeleteDesired(key, 2, scope.Generation); err != nil {
					t.Fatal(err)
				}
				if err = m.Step(ctx, key); err != nil {
					t.Fatal(err)
				}
			}
			if closed, err := m.Closed(ctx, spec, selection, 2); err != nil || !closed {
				t.Fatal("original source/projection/root pin not settled", err)
			}
			after, err := os.Stat(source)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("source directory replaced", err)
			}
			data, err := os.ReadFile(filepath.Join(source, "original"))
			if err != nil || string(data) != "exact-original" {
				t.Fatal("fault recovery deleted source data", err)
			}
		})
	}
}
