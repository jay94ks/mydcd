// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

func TestRealBoundaryManagedAppConsumesCLICreatedVolume(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppPrecreatedVolume, true, true)
}

func prepareManagedPrecreatedVolume(t *testing.T, ctx context.Context, owner **Runtime, root string, user userauth.Client, peer sfcp.Peer, p control.Policy, read func() cluster.View, capacity ...uint64) func() {
	t.Helper()
	home, profile := filepath.Join(root, "precreate-home"), filepath.Join(root, "precreate.yaml")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", user.Cluster, peer.Key, peer.Endpoint)
	if err := os.WriteFile(profile, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) {
		t.Helper()
		cmd := nativeCLICmd(ctx, os.Getenv("SFC_TEST_CLI"), home, profile, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal("precreate CLI", args, err, string(out))
		}
	}
	cli("login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	args := []string{"--tenant", "tenant", "volume", "create", "app/data", "--node", "node-a", "--uid", "10001", "--gid", "10001", "--id", "precreate-data", "--no-wait"}
	if len(capacity) == 1 {
		args = append(args, "--size", fmt.Sprint(capacity[0]))
	}
	cli(args...)
	var original volumes.NativeReady
	for {
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		if ready, ok := v.Native("tenant", "app", "data"); ok {
			original = ready
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("CLI creation did not publish original Ready", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	key := volumes.NativeKey(original.Spec)
	before, err := (*owner).nativeVolumes.View(key)
	if err != nil || before.State.LastID != 1 {
		t.Fatal("original native creation journal", err)
	}
	disk, err := (*owner).docker.API.VolumeInspect(ctx, original.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(disk.Volume.Mountpoint, "prior-row")
	if err := os.WriteFile(path, []byte("original precreated app data\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, int(original.Spec.UID), int(original.Spec.GID)); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		v, err := p.Volumes(read().State)
		ready, ok := v.Native("tenant", "app", "data")
		if err != nil || !ok || ready.Spec != original.Spec || ready.Generation != original.Generation || ready.Owner != original.Owner {
			t.Fatal("app replaced precreated logical/native identity", err)
		}
		after, err := (*owner).nativeVolumes.View(key)
		if err != nil || after.State.LastID != before.State.LastID || after.State.Applied != before.State.Applied {
			t.Fatal("app created another native generation", err)
		}
		if row, err := os.ReadFile(path); err != nil || string(row) != "original precreated app data\n" {
			t.Fatal("precreated data lost through app lifecycle", err)
		}
		t.Log("actual volume create CLI/Ready -> same native Apply1/data -> actual compose Task/Secret mount -> down/Snapshot/same DB/retain; existing data and identity preserved")
	}
}
