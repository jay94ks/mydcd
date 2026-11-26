// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/moby/moby/client"
)

func TestRealBoundaryManagedAppVolumeDeleteAfterDown(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppVolumeDelete, true, true)
}

func verifyManagedAppVolumeDelete(t *testing.T, ctx context.Context, r *Runtime, root string, p control.Policy, read func() cluster.View, wait func(string, func() bool)) {
	t.Helper()
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	original, ok := registry.Native("tenant", "app", "data")
	if !ok {
		t.Fatal("retained original app volume missing")
	}
	cmd := nativeCLICmd(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), "--tenant", "tenant", "volume", "delete", "app/data", "--id", "delete-retained-app", "--no-wait")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("retained app volume CLI delete", err, string(out))
	}
	wait("retained app original native Gone and shared tombstone", func() bool {
		v, err := p.Volumes(read().State)
		c, ok := v.Volume(original.Spec.Scope)
		return err == nil && ok && c.Deleted()
	})
	if _, err := r.docker.API.VolumeInspect(ctx, original.Owner.Native, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("app retained native still present", err)
	}
	encoded, err := state.Encode(read().State)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil || p.Validate(restored, restored, state.Command{}) != nil {
		t.Fatal("app history lost after explicit data deletion", err)
	}
	apps, err := p.Apps(restored)
	if err != nil || len(apps.Bindings().Live()) != 0 {
		t.Fatal("original closed app binding recreated", err)
	}
	t.Log("actual compose app/Secret/Volume/Task -> down/whole refs returned/retain -> dedicated CLI deletion under revoked placement -> original native Gone/shared tombstone; original app history and Snapshot remain valid")
}
