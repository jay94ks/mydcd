// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

func TestRealBoundaryColdBackupRejectsStoppedContainerReference(t *testing.T) {
	runRealVolumeOwnerBoundary(t, true, true, false, volumeOwnerBackupMount)
}
func verifyBackupMountBoundary(t *testing.T, ctx context.Context, owner *Runtime, root string, p control.Policy, read func() cluster.View, source volumes.NativeReady, preflight control.VolumeBackupSource, cli func(...string)) {
	t.Helper()
	counter := observeBackupIO(owner)
	view := func() control.Volumes {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	wait := func(label string, ready func() bool) {
		t.Helper()
		for !ready() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	name := "sfc-cold-mount-" + source.Owner.Native[len(source.Owner.Native)-24:]
	labels := map[string]string{"org.sfc.owner": engine.Owner(source.Spec.Scope.Cluster, source.Owner.Key), "org.sfc.kind": "container", "org.sfc.test": os.Getenv("SFC_DOCKER_TEST_OWNER")}
	cleanup := func() {
		clean, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		found, err := owner.docker.API.ContainerInspect(clean, name, client.ContainerInspectOptions{})
		if cerrdefs.IsNotFound(err) {
			return
		}
		if err != nil {
			t.Error(err)
			return
		}
		if found.Container.Config.Labels["org.sfc.owner"] != labels["org.sfc.owner"] || found.Container.Config.Labels["org.sfc.test"] != labels["org.sfc.test"] || found.Container.State.Running {
			t.Error("mount reference rollback owner/state mismatch")
			return
		}
		if _, err = owner.docker.API.ContainerRemove(clean, found.Container.ID, client.ContainerRemoveOptions{}); err != nil {
			t.Error(err)
		}
	}
	// Register exact stopped-fixture cleanup before the SDK create request.
	defer cleanup()
	if _, err := owner.docker.API.ContainerInspect(ctx, name, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("mount reference name not initially absent", err)
	}
	created, err := owner.docker.API.ContainerCreate(ctx, client.ContainerCreateOptions{Name: name, Config: &container.Config{Image: preflight.Image, User: "10001:10001", Cmd: []string{"/backend", "--volume-exit=clean"}, Labels: labels}, HostConfig: &container.HostConfig{NetworkMode: "none", Mounts: []mount.Mount{{Type: mount.TypeVolume, Source: source.Owner.Native, Target: "/data", VolumeOptions: &mount.VolumeOptions{NoCopy: true}}}}})
	if err != nil {
		t.Fatal(err)
	}
	found, err := owner.docker.API.ContainerInspect(ctx, created.ID, client.ContainerInspectOptions{})
	if err != nil || found.Container.State.Running || len(found.Container.Mounts) != 1 || found.Container.Mounts[0].Name != source.Owner.Native {
		t.Fatal("actual stopped volume reference absent", err)
	}
	current, _ := view().Volume(source.Spec.Scope)
	change := struct {
		Schema   uint8  `json:"schema"`
		Action   string `json:"action"`
		Expected uint64 `json:"expected"`
		Payload  any    `json:"payload"`
	}{1, "begin-volume-backup", current.Revision(), control.VolumeBackupBegin{Scope: source.Spec.Scope, ID: "mounted-source", MaxBytes: 128 << 10, MaxEntries: 16, Compatibility: preflight.Compatibility}}
	raw, _ := json.Marshal(change)
	path := filepath.Join(root, "mounted-source.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cli("manage", "apply", "--request-id", "mounted-source-begin", "--change", path)
	job := func() control.VolumeBackup {
		t.Helper()
		j, ok := view().Backup(source.Spec.Scope, "mounted-source")
		if !ok {
			t.Fatal("missing accepted original")
		}
		return j
	}
	wait("actual stopped-container source guard", func() bool {
		j := job()
		row, err := owner.backupArtifacts.journal.Read(backupArtifactKey(j.Binding))
		return err == nil && row.State.Pending != nil && row.State.Pending.Phase == reconcile.RecoveryRequired
	})
	if _, err = owner.backupArtifacts.backend.Source(ctx, job().Binding); !errors.Is(err, volumes.ErrActivation) {
		t.Fatal("stopped reference passed native source guard", err)
	}
	if calls, _ := counter.outcome("mounted-source"); calls != 0 {
		t.Fatal("source was exported while referenced", calls)
	}
	cli("volume", "backup", "cancel", "app/data", "mounted-source", "--id", "mounted-source-cancel", "--no-wait")
	if _, err = owner.backupArtifacts.Step(ctx, job()); err == nil {
		t.Fatal("referenced source reader was falsely closed")
	}
	core, _ := view().Volume(source.Spec.Scope)
	if job().Phase != "Cancelling" || len(core.Consumers()) != 1 {
		t.Fatal("mount guard discarded original reader/unknown")
	}
	cleanup()
	wait("original cancel after stopped reference removed", func() bool { return job().Phase == "Cancelled" })
	row, err := owner.backupArtifacts.journal.Read(backupArtifactKey(job().Binding))
	if err != nil || row.State.Pending != nil || row.State.Applied.Present || row.State.LastID != 1 || row.Checkpoint != nil {
		t.Fatal("guard/cancel replaced original operation", err)
	}
	cli("volume", "delete", "app/data", "--id", "mounted-source-delete", "--no-wait")
	wait("exact original source deleted", func() bool { v, ok := view().Volume(source.Spec.Scope); return ok && v.Deleted() })
	t.Log("actual created/stopped container retains exact source Volume reference; actual user signed begin/Raft accepted -> native mount guard refuses Source/Export -> original Apply1/Unknown/shared reader retained; cancel cannot claim closure while reference remains; exact fixture nonforce removal -> original worker cancellation/reader return -> original source delete. No started fixture process or fabricated mount/SDK response")
}
