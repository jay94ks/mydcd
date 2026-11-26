// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestRealBoundaryManagedNativeMissingAndForeignIdentity(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppNativeIdentityFaults, true, true, false, true)
}

func verifyManagedNativeIdentityFaults(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View) map[string]any {
	t.Helper()
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	before, err := r.workload.View(key)
	if err != nil || !before.State.Applied.Present || before.State.Pending != nil {
		t.Fatal("original applied Task", err)
	}
	spec, err := workload.DecodeContainer(before.State.Applied.Spec)
	if err != nil || spec.Process == nil || spec.Inputs == nil || len(spec.Volumes) != 1 {
		t.Fatal("original combined inputs/Volume", err)
	}
	id, err := r.docker.Identity("container", key, before.State.Applied)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.docker.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	if err != nil || !id.Matches(got.Container.Name, got.Container.Config.Labels) || !got.Container.State.Running {
		t.Fatal("original running physical identity", err)
	}
	originalID, held := got.Container.ID, id.Name+"-held"
	bridge, err := r.network.View(spec.Bridge)
	if err != nil {
		t.Fatal(err)
	}
	consumer := "workload/" + id.Name
	projection, err := r.projections.InspectInputs(ctx, *spec.Inputs, consumer, key, before.State.Applied.Generation)
	if err != nil {
		t.Fatal(err)
	}
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	ref := deployment.ObjectRef{Key: key, Generation: before.State.Applied.Generation, Revision: before.State.Desired.Revision}
	// The original stage result is the authority for the public source revision.
	execution, _ := apps.Execution("tenant", "app")
	stage, _ := execution.Stage(key)
	ref.Revision = stage.Result.Revision
	binding, ok := apps.Binding(ref)
	if !ok {
		t.Fatal("original shared Binding")
	}
	volumes, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, _ := volumes.Volume(spec.Volumes[0].Scope)
	volumeConsumers := core.Consumers()
	foreignID := ""
	restored := false
	rollback := func() {
		if restored {
			return
		}
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if foreignID != "" {
			x, err := r.docker.API.ContainerInspect(clean, foreignID, client.ContainerInspectOptions{})
			if err != nil || strings.TrimPrefix(x.Container.Name, "/") != id.Name || x.Container.Config == nil || x.Container.Config.Labels["org.mydc.owner"] != r.owner || x.Container.Config.Labels["org.mydc.spec"] != "foreign-fixture" || x.Container.State.Running {
				t.Error("foreign fixture rollback identity", err)
				return
			}
			if _, err := r.docker.API.ContainerRemove(clean, foreignID, client.ContainerRemoveOptions{}); err != nil {
				t.Error(err)
				return
			}
			foreignID = ""
		}
		x, err := r.docker.API.ContainerInspect(clean, originalID, client.ContainerInspectOptions{})
		if err != nil || x.Container.Config == nil || !id.Matches(id.Name, x.Container.Config.Labels) {
			t.Error("original ID/labels before rename restore", err)
			return
		}
		name := strings.TrimPrefix(x.Container.Name, "/")
		if name == held {
			if _, err := r.docker.API.ContainerRename(clean, originalID, client.ContainerRenameOptions{NewName: id.Name}); err != nil {
				t.Error(err)
				return
			}
		} else if name != id.Name {
			t.Error("original rollback name mismatch")
			return
		}
		restored = true
	}
	// Registered before the first rename. On normal return this closes before
	// the fixture seals Vault/restarts Runtime; on failure the original closes
	// before the fixture's native journals and private files are cleaned.
	defer rollback()
	unchanged := func(label string) {
		t.Helper()
		after, err := r.workload.View(key)
		if err != nil || !reflect.DeepEqual(after, before) {
			t.Fatal(label, "changed original local A2", err)
		}
		b, err := r.network.View(spec.Bridge)
		if err != nil || !reflect.DeepEqual(b.Consumers, bridge.Consumers) {
			t.Fatal(label, "changed original Bridge consumers", err)
		}
		lease, err := r.projections.InspectInputs(ctx, *spec.Inputs, consumer, key, before.State.Applied.Generation)
		if err != nil || !reflect.DeepEqual(lease, projection) {
			t.Fatal(label, "changed original projection pin/files", err)
		}
		current, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		bnd, ok := current.Binding(ref)
		if !ok || bnd.Digest() != binding.Digest() {
			t.Fatal(label, "changed original shared Binding")
		}
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		vc, _ := v.Volume(spec.Volumes[0].Scope)
		if !reflect.DeepEqual(vc.Consumers(), volumeConsumers) {
			t.Fatal(label, "released live Volume writer")
		}
		x, err := r.docker.API.ContainerInspect(ctx, originalID, client.ContainerInspectOptions{})
		if err != nil || !x.Container.State.Running {
			t.Fatal(label, "original process was stopped/removed", err)
		}
	}
	if _, err := r.docker.API.ContainerRename(ctx, originalID, client.ContainerRenameOptions{NewName: held}); err != nil {
		t.Fatal(err)
	}
	if err := r.workload.Step(ctx, key); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("missing original lookup must remain Unknown", err)
	}
	if _, err := r.docker.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("original Task automatically recreated", err)
	}
	unchanged("missing")
	labels := maps.Clone(id.Labels)
	labels["org.mydc.spec"] = "foreign-fixture"
	foreign, err := r.docker.API.ContainerCreate(ctx, client.ContainerCreateOptions{Name: id.Name, Config: &container.Config{Image: spec.Process.ImageID, Labels: labels, Cmd: []string{"/backend"}}, HostConfig: &container.HostConfig{NetworkMode: "none", ReadonlyRootfs: true, Tmpfs: map[string]string{"/data": "size=4096"}}})
	if err != nil {
		t.Fatal("owned foreign fixture Create", err)
	}
	foreignID = foreign.ID
	if err := r.workload.Step(ctx, key); !errors.Is(err, engine.ErrOwnership) {
		t.Fatal("same-name foreign spec was adopted", err)
	}
	unchanged("foreign")
	x, err := r.docker.API.ContainerInspect(ctx, foreignID, client.ContainerInspectOptions{})
	if err != nil || x.Container.State.Running || x.Container.Config.Labels["org.mydc.spec"] != "foreign-fixture" {
		t.Fatal("product changed/started foreign fixture", err)
	}
	for _, m := range x.Container.Mounts {
		if m.Type == "volume" {
			t.Fatal("foreign fixture created anonymous volume")
		}
	}
	foreignProof := foreignID
	rollback()
	if !restored {
		t.Fatal("original native name not restored")
	}
	if err := r.workload.Step(ctx, key); err != nil {
		t.Fatal("same original Task read-back after fixture restore", err)
	}
	status, err := r.workload.Status(ctx, key)
	if err != nil || status.NativeID != originalID || !status.Running {
		t.Fatal("original identity recovery", err)
	}
	unchanged("restored")
	t.Log("actual CLI/remote Secret/Volume Task: missing exact original name remains Unknown without Create; real same-name foreign-spec object is neither adopted/started/deleted nor used to release refs; original running ID/A2/Binding/private pin/Bridge/writer remain; owned foreign fixture removed and original name restored before same DB/actual CLI down")
	return map[string]any{"original_id": originalID, "foreign_fixture_id": foreignProof, "missing_recreated": false, "foreign_adopted": false, "original_apply_id": before.State.LastID, "original_binding": binding.Digest(), "original_writer_consumers": len(volumeConsumers), "restored_original_id": status.NativeID}
}
