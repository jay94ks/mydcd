// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// Shared Book rejection and actual SDK failure are separate inputs. The latter
// deliberately uses a fixture-only Task, not a second accepted shared app.
func verifyRouteStaticAddressCollision(t *testing.T, ctx context.Context, r *Runtime, root, manifest, sourceID string, p control.Policy, read func() cluster.View) {
	t.Helper()
	sourceKey := deployment.ResourceKey("task", "tenant", "route-source", "endpoint")
	sourceTask, err := r.workload.View(sourceKey)
	if err != nil || !sourceTask.State.Applied.Present || sourceTask.State.Pending != nil {
		t.Fatal("original address must belong to an applied Task", err)
	}
	source, err := workload.DecodeContainer(sourceTask.State.Applied.Spec)
	if err != nil || source.Process == nil || !source.IPv4.IsValid() {
		t.Fatal("original frozen image/address", err)
	}
	before := read().State
	planning, err := p.AppPlanning(before, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := p.Catalog(before)
	if err != nil {
		t.Fatal(err)
	}
	document, err := os.ReadFile(filepath.Join(root, "route-source-app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	competing, err := deployment.ParseApp(document)
	if err != nil {
		t.Fatal(err)
	}
	competing.Name, competing.Sfc.Deployment = "route-ip-competitor", "route-ip-competitor"
	planning.Project, planning.Deployment = competing.Name, competing.Sfc.Deployment
	_, err = deployment.CompileApp(competing, catalog, planning)
	var conflict *deployment.InputError
	if !errors.As(err, &conflict) || conflict.Code != "ADDRESS_CONFLICT" {
		t.Fatal("shared duplicate address did not reach the original Book", err)
	}
	if now := read().State; now.Object(control.ResourcesKey) != before.Object(control.ResourcesKey) || now.Object(control.AppsKey) != before.Object(control.AppsKey) {
		t.Fatal("read-only conflicting plan changed shared resources/apps")
	}

	bridgeBefore, err := r.network.View(source.Bridge)
	if err != nil {
		t.Fatal(err)
	}
	sourceIdentity, err := r.docker.Identity("container", sourceKey, sourceTask.State.Applied)
	if err != nil {
		t.Fatal(err)
	}
	original, err := r.docker.API.ContainerInspect(ctx, sourceID, client.ContainerInspectOptions{})
	if err != nil || original.Container.ID != sourceID || original.Container.Config == nil || !sourceIdentity.Matches(original.Container.Name, original.Container.Config.Labels) || original.Container.State == nil || !original.Container.State.Running {
		t.Fatal("original live IP holder", err)
	}
	preserveSource := func() {
		t.Helper()
		got, err := r.docker.API.ContainerInspect(ctx, sourceID, client.ContainerInspectOptions{})
		if err != nil || got.Container.State == nil || !got.Container.State.Running || got.Container.ID != original.Container.ID || got.Container.State.Pid != original.Container.State.Pid || got.Container.State.StartedAt != original.Container.State.StartedAt || !reflect.DeepEqual(got.Container.NetworkSettings, original.Container.NetworkSettings) {
			t.Fatal("address collision disturbed original running app", err)
		}
	}
	key, path := "workload/e3-static-ip-collision", filepath.Join(root, "route-ipam-collision.db")
	spec := workload.ContainerSpec{Schema: 1, Node: r.owner, Image: source.Process.ImageID, Process: source.Process, Bridge: source.Bridge, BridgeGeneration: source.BridgeGeneration, IPv4: source.IPv4, Memory: 16 << 20, NanoCPU: 100000000}
	specRaw, _ := json.Marshal(spec)
	target := reconcile.Resource{Present: true, Generation: 1, Spec: string(specRaw)}
	id, err := r.docker.Identity("container", key, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("refuse an existing collision journal", err)
	}
	if gone, err := r.docker.Gone(ctx, "container", key); err != nil || !gone {
		t.Fatal("refuse an existing collision container", err)
	}
	var evidence map[string]any
	raw, err := os.ReadFile(manifest)
	if err != nil || json.Unmarshal(raw, &evidence) != nil || evidence == nil {
		t.Fatal("original owner manifest", err)
	}
	report := map[string]any{"key": key, "journal": path, "target": target, "identity": id, "original_container": sourceID, "bridge_consumers_before": bridgeBefore.Consumers, "shared_rejection": conflict.Code, "scope": "fixture-only Task; actual SDK/address/Start checkpoint/pin retirement, not shared app acceptance"}
	evidence["route_static_ip_collision"] = report
	save := func() {
		t.Helper()
		raw, err := json.Marshal(evidence)
		if err == nil {
			err = os.WriteFile(manifest, raw, 0644)
		}
		if err != nil {
			t.Fatal("collision manifest", err)
		}
	}
	save() // Before journal creation, dependency borrow, SDK Create or Start.
	w, err := workload.OpenManager(path, r.docker, r.network)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if w != nil {
			if err := w.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	admitted, retired := false, false
	retire := func(clean context.Context) error {
		if !admitted || retired {
			return nil
		}
		if w == nil {
			return errors.New("original workload journal is unavailable; preserve native and pin")
		}
		if err := w.Desired(key, 2, 1, nil, 1); err != nil {
			return err
		}
		if err := w.Step(clean, key); err != nil {
			return err
		}
		gone, err := w.Gone(clean, key, 2, 1)
		if err != nil || !gone {
			return errors.Join(reconcile.ErrPending, err)
		}
		retired = true
		return nil
	}
	defer func() {
		clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if err := retire(clean); err != nil {
			t.Error("retain unknown collision journal/native/pin for containment", err)
		}
	}() // Exact original Task retirement, registered before the first Desired.
	if err := w.Desired(key, 1, 1, &spec, 1); err != nil {
		t.Fatal(err)
	}
	admitted = true
	startErr := w.Step(ctx, key)
	if startErr == nil || !strings.Contains(strings.ToLower(startErr.Error()), "address already in use") {
		t.Fatal("expected actual SDK address conflict, not a different prerequisite failure", startErr)
	}
	pending, err := w.View(key)
	if err != nil || pending.State.Applied.Present || pending.State.Pending == nil || pending.State.Pending.ID != 1 || pending.State.Pending.Phase != reconcile.RecoveryRequired || pending.State.Pending.Target != target || pending.Checkpoint == nil || pending.Checkpoint.Operation != 1 || pending.Checkpoint.Target != target {
		t.Fatal("IP conflict forgot original Unknown Start", err)
	}
	failed, err := r.docker.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	if err != nil || failed.Container.Config == nil || !id.Matches(failed.Container.Name, failed.Container.Config.Labels) || failed.Container.State == nil || failed.Container.State.Running || failed.Container.State.Pid != 0 || failed.Container.State.Status != container.StateCreated {
		t.Fatal("actual SDK collision did not retain the original created native", err)
	}
	var checkpoint struct {
		Schema uint8
		Native string
	}
	if json.Unmarshal(pending.Checkpoint.Data, &checkpoint) != nil || checkpoint.Schema != 1 || checkpoint.Native != failed.Container.ID {
		t.Fatal("Start checkpoint lost the positively observed original native")
	}
	held, err := r.network.InspectConsumer(ctx, source.Bridge, "workload/"+id.Name, source.BridgeGeneration)
	if err != nil {
		t.Fatal("SDK conflict returned the unresolved native's Bridge pin", err)
	}
	preserveSource()
	report["pending"], report["native_id"], report["sdk_error"], report["bridge_pin"] = pending, failed.Container.ID, startErr.Error(), held
	save()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w = nil
	w, err = workload.OpenManager(path, r.docker, r.network)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Step(ctx, key); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("same-DB unknown Start was replayed or settled", err)
	}
	after, err := w.View(key)
	if err != nil || !reflect.DeepEqual(after, pending) {
		t.Fatal("same-DB recovery changed original operation/checkpoint", err)
	}
	stillHeld, err := r.network.InspectConsumer(ctx, source.Bridge, held.Consumer, source.BridgeGeneration)
	if err != nil || !reflect.DeepEqual(stillHeld, held) {
		t.Fatal("same-DB recovery replaced or returned the original pin", err)
	}
	if err := retire(ctx); err != nil {
		t.Fatal("explicit collision Task retirement", err)
	}
	if _, err := r.docker.API.ContainerInspect(ctx, failed.Container.ID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("original failed native is not actually Gone", err)
	}
	bridgeAfter, err := r.network.View(source.Bridge)
	if err != nil || bridgeAfter.State.Applied != bridgeBefore.State.Applied || !reflect.DeepEqual(bridgeAfter.Consumers, bridgeBefore.Consumers) {
		t.Fatal("collision retirement changed borrowed Bridge/original consumers", err)
	}
	preserveSource()
	report["retired"], report["bridge_consumers_after"] = retired, bridgeAfter.Consumers
	save()
}
