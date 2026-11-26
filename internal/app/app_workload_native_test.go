// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/jay94ks/mydcd/tests/vaultfixture"
	"github.com/moby/moby/client"
)

func verifyManagedTaskVolume(t *testing.T, ctx context.Context, runtime **Runtime, cfg config.Node, policy control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), recovered func(*Runtime), image string, withVolume bool, vault *vaultfixture.Vault, withRetirement bool, cliChecks ...func()) {
	t.Helper()
	r := *runtime
	taskKey := deployment.ResourceKey("task", "tenant", "app", "web")
	stage := func() deployment.StageRecord {
		a, err := policy.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		e, _ := a.Execution("tenant", "app")
		s, _ := e.Stage(taskKey)
		return s
	}
	wait("automatic managed Volume/Binding/Task health/HTTP", func() bool {
		s := stage()
		return s.Observation != nil && s.Observation.Applied && s.Observation.Healthy
	})
	original := stage()
	status, err := r.workload.Status(ctx, taskKey)
	if err != nil || status.NativeID != original.Observation.Native || !status.Ready || !status.HTTPConfigured || !status.HealthConfigured || !ed25519.Verify(r.Identity.Public[:], deployment.ObservationBytes(*original.Observation), original.Observation.Signature) {
		t.Fatal("actual owner observation/readiness", err)
	}
	a, err := policy.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := a.Binding(deployment.ObjectRef{Key: taskKey, Generation: original.Result.Generation, Revision: original.Result.Revision})
	wantPins := 0
	if withVolume {
		wantPins = 1
	}
	wantGrants := 0
	if vault != nil {
		wantGrants = 1
	}
	if !ok || len(b.Pins()) != wantPins || len(b.ProjectionGrants()) != wantGrants {
		t.Fatal("original shared Volume binding")
	}
	if withVolume {
		registry, err := policy.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		ready, ok := registry.Native("tenant", "app", "data")
		if !ok || ready.Verify() != nil {
			t.Fatal("actual native signed volume registration")
		}
		got, err := r.docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if data, e := os.ReadFile(filepath.Join(got.Volume.Mountpoint, "marker")); e != nil || string(data) != "volume-original" {
			t.Fatal("actual nonroot writer data", e)
		}
	}
	wait("same daemon app completion", func() bool {
		apps, e := policy.Apps(read().State)
		if e != nil {
			return false
		}
		execution, _ := apps.Execution("tenant", "app")
		return execution.Status() == "Succeeded"
	})
	if cfg.Modules["ingress"].Enabled {
		verifyManagedIngressServing(t, ctx, r, cfg, policy, read, wait)
	}
	request := control.AppBindingRequest{Task: deployment.ObjectRef{Key: taskKey, Generation: original.Result.Generation, Revision: original.Result.Revision}, Digest: b.Digest()}
	if len(cliChecks) == 3 {
		cliChecks[0]()
	}
	if r.dnsOwner() != nil {
		verifyManagedAppDNS(t, ctx, r, policy, read, wait)
	}
	if vault != nil {
		if _, _, err = r.CollectAppTaskClosure(ctx, request); err == nil {
			t.Fatal("live Task produced termination proof")
		}
		vault.API("PUT", "sys/seal", nil, nil, vault.Admin)
	}
	if err = r.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	row, err := r.workload.View(taskKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	*runtime = nil
	r, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	*runtime = r
	if _, err = r.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	if err = r.workload.Step(ctx, taskKey); err != nil {
		t.Fatal("original Task recovery", err)
	}
	resumed, err := r.workload.Status(ctx, taskKey)
	if err != nil || resumed.NativeID != status.NativeID || !resumed.Ready {
		t.Fatal("same DB/container/readiness", err)
	}
	restored, err := r.workload.View(taskKey)
	if err != nil || restored.State.LastID != row.State.LastID || restored.State.Applied != row.State.Applied {
		t.Fatal("original journal preserved", err)
	}
	if cfg.Modules["ingress"].Enabled {
		verifyManagedIngressServing(t, ctx, r, cfg, policy, read, wait)
	}
	if r.dnsOwner() != nil {
		verifyManagedAppDNS(t, ctx, r, policy, read, wait)
	}
	if recovered != nil {
		recovered(r)
		// The hook may explicitly restart/stop this original (user controls,
		// event collection). Revocation must preserve its resulting instance,
		// rather than the Start timestamp captured before those operations.
		resumed, err = r.workload.Status(ctx, taskKey)
		if err != nil || resumed.NativeID != status.NativeID {
			t.Fatal("recovery hook replaced original native", err)
		}
	}
	catalog, _ := policy.Catalog(read().State)
	tenant, _ := catalog.Tenant("tenant")
	change("revoke-task-node", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant"})
	if err = r.workload.Step(ctx, taskKey); err != nil {
		t.Fatal("revocation blocked running observation", err)
	}
	timeout := 1
	if _, err = r.docker.API.ContainerStop(ctx, status.NativeID, client.ContainerStopOptions{Timeout: &timeout}); err != nil {
		t.Fatal(err)
	}
	stepErr := r.workload.Step(ctx, taskKey)
	// Recovery observes an already exited original; it is not an implicit
	// Start request. A nil Step error therefore cannot prove a restart.
	actual, err := r.docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
	if err != nil || actual.Container.State == nil || actual.Container.State.Running || actual.Container.State.StartedAt != resumed.StartedAt {
		t.Fatal("revoked original restarted or changed native instance", err, stepErr)
	}
	if again, err := r.workload.View(taskKey); err != nil || again.State.LastID != row.State.LastID || again.State.Applied != row.State.Applied {
		t.Fatal("denial replaced original Task", err)
	}
	if withRetirement {
		verifyAutomaticAppRetirement(t, ctx, runtime, cfg, policy, read, change, wait, request, status.NativeID, withVolume, cliChecks...)
		r = *runtime
	} else if vault != nil {
		verifyManagedAppTaskClosure(t, ctx, r, policy, read, request, row.State.Applied)
	}
	t.Logf("nativeOwner=%s image=%s nativeTask=%s", r.owner, image, status.NativeID)
	if withRetirement {
		t.Log("actual managed owner retirement and reference settlement completed; retained fixture Volume/image deletion is test rollback; CLI/two-node composition remains separate")
	} else if vault != nil {
		t.Log("actual Vault/Secret/Volume/Task consumption and original closure collector completed; original Remove was requested by the test; automatic retirement/CLI/two-node composition remains separate")
	} else {
		t.Logf("actual managed Runtime/user/MYDCP/Raft/bbolt -> immutable Task/Binding (named Volume=%t) -> nonroot/health+HTTP -> same DB/ID -> revoke retains running observation but rejects stopped Start; fixture journal rollback, not compose down or Secret/Vault/two-node success", withVolume)
	}
}

// This owned fixture rollback runs after stopping the Runtime producer. It
// uses original journals/SDK Remove and verifies retained data before deleting
// only this test's native Volume and image. It is not a compose-down claim.
func cleanupManagedTaskVolumes(t *testing.T, ctx context.Context, c *engine.Client, cfg config.Node, n *network.Manager, manifest map[string]any) {
	t.Helper()
	native, err := volumes.OpenNative(filepath.Join(cfg.Node.StateDir, "workload", "volumes.db"), c)
	if err != nil {
		t.Error(err)
		return
	}
	defer native.Close()
	clusterID, clusterOK := manifest["Cluster"].([32]byte)
	nodeKey, nodeOK := manifest["NodeKey"].([32]byte)
	if !clusterOK || !nodeOK {
		t.Error("original owner identity missing")
		return
	}
	var fixed *volumes.FixedManager
	if manifest["FixedVolume"] == true {
		key, err := identity.Load(cfg.Node.IdentityDir)
		if err != nil || key.Public != nodeKey {
			t.Error("fixed rollback original identity", err)
			return
		}
		defer clear(key.Private)
		roots, err := nodestorage.OpenRoots(filepath.Join(cfg.Node.StateDir, "storage", "roots.db"), clusterID, cfg.Node.ID, key.Private)
		if err != nil {
			t.Error(err)
			return
		}
		defer roots.Close()
		fixed, err = volumes.OpenFixed(filepath.Join(cfg.Node.StateDir, "workload", "fixed", "journal.db"), c, roots, clusterID, cfg.Node.ID, key.Private, func(context.Context, nodestorage.Reference) (nodestorage.Root, error) {
			return nodestorage.Root{}, volumes.ErrNativeVolume
		})
		if err != nil {
			t.Error(err)
			return
		}
		defer fixed.Close()
		if err = native.AttachFixed(fixed); err != nil {
			t.Error(err)
			return
		}
	}
	// Test rollback may return only leases captured after this exact Runtime's
	// successful I/O join. Shared registry closure is not fabricated here.
	if pins, ok := manifest["RegistryJoinedRollbackPins"].([]volumes.NativeLease); ok {
		for _, pin := range pins {
			if err := native.Return(pin); err != nil {
				t.Error("joined registry rollback lease", err)
			}
		}
	}
	activation, err := volumes.OpenActivations(filepath.Join(cfg.Node.StateDir, "workload", "activations.db"), native, c, clusterID, nodeKey, func(context.Context, volumes.StartRequest) (volumes.Permit, error) {
		return volumes.Permit{}, volumes.ErrActivation
	})
	if err != nil {
		t.Error(err)
		return
	}
	defer activation.Close()
	store, err := deployment.OpenProjections(filepath.Join(cfg.Node.StateDir, "workload", "inputs"), clusterID, nodeKey, maxAppInputBytes, func(context.Context, deployment.Binding) error { return deployment.ErrInputs })
	if err != nil {
		t.Error(err)
		return
	}
	defer store.Close()
	w, err := workload.OpenManagerWithResources(filepath.Join(cfg.Node.StateDir, "workload", "journal.db"), c, n, store, activation)
	if err != nil {
		t.Error(err)
		return
	}
	defer w.Close()
	volumeKeys := map[string]bool{}
	images := map[string]bool{}
	if expected, _ := manifest["PrivateImages"].(map[string]string); manifest["PrivateEngineVerified"] == true {
		for image := range expected {
			images[image] = true
		}
	}
	if image, ok := manifest["Image"].(string); ok {
		images[image] = true
	}
	if owned, ok := manifest["OwnedImageIDs"].([]string); ok {
		for _, image := range owned {
			images[image] = true
		}
	}
	// E5 records exact temporary image aliases before each SDK effect. They
	// remain owned cleanup targets even when preparation fails before app up.
	for _, field := range []string{"RegistrySeedReference", "RegistryTagReference", "RegistryReference"} {
		if image, ok := manifest[field].(string); ok && image != "" {
			images[image] = true
		}
	}
	for _, key := range w.Keys() {
		row, err := w.View(key)
		if err != nil {
			t.Error(err)
			continue
		}
		if manifest["ExpectGone"] == true && (row.State.Pending != nil || row.State.Applied.Present || row.State.Desired.Present || len(row.Consumers) != 0) {
			t.Error("product left original Task before cleanup", key)
		}
		resource := row.State.Desired.Resource
		if !resource.Present {
			resource = row.State.Applied
		}
		if !resource.Present {
			continue
		}
		spec, err := workload.DecodeContainer(resource.Spec)
		if err != nil {
			t.Error(err)
			continue
		}
		for _, mount := range spec.Volumes {
			volumeKeys[mount.NativeKey] = true
		}
		images[spec.Image] = true
		revision := row.State.Desired.Revision + 1
		if err = w.Desired(key, revision, resource.Generation, nil, max(1, row.Capacity)); err == nil {
			err = w.Step(ctx, key)
		}
		if err != nil {
			t.Error("original Task rollback", err)
			continue
		}
		if gone, e := w.Gone(ctx, key, revision, resource.Generation); e != nil || !gone {
			t.Error("original Task not Gone", e)
		}
	}
	for _, key := range native.Keys() {
		volumeKeys[key] = true
	}
	for key := range volumeKeys {
		row, err := native.View(key)
		if err != nil {
			t.Error(err)
			continue
		}
		if strings.HasPrefix(key, "fixed-volume/") {
			if fixed == nil {
				t.Error("fixed rollback adapter missing")
				continue
			}
			resource := row.State.Applied
			if !resource.Present && row.State.Pending != nil {
				resource = row.State.Pending.Target
			}
			if !resource.Present {
				resource = row.State.Desired.Resource
			}
			if !resource.Present {
				continue
			}
			var declaration struct {
				Schema    uint8
				Spec      volumes.NativeSpec
				Selection nodestorage.FixedSelection
			}
			if json.Unmarshal([]byte(resource.Spec), &declaration) != nil || declaration.Schema != 1 || declaration.Spec.Validate() != nil || declaration.Selection.Validate() != nil {
				t.Error("original fixed rollback declaration")
				continue
			}
			revision := row.State.Desired.Revision
			if row.State.Desired.Present {
				revision++
			}
			if err = fixed.DeleteDesired(key, revision, resource.Generation); err == nil {
				err = fixed.Step(ctx, key)
			}
			if err != nil {
				t.Error("original fixed rollback without source deletion", err)
				continue
			}
			if closed, err := fixed.Closed(ctx, declaration.Spec, declaration.Selection, revision); err != nil || !closed {
				t.Error("original fixed projection/root pin remains", err)
			}
			continue
		}
		if !row.State.Applied.Present {
			continue
		}
		var spec volumes.NativeSpec
		if json.Unmarshal([]byte(row.State.Applied.Spec), &spec) != nil {
			t.Error("original native Volume spec")
			continue
		}
		if err = native.DeleteDesired(key, row.State.Desired.Revision+1, row.State.Applied.Generation); err == nil {
			err = native.Step(ctx, key)
		}
		if err != nil {
			t.Error("original Volume rollback", err)
		}
	}
	for image := range images {
		borrowed, _ := manifest["BorrowedImages"].([]string)
		preserve := false
		for _, reference := range borrowed {
			if reference == image {
				preserve = true
				break
			}
		}
		if preserve {
			continue
		} // explicit pre-existing pinned input, including failure rollback
		if manifest["KeepImages"] == true {
			continue
		} // Another owned node uses the shared Engine's image.
		got, err := c.API.ImageInspect(ctx, image)
		if cerrdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			t.Error(err)
			continue
		}
		expectedImages, _ := manifest["PrivateImages"].(map[string]string)
		expectedID := expectedImages[image]
		labelled := got.Config != nil && got.Config.Labels["org.mydc.test.owner"] == manifest["Tag"]
		privateExact := manifest["PrivateEngineVerified"] == true && expectedID != "" && got.ID == expectedID
		if !labelled && !privateExact {
			t.Error("fixture image ownership")
			continue
		}
		target := got.ID
		if _, registryCase := manifest["RegistryAddress"]; registryCase {
			target = image
		}
		if _, err = c.API.ImageRemove(ctx, target, client.ImageRemoveOptions{}); err != nil {
			t.Error(err)
		}
	}
}
