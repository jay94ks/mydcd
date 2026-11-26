// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/jay94ks/mydcd/tests/gitfixture"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

func TestRealBoundaryMoveRejectsIncompleteTargetRuntime(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppVolumeMove, true, true, false, true)
}

func TestRealBoundaryMoveStartsTargetAppWithOriginalVolume(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppVolumeMoveAuto, true, true, false, true)
}

func TestE6ManagedCDGroupVolumeMove(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppCDVolumeMove, true, true, false, true)
}

func TestRealBoundaryMoveStartsReadonlyTargetApp(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppVolumeMoveReadonly, true, true, false, true)
}

func TestRealBoundaryMoveRetainsUnusedTargetVolume(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppVolumeMoveUnused, true, true, false, true)
}

func TestRealBoundaryMoveReturnsTargetWritesThroughNewMaterialization(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppVolumeMoveReverse, true, true, false, true)
}

func TestRealBoundaryMoveCancelDuringRetirementAndExplicitSourceRedeploy(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppVolumeMoveCancelResume, true, true, false, true)
}

func TestRealBoundaryMoveReceiverProcessKillResumesOriginalOffset(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppVolumeMoveProcessCut, true, true, false, true)
}

type managedMoveNativeControls struct {
	sourceStop, targetNetwork *managedCreateReplyFault
	sourceUsage               *volumeUsageGate
	reopenSource              func(whenClosed func()) *Runtime
	reopenTarget              func(whenClosed func()) *Runtime
	sourceRuntime             func() *Runtime
	cdSource                  *gitfixture.Fixture
	cdTarget                  []byte
}

func verifyManagedAppMoveQuiesce(t *testing.T, ctx context.Context, source, target *Runtime, root string, compose []byte, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), reject func(string, string, uint64, any, state.Code), approve func(control.UserOperation), wait func(string, func() bool), scenario managedAppScenario, controls managedMoveNativeControls) {
	t.Helper()
	automatic := scenario != managedAppVolumeMove
	capacity := uint64(128 << 10)
	if scenario == managedAppVolumeMoveProcessCut {
		capacity = 512 << 10
	}
	if target == nil {
		t.Fatal("installed independent target member required")
	}
	taskKey := deployment.ResourceKey("task", "tenant", "app", "web")
	registry := func() control.Volumes {
		t.Helper()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	apps := func() control.Apps {
		t.Helper()
		a, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	wait("original source app complete and running", func() bool { e, ok := apps().Execution("tenant", "app"); return ok && e.Status() == "Succeeded" })
	ready, ok := registry().Native("tenant", "app", "data")
	if !ok {
		t.Fatal("original app Volume")
	}
	if automatic {
		disk, err := source.docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
		if err != nil {
			t.Fatal(err)
		}
		dir, err := os.OpenRoot(disk.Volume.Mountpoint)
		if err != nil {
			t.Fatal(err)
		}
		file, err := dir.OpenFile("move-sentinel", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			dir.Close()
			t.Fatal(err)
		}
		_, err = file.WriteString("original-data-before-move")
		if err == nil {
			err = file.Chown(int(ready.Spec.UID), int(ready.Spec.GID))
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		var directoryErr error
		if err == nil && closeErr == nil {
			directory, openErr := dir.Open(".")
			directoryErr = openErr
			if openErr == nil {
				directoryErr = errors.Join(directory.Sync(), directory.Close())
			}
		}
		if scenario == managedAppVolumeMoveProcessCut && err == nil && closeErr == nil && directoryErr == nil {
			seedMoveProcessCutData(t, dir, ready.Spec.UID, ready.Spec.GID)
		}
		rootErr := dir.Close()
		if err != nil || closeErr != nil || directoryErr != nil || rootErr != nil {
			t.Fatal("owned source sentinel", err, closeErr, directoryErr, rootErr)
		}
	}
	oldTask, err := source.workload.Status(ctx, taskKey)
	if err != nil || !oldTask.Running || oldTask.NativeID == "" {
		t.Fatal("original source Task", err)
	}
	row, err := source.workload.View(taskKey)
	if err != nil || !row.State.Applied.Present {
		t.Fatal(err)
	}
	compatibility := sha256.Sum256(append([]byte("mydc-volume-cold-recipe-1\x00"), []byte(row.State.Applied.Spec)...))
	c, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	change("move-app-node-scope", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a", "node-b"}})
	for _, scope := range []string{"", "tenant"} {
		change("move-app-target-quota-"+scope, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-b", Capacity: workload.Resources{CPU: 1e9, Memory: 256 << 20}, Networks: 2, MaxConsumers: 8})
	}
	volume, _ := registry().Volume(ready.Spec.Scope)
	change("move-app-source-capacity", "set-volume-capacity", volume.Revision(), control.VolumeCapacity{Scope: ready.Spec.Scope, Native: control.VolumeNativeDigest(ready), Bytes: capacity})
	for _, node := range []string{"node-a", "node-b"} {
		for _, tenant := range []string{"", "tenant"} {
			change("move-app-budget-"+node+tenant, "set-volume-backup-limit", 0, control.VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: capacity, Count: 1, StagingBytes: capacity, StagingCount: 1, Original: &control.OriginalVolumeLimit{Bytes: 2 * capacity, Count: 2}})
		}
	}
	docker, err := engine.Open(ctx, "unix:///var/run/docker.sock", target.owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = docker.Close() })
	nativePath := filepath.Join(root, "app-move-target-native.db")
	if automatic {
		if target.workload == nil || target.network == nil || target.nativeVolumes == nil || target.activations == nil {
			t.Fatal("full normal target Runtime required")
		}
		nativePath = filepath.Join(root, "provider-state", "workload", "volumes.db")
	} else {
		target.docker = docker
		target.nativeVolumes, err = volumes.OpenNative(nativePath, docker)
		if err != nil {
			t.Fatal(err)
		}
		target.backupArtifacts, err = openBackupArtifacts(filepath.Join(root, "app-move-target-artifacts"), p.Cluster, target.Identity.Public, runtimeBackupBackend{target}, runtimeMoveBackend{target})
		if err != nil {
			t.Fatal(err)
		}
		target.volumeRestores, err = reconcile.OpenJournal(filepath.Join(root, "app-move-target-restores.db"))
		if err != nil {
			t.Fatal(err)
		}
	}
	spec := ready.Spec
	spec.Node = "node-b"
	spec.NodeKey = target.Identity.Public
	spec.Materialization = "m-app-move"
	filter := client.Filters{}.Add("label", "org.mydc.owner="+docker.Owner)
	prior, err := docker.API.VolumeList(ctx, client.VolumeListOptions{Filters: filter})
	if err != nil || len(prior.Items) != 0 {
		t.Fatal("target owner prestate", err)
	}
	t.Log("nativeOwner=" + docker.Owner)
	t.Cleanup(func() {
		_ = target.Close()
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		owned, e := engine.Open(clean, "unix:///var/run/docker.sock", docker.Owner)
		if e != nil {
			t.Error(e)
			return
		}
		defer owned.Close()
		if automatic {
			cleanupMoveTargetRuntime(t, clean, owned, root, p.Cluster, target.Identity.Public)
			return
		}
		manager, e := volumes.OpenNative(nativePath, owned)
		if e != nil {
			t.Error(e)
			return
		}
		defer manager.Close()
		key := volumes.NativeKey(spec)
		if row, e := manager.View(key); e == nil {
			generation := row.State.Applied.Generation
			if generation == 0 {
				generation = 1
			}
			if e = manager.DeleteDesired(key, 2, generation); e != nil {
				t.Error(e)
				return
			}
			if e = manager.Step(clean, key); e != nil {
				t.Error(e)
				return
			}
			if gone, e := manager.Gone(clean, key, 2, generation); e != nil || !gone {
				t.Error("target original rollback", e)
			}
		}
		left, e := owned.API.VolumeList(clean, client.VolumeListOptions{Filters: filter})
		if e != nil || len(left.Items) != 0 {
			t.Error("target owner rollback remains", e)
		}
	})
	appInventory, _ := apps().Inventory("tenant", "app")
	active, _ := appInventory.Active()
	volume, _ = registry().Volume(ready.Spec.Scope)
	_, ownerRevision := volume.Owner()
	q := control.VolumeMoveBegin{App: &control.VolumeMoveApp{Operation: active.ID, Revision: appInventory.Revision(), Plan: active.Plan}, Scope: ready.Spec.Scope, ID: "app-move", OwnerRevision: ownerRevision, Target: spec, Compatibility: compatibility, MaxBytes: capacity, MaxEntries: 16, CapacityBytes: capacity, ExpiresAt: time.Now().Unix() + 120}
	input, err := deployment.ParseApp(compose)
	if err != nil {
		t.Fatal(err)
	}
	web := input.Services["web"]
	web.MyDC.Node = "node-b"
	if scenario == managedAppVolumeMoveReadonly {
		for i := range web.Volumes {
			web.Volumes[i].ReadOnly = true
		}
	} else if scenario == managedAppVolumeMoveUnused {
		web.Volumes = nil
		delete(web.Environment, "MYDC_VOLUME_FIXTURE")
		// This fixture image declares VOLUME /data. Cover it explicitly with
		// an unrelated ephemeral mount, never Docker's implicit named volume
		// or the restored data volume that this target deliberately leaves idle.
		web.Tmpfs = append(web.Tmpfs, "/data:size=4m,uid=10001,gid=10001,mode=0750")
		web.Healthcheck = &deployment.Healthcheck{Test: []string{"CMD", "/backend", "--probe"}, Interval: "1s", Timeout: "1s", Retries: 2}
	}
	resources, err := p.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	reference := input.Networks["app"]
	sourceNetwork, ok := resources.Networks.NamedNetwork("tenant", reference.Name, "node-a")
	if !reference.External || !ok || len(sourceNetwork.Pools) != 1 {
		t.Fatal("source app requires its original named management network")
	}
	prefix := sourceNetwork.Pools[0].Prefix
	if !prefix.Addr().Is4() || prefix.Bits() != 24 {
		t.Fatal("owned source/target fixture requires a nonoverlapping IPv4 /24 pair")
	}
	addr := prefix.Addr().As4()
	if addr[2] == 255 {
		t.Fatal("owned target CIDR would overflow the fixture /24 pair")
	}
	addr[2]++
	next := netip.PrefixFrom(netip.AddrFrom4(addr), 24).Masked()
	// Management owns both named networks. The app borrows its node-local
	// member by name and cannot create or remove either native Bridge. A lone
	// member projects only a Bridge; multi-peer TUN/DNS is a separate fixture.
	targetNetwork := tenancy.TUNDefinition{Tenant: "tenant", Name: "move-target-network", Members: []tenancy.TUNNode{{Node: "node-b", Pools: []tenancy.Subnet{{ID: "pool", Prefix: next, Gateway: next.Addr().Next(), MTU: sourceNetwork.Pools[0].MTU}}, Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.254.2/32")}}}}
	// Persist target ownership before its management source can create a native
	// Bridge. Preserve the source manifest's exact JSON numbers and key arrays.
	manifestPath := os.Getenv("MYDC_NATIVE_MANIFEST")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]json.RawMessage
	if err = json.Unmarshal(manifestRaw, &manifest); err != nil || manifest == nil {
		t.Fatal("original source ownership manifest", err)
	}
	manifest["Target"], err = json.Marshal(map[string]any{"Owner": docker.Owner, "Cluster": p.Cluster, "NodeKey": target.Identity.Public, "Root": root, "Key": (tenancy.SourceIdentity{Kind: "bridge", Tenant: "tenant", Network: targetNetwork.Name, Node: "node-b"}).Key(), "CIDR": next.String()})
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manifestPath, manifestRaw, 0644); err != nil {
		t.Fatal(err)
	}
	change("move-target-network", "create-tun-network", resources.Networks.Revision(), targetNetwork)
	web.Networks = map[string]deployment.Attachment{"move-target": {IPv4: next.Addr().Next().Next().String()}}
	input.Services["web"] = web
	if scenario == managedAppVolumeMoveReadonly {
		mirror := web
		mirror.Networks = map[string]deployment.Attachment{"move-target": {IPv4: next.Addr().Next().Next().Next().String()}}
		input.Services["mirror"] = mirror
	}
	input.Networks = map[string]deployment.ComposeNetwork{"move-target": {External: true, Name: targetNetwork.Name}}
	decl := input.Volumes["data"]
	decl.MyDC.Node = "node-b"
	input.Volumes["data"] = decl
	c, err = p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	planning, err := p.AppPlanning(read().State, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	planning.Project, planning.Deployment = "app", "app"
	specRaw, _ := json.Marshal(spec)
	targetID, err := docker.Identity("volume", volumes.NativeKey(spec), reconcile.Resource{Present: true, Generation: 1, Spec: string(specRaw)})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := deployment.CompileAppVolumeMove(input, c, planning, deployment.VolumeMovePlacement{Scope: q.Scope, Source: ready.Owner, SourceOwnerRevision: ownerRevision, Target: volumes.Owner{Node: spec.Node, Key: spec.NodeKey, Native: targetID.Name}})
	if err != nil {
		t.Fatal("target declaration preview", err)
	}
	if err = preview.CheckAppInput(); err != nil {
		t.Fatal("target artifact lost app.yaml contract", err)
	}
	if scenario == managedAppCDVolumeMove {
		controls.cdTarget, err = yaml.Marshal(input)
		if err != nil || controls.cdSource == nil {
			t.Fatal("actual CD move needs its exact target declaration and source", err)
		}
	}
	raw, err := preview.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if automatic {
		q, preview, raw, approve = beginMoveThroughCLI(t, ctx, root, input, q, source, p, read, wait)
	} else {
		q.App.Target = &control.VolumeMoveTargetApp{Upload: "move-target", Operation: "move-target-app", Plan: preview.Digest()}
		change("move-target-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "app", ID: "move-target", Length: len(raw), Digest: preview.Digest()})
		for offset, part := 0, 0; offset < len(raw); part++ {
			end := min(offset+deployment.ArtifactPartBytes, len(raw))
			change("move-target-part-"+string(rune('a'+part)), "put-app-part", uint64(part+1), control.AppUploadPart{Tenant: "tenant", ID: "move-target", Index: part, Data: raw[offset:end]})
			offset = end
		}
		change("move-app-original", "begin-volume-move", volume.Revision(), q)
	}
	selection := control.VolumeMoveSelection{Scope: q.Scope, ID: q.ID}
	job, m, ok := registry().Move(selection)
	if !ok || m.Phase != volumes.Prepared {
		t.Fatal("accepted app move")
	}
	if job.App.Target == nil || job.App.Target.Plan != preview.Digest() || p.RevalidateMoveAppTarget(read().State, job) != nil {
		t.Fatal("original target declaration not fixed")
	}
	reject("move-target-abort-refused", "abort-app-upload", uint64((len(raw)+deployment.ArtifactPartBytes-1)/deployment.ArtifactPartBytes+1), control.AppUploadSelection{Tenant: "tenant", ID: q.App.Target.Upload}, state.ConditionFailed)
	currentInventory, _ := apps().Inventory("tenant", "app")
	reject("move-target-direct-begin-refused", "begin-app", currentInventory.Revision(), control.AppBegin{Tenant: "tenant", App: "app", Deployment: "app", Upload: q.App.Target.Upload, Operation: q.App.Target.Operation}, state.ConditionFailed)
	if automatic {
		// A different upload must not replace the original app/move either.
		// Reusing only the move-held upload would test the older upload guard.
		change("move-competitor-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "app", ID: "move-competitor", Length: len(raw), Digest: preview.Digest()})
		parts := 0
		for offset := 0; offset < len(raw); parts++ {
			end := min(offset+deployment.ArtifactPartBytes, len(raw))
			change("move-competitor-part-"+string(rune('a'+parts)), "put-app-part", uint64(parts+1), control.AppUploadPart{Tenant: "tenant", ID: "move-competitor", Index: parts, Data: raw[offset:end]})
			offset = end
		}
		inventory, _ := apps().Inventory("tenant", "app")
		reject("move-competitor-begin-refused", "begin-app", inventory.Revision(), control.AppBegin{Tenant: "tenant", App: "app", Deployment: "app", Upload: "move-competitor", Operation: "replace-accepted-move"}, state.ConditionFailed)
		change("move-competitor-abort", "abort-app-upload", uint64(parts+1), control.AppUploadSelection{Tenant: "tenant", ID: "move-competitor"})
	}
	planning, err = p.AppPlanning(read().State, "admin", "tenant")
	targetNeed := workload.Resources{CPU: 100000000, Memory: 16 << 20}
	targetTasks := 1
	if scenario == managedAppVolumeMoveReadonly {
		targetNeed = workload.Resources{CPU: 200000000, Memory: 32 << 20}
		targetTasks = 2
	}
	if err != nil || planning.Nodes["node-a"].Used != (workload.Resources{CPU: 100000000, Memory: 16 << 20}) || planning.Nodes["node-b"].Used != targetNeed || len(planning.Planned) != targetTasks {
		t.Fatal("source and planned target budgets must both remain charged", err)
	}
	for _, held := range planning.Planned {
		if held.Demand.Kind != "task" || held.Demand.Key != taskKey && (scenario != managedAppVolumeMoveReadonly || held.Demand.Key != deployment.ResourceKey("task", "tenant", "app", "mirror")) {
			t.Fatal("management Bridge was charged as an app-owned pending resource")
		}
	}
	resources, err = p.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	rootBefore := read().State.Object(control.ResourcesKey)
	reject("move-target-budget-competition", "reserve-task", resources.Quotas.Revision(), tenancy.Reservation{Key: "workload/task/tenant/competitor/web", Tenant: "tenant", Node: "node-b", Need: workload.Resources{CPU: 1e9, Memory: 256 << 20}}, state.Invalid)
	limit, _ := resources.Quotas.Limit("tenant", "node-b")
	revision := limit.Revision
	limit.Revision = 0
	limit.Capacity.Memory = 1
	reject("move-target-limit-shrink", "set-node-quota", revision, limit, state.Invalid)
	competitor := tenancy.Network{Tenant: "tenant", ID: "competitor", Node: "node-b", Owner: target.Identity.Public, Pools: []tenancy.Subnet{{ID: "pool", Prefix: next, Gateway: next.Addr().Next(), MTU: 1280}}}
	// The resource reducer reports a typed Create conflict as ConditionFailed,
	// while a later whole-projection rejection is Invalid. Prove the candidate
	// passes quota admission and fails the actual shared subnet reservation;
	// neither a different admission failure nor a stale root proves overlap.
	if err = resources.Quotas.AdmitNetwork(c, "admin", competitor.Tenant, competitor.Node, competitor.Owner, resources.Networks); err != nil {
		t.Fatal("CIDR competition must pass network quota admission", err)
	}
	if _, err = resources.Networks.Create(c, "admin", resources.Networks.Revision(), competitor); !errors.Is(err, tenancy.ErrPolicy) {
		t.Fatal("CIDR competition must reject the reserved subnet", err)
	}
	reject("move-target-cidr-competition", "create-network", resources.Networks.Revision(), competitor, state.ConditionFailed)
	if read().State.Object(control.ResourcesKey) != rootBefore {
		t.Fatal("rejected competition changed original policy")
	}
	inputRaw, _ := json.Marshal(input)
	var competing deployment.Compose
	if json.Unmarshal(inputRaw, &competing) != nil {
		t.Fatal("candidate clone")
	}
	competing.Name = "competitor"
	planning.Project, planning.Deployment = "competitor", "competitor"
	if _, err = deployment.CompileApp(competing, c, planning); err == nil {
		t.Fatal("competing app borrowed the planned target static IP")
	} else if inputErr, ok := err.(*deployment.InputError); !ok || inputErr.Code != "ADDRESS_CONFLICT" {
		t.Fatal("competition did not reach the held static IP boundary", err)
	}
	if _, err = source.volumeMovePermit(ctx, job, "quiesce"); err == nil {
		t.Fatal("source app stopped before target preparation")
	}
	still, err := source.docker.API.ContainerInspect(ctx, oldTask.NativeID, client.ContainerInspectOptions{})
	if err != nil || still.Container.State == nil || !still.Container.State.Running {
		t.Fatal("original running source lost before preparation", err)
	}
	if scenario == managedAppVolumeMoveCancelResume {
		verifyMoveCancelSourceRedeploy(t, ctx, source, target, root, compose, ready, job, p, read, change, approve, wait, controls.sourceStop, func() *Runtime { return controls.reopenSource(nil) })
		return
	}
	if automatic {
		verifyAutomaticMoveTarget(t, ctx, source, target, root, compose, ready, job, p, read, change, reject, approve, wait, scenario, controls)
		return
	}
	// Observe a real preparation failure before allowing any source shutdown.
	if _, err = target.nativeVolumes.Desired(spec, 1, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err = target.nativeVolumes.Step(ctx, volumes.NativeKey(spec)); err != nil {
		t.Fatal(err)
	}
	preflightReady, err := target.nativeVolumes.Ready(ctx, volumes.NativeKey(spec), target.Identity.Private)
	if err != nil {
		t.Fatal(err)
	}
	preflightDisk, err := docker.API.VolumeInspect(ctx, preflightReady.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(preflightDisk.Volume.Mountpoint, "owned-preflight-blocker")
	f, err := os.OpenFile(blocker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if err = target.prepareMoveTarget(ctx, job); err == nil {
		t.Fatal("nonempty target prepared")
	}
	_, blocked, _ := registry().Move(selection)
	still, err = source.docker.API.ContainerInspect(ctx, oldTask.NativeID, client.ContainerInspectOptions{})
	if err != nil || still.Container.State == nil || !still.Container.State.Running || blocked.Preparation != nil {
		t.Fatal("source stopped despite failed preparation", err)
	}
	if err = os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err = target.prepareMoveTarget(ctx, job); err == nil {
		t.Fatal("unapproved target reported actual input readiness")
	}
	_, pendingInputs, _ := registry().Move(selection)
	if pendingInputs.Preparation != nil {
		t.Fatal("metadata-only target preparation was published")
	}
	if _, err = source.volumeMovePermit(ctx, job, "quiesce"); err == nil {
		t.Fatal("source stopped without target Group approval")
	}
	still, err = source.docker.API.ContainerInspect(ctx, oldTask.NativeID, client.ContainerInspectOptions{})
	if err != nil || still.Container.State == nil || !still.Container.State.Running {
		t.Fatal("unapproved target lost source Running", err)
	}
	approve(job.Origin)
	// A Volume-only installed target no longer proves that the app's actual
	// network/workload can run. Positive source retirement/owner handoff belongs
	// to the full normal-target Runtime scenario, not this partial adapter.
	if target.network != nil || target.workload != nil {
		t.Fatal("negative fixture must lack target app modules")
	}
	if err = target.prepareMoveTarget(ctx, job); err == nil {
		t.Fatal("incomplete target Runtime prepared a full app")
	}
	_, unready, _ := registry().Move(selection)
	current, _ := registry().Volume(q.Scope)
	currentOwner, _ := current.Owner()
	still, err = source.docker.API.ContainerInspect(ctx, oldTask.NativeID, client.ContainerInspectOptions{})
	if err != nil || still.Container.State == nil || !still.Container.State.Running || unready.Preparation != nil || unready.Phase != volumes.Prepared || currentOwner != job.Binding.Source || unready.Irreversible {
		t.Fatal("missing target modules stopped or reassigned original source", err)
	}
	change("cancel-unready-app-move", "cancel-volume-move", current.Revision(), job.Selection())
	wait("unready target and untouched original source cancellation", func() bool {
		_, move, ok := registry().Move(selection)
		if ok && move.Phase == volumes.Cancelled {
			return true
		}
		if ok && move.Phase == volumes.Cancelling && move.CancelledTarget == nil {
			if err := target.cancelMoveTarget(ctx, job); err != nil && !errors.Is(err, reconcile.ErrPending) {
				t.Fatal("original unready target cancellation", err)
			}
		}
		return false
	})
	_, cancelled, _ := registry().Move(selection)
	current, _ = registry().Volume(q.Scope)
	currentOwner, cancelledOwnerRevision := current.Owner()
	still, err = source.docker.API.ContainerInspect(ctx, oldTask.NativeID, client.ContainerInspectOptions{})
	if err != nil || still.Container.State == nil || !still.Container.State.Running || currentOwner != job.Binding.Source || cancelledOwnerRevision != job.Binding.SourceOwnerRevision || cancelled.SourceCleanup == nil || !cancelled.SourceCleanup.Unchanged || cancelled.CancelledTarget == nil || cancelled.Fence != nil {
		t.Fatal("early cancellation retired/replaced the original source", err)
	}
	if gone, err := target.nativeVolumes.Gone(ctx, volumes.NativeKey(job.Target), 2, 1); err != nil || !gone {
		t.Fatal("unready native target was not positively retired", err)
	}
	t.Log("Volume-only target cannot authorize app quiescence; nonempty/unapproved/unavailable-module preparation keeps original source running; explicit cancel joins/removes original target and records both cancellation facts while preserving source native ID/writer/owner revision; direct installed-target producer, no full target app success claim")
}
