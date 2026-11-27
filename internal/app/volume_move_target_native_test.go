// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

func cleanupMoveTargetRuntime(t *testing.T, ctx context.Context, docker *engine.Client, root string, cluster, key [32]byte) {
	t.Helper()
	cfg, err := loadTestNode(filepath.Join(root, "provider-node.yaml"))
	if err != nil {
		t.Error(err)
		return
	}
	cleanupOwnedRuntimeSources(t, ctx, docker, cfg, cluster, key)
}

// Shared by the existing target rollback and the RQ7 two-owner fixture. Both
// Runtime producers must be closed before inspecting journals/returning pins.
func cleanupOwnedRuntimeSources(t *testing.T, ctx context.Context, docker *engine.Client, cfg config.Node, cluster, key [32]byte) {
	t.Helper()
	networks, err := network.OpenManager(filepath.Join(cfg.Node.StateDir, "network", "journal.db"), docker)
	if err != nil {
		t.Error(err)
		return
	}
	defer networks.Close()
	cleanupManagedTaskVolumes(t, ctx, docker, cfg, networks, map[string]any{"Cluster": cluster, "NodeKey": key, "KeepImages": true})
	remaining, err := docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.sfc.owner="+docker.Owner)})
	if err != nil || len(remaining.Items) != 0 {
		t.Error("owned target Task remains; retaining original Bridge pins", err)
		return
	}
	if !cleanupManagedRouteNative(t, ctx, cfg, docker.Owner, key, networks, true, false) {
		t.Error("target route/isolation rollback incomplete; retaining Bridge pins")
		return
	}
	for _, key := range networks.Keys() {
		row, err := networks.View(key)
		if err != nil {
			t.Error(err)
			continue
		}
		resource := row.State.Desired.Resource
		if !resource.Present {
			resource = row.State.Applied
		}
		if !resource.Present {
			continue
		}
		spec, err := network.DecodeBridge(resource.Spec)
		if err != nil || spec.Owner != docker.Owner {
			t.Error("target rollback requires the original owned Bridge", err)
			continue
		}
		// Both producers are closed and every owned Task is positively gone.
		// Return the original management borrow as well as native Task pins,
		// using their recorded generations rather than inventing new leases.
		for consumer, pin := range row.Consumers {
			if err = networks.ReturnConsumer(key, consumer, pin.Generation); err != nil {
				t.Error("owned target Bridge consumer rollback", err)
				break
			}
		}
		if err != nil {
			continue
		}
		revision := row.State.Desired.Revision + 1
		if err = networks.Desired(key, revision, resource.Generation, nil, max(1, row.Capacity)); err == nil {
			err = networks.Step(ctx, key)
		}
		if err != nil {
			t.Error("owned target Bridge rollback", err)
			continue
		}
		if gone, err := networks.Gone(ctx, key, revision, resource.Generation, spec); err != nil || !gone {
			t.Error("owned target Bridge remains", err)
		}
	}
}

func verifyMoveTargetActive(t *testing.T, ctx context.Context, source, target *Runtime, original volumes.NativeReady, job control.VolumeMove, p control.Policy, read func() cluster.View, approve func(control.UserOperation), wait func(string, func() bool), scenario managedAppScenario, recoverTransfer func() *Runtime, failedPreparation func(), approveTarget func(control.UserOperation) *Runtime) volumes.NativeReady {
	t.Helper()
	if _, err := source.volumeMovePermit(ctx, job, "quiesce"); err == nil {
		t.Fatal("unapproved target stopped source")
	}
	before, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	_, unapproved, _ := before.Move(job.Selection())
	if unapproved.Preparation != nil {
		t.Fatal("unapproved target published full preparation")
	}
	if approveTarget == nil {
		approve(job.Origin)
	} else {
		target = approveTarget(job.Origin)
	}
	if failedPreparation != nil {
		failedPreparation()
	}
	wait("approved normal target preparation", func() bool {
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		_, m, ok := v.Move(job.Selection())
		return ok && m.Preparation != nil
	})
	if recoverTransfer != nil {
		target = recoverTransfer()
	}
	lastError := ""
	wait("same move automatic owner Arm and target Inventory execution", func() bool {
		target.mu.RLock()
		e := target.volumeBackupError
		moduleErr := target.moduleError
		target.mu.RUnlock()
		diagnostic := ""
		if e != nil {
			diagnostic = "volume: " + e.Error()
		}
		if moduleErr != nil {
			diagnostic += "; module: " + moduleErr.Error()
		}
		if diagnostic != "" && diagnostic != lastError {
			lastError = diagnostic
			t.Log("target move waiting", diagnostic)
		}
		view := read()
		a, err := p.Apps(view.State)
		if err != nil {
			t.Fatal(err)
		}
		execution, ok := a.Execution(job.Binding.Scope.Tenant, job.Binding.Scope.App)
		if !ok || execution.ActiveOperation() != job.App.Target.Operation || execution.Status() != "Succeeded" {
			return false
		}
		registry, err := p.Volumes(view.State)
		if err != nil {
			t.Fatal(err)
		}
		_, move, ok := registry.Move(job.Selection())
		return ok && move.Phase == volumes.Completed
	})
	v, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, _ := v.Volume(job.Binding.Scope)
	_, move, _ := v.Move(job.Selection())
	owner, revision := core.Owner()
	if owner != job.Binding.Target || revision != move.CommitRevision || !move.Irreversible || move.Phase != volumes.Completed || move.ReaderClosed == nil || move.Activated == nil || move.SourceCleanup == nil || move.TargetCleanup == nil {
		t.Fatal("automatic owner/activation/transfer cleanup not published")
	}
	idle := scenario == managedAppVolumeMoveUnused
	if move.Activated.Idle != idle || move.Activated.Running == idle || !idle && move.Activated.Consumer.Writable != (scenario != managedAppVolumeMoveReadonly) || idle && len(core.Consumers()) != 0 {
		t.Fatal("activation fact did not match the original target's actual use")
	}
	if scenario == managedAppVolumeMoveReadonly {
		if len(core.Consumers()) != 2 {
			t.Fatal("readonly completion lost a declared live reader")
		}
		resources, err := p.Resources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		global, globalOK := resources.Quotas.Limit("", job.Target.Node)
		scoped, scopedOK := resources.Quotas.Limit(job.Binding.Scope.Tenant, job.Target.Node)
		native, err := target.nativeVolumes.View(volumes.NativeKey(job.Target))
		if err != nil || !globalOK || !scopedOK || native.Capacity != min(global.MaxConsumers, scoped.MaxConsumers) || len(native.Consumers) != 2 || native.State.Pending != nil || native.State.LastID != 1 || native.State.GenerationFloor != 1 {
			t.Fatal("readonly app did not adopt its quorum consumer limit on the original materialization", err, native.Capacity, len(native.Consumers))
		}
		apps, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		selected := false
		for _, binding := range apps.Bindings().Live() {
			if binding.Needs().Use.Service != "mirror" {
				continue
			}
			for _, pin := range binding.Pins() {
				if pin.Scope == job.Binding.Scope && pin.Consumer == move.Activated.Consumer && !pin.Consumer.Writable {
					selected = true
				}
			}
		}
		mirror, err := target.workload.Status(ctx, deployment.ResourceKey("task", job.Binding.Scope.Tenant, job.Binding.Scope.App, "mirror"))
		if !selected || err != nil || !mirror.Ready || !mirror.Running || mirror.NativeID == "" {
			t.Fatal("readonly activation did not select the first original live Task", err)
		}
	}
	cold, err := source.activations.ColdSource(ctx, original)
	if err != nil || core.CheckActivation(cold.Writer.Consumer) == nil {
		t.Fatal("original writer/fence not retained", err)
	}
	key := deployment.ResourceKey("task", job.Binding.Scope.Tenant, job.Binding.Scope.App, "web")
	status, err := target.workload.Status(ctx, key)
	if err != nil || !status.Ready || !status.Running || status.NativeID == "" {
		t.Fatal("actual target Task", err)
	}
	actual, err := target.docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
	if err != nil || actual.Container.NetworkSettings == nil {
		t.Fatal(err)
	}
	address := ""
	for _, endpoint := range actual.Container.NetworkSettings.Networks {
		if endpoint != nil && endpoint.IPAddress.IsValid() {
			address = endpoint.IPAddress.String()
		}
	}
	if address == "" {
		t.Fatal("target native address")
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(address, "8080")+"/ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		t.Fatal("actual target HTTP", err)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || response.StatusCode != http.StatusOK || string(body) != "sfc-boundary /ping" {
		t.Fatal("actual target response", response.StatusCode, err, closeErr)
	}
	ready, ok := v.Native(job.Binding.Scope.Tenant, job.Binding.Scope.App, job.Binding.Scope.ID)
	if !ok || ready.Owner != job.Binding.Target {
		t.Fatal("same logical Volume lost target native")
	}
	matched := 0
	for _, mount := range actual.Container.Mounts {
		if mount.Name == ready.Owner.Native {
			matched++
			if idle || mount.RW != (scenario != managedAppVolumeMoveReadonly) {
				t.Fatal("target native mount did not match declared use")
			}
		}
	}
	if !idle && matched != 1 || idle && matched != 0 {
		t.Fatal("target native mount missing or fabricated for unused Volume")
	}
	if idle {
		if err := target.nativeVolumes.CheckIdle(ctx, ready); err != nil {
			t.Fatal("unused target retains a local pin or actual Engine attachment", err)
		}
	}
	disk, err := target.docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "move-sentinel"))
	if err != nil || string(data) != "original-data-before-move" {
		t.Fatal("target did not preserve original sentinel", err)
	}
	return ready
}

func verifyAutomaticMoveTarget(t *testing.T, ctx context.Context, source, target *Runtime, root string, compose []byte, original volumes.NativeReady, job control.VolumeMove, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), reject func(string, string, uint64, any, state.Code), approve func(control.UserOperation), wait func(string, func() bool), scenario managedAppScenario, controls managedMoveNativeControls) {
	t.Helper()
	managementBefore := read().State
	var registration control.UserOperation
	if scenario == managedAppCDVolumeMove {
		apps, err := p.Apps(managementBefore)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		registration, found = apps.CDRegistration(job.Binding.Scope.Tenant, job.Binding.Scope.App)
		if !found || job.App == nil || job.App.CD == nil || job.App.CD.Requester != registration.Session.Key || job.App.CD.Principal != registration.Session.User {
			t.Fatal("explicit CD move lost original Group requester/source registration")
		}
	}
	var approveTarget func(control.UserOperation) *Runtime
	var processEvidence *moveProcessCutEvidence
	if scenario == managedAppVolumeMoveProcessCut {
		approveTarget = func(control.UserOperation) *Runtime {
			target, processEvidence = runMoveReceiverProcessCut(t, ctx, target, root, job, p, read, approve, wait, controls)
			return target
		}
	}
	var failedPreparation func()
	if scenario == managedAppVolumeMoveAuto {
		failedPreparation = armMoveNativeReadFailure(t, ctx, source, target, original, job, p, read, wait, controls.targetNetwork)
	}
	var recoverTransfer func() *Runtime
	if scenario == managedAppVolumeMoveAuto {
		recover := armMoveActiveCleanupSyncFailure(t, ctx, target, job, p, read, wait, func() *Runtime { return controls.reopenTarget(nil) })
		recoverTransfer = func() *Runtime {
			target = recover()
			return target
		}
	} else if scenario == managedAppVolumeMoveReadonly || scenario == managedAppVolumeMoveUnused {
		recover := armMoveTargetSyncFailure(t, ctx, target, job, p, read, wait, func() *Runtime { return controls.reopenTarget(nil) })
		recoverTransfer = func() *Runtime {
			target = recover()
			return target
		}
	}
	ready := verifyMoveTargetActive(t, ctx, source, target, original, job, p, read, approve, wait, scenario, recoverTransfer, failedPreparation, approveTarget)
	nativeRetainedSource(t, nativeVolumeShow(t, ctx, root, job.Binding.Scope), job.Binding.ID, job.Binding.Source.Node, "retained")
	if scenario == managedAppVolumeMoveAuto {
		verifyNativeRetainedSourceDeletion(t, ctx, source, root, original, job, p, read, wait, controls)
	}
	if scenario == managedAppVolumeMoveProcessCut {
		verifyMoveProcessCutData(t, ctx, target, ready, job, read, processEvidence)
	}
	if scenario == managedAppVolumeMoveReadonly || scenario == managedAppVolumeMoveUnused {
		target = reopenMoveTargetMode(t, ctx, target, ready, job, p, read, wait, scenario, func() *Runtime { return controls.reopenTarget(nil) })
	}
	a, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	identity, ok := a.Origin(job.Binding.Scope.Tenant, job.Binding.Scope.App)
	var revokedGroup string
	if scenario == managedAppCDVolumeMove {
		if !ok || !bytes.Equal(control.OperationBytes(identity), control.OperationBytes(registration)) || !bytes.Equal(identity.Signature, registration.Signature) {
			t.Fatal("explicit move replaced the signed CD registration")
		}
		execution, active := a.Execution(job.Binding.Scope.Tenant, job.Binding.Scope.App)
		key := deployment.ResourceKey("task", job.Binding.Scope.Tenant, job.Binding.Scope.App, "web")
		stage, exists := execution.Stage(key)
		if !active || !exists || stage.Result == nil || stage.Command == nil {
			t.Fatal("actual CD move target has no original Task receipt")
		}
		binding, bound := a.Binding(deployment.ObjectRef{Key: key, Generation: stage.Result.Generation, Revision: stage.Result.Revision})
		origin, retained := a.BindingSource(binding.Digest())
		registeredCommand, err := registration.Command()
		if err != nil || !bound || !retained || origin.Sync == nil || origin.Sync.User == nil || origin.Sync.User.Change.Action != "begin-volume-move" || !bytes.Equal(control.OperationBytes(*origin.Sync.User), control.OperationBytes(job.Origin)) || !bytes.Equal(origin.Sync.User.Signature, job.Origin.Signature) || binding.Needs().Use.RequesterKey != registration.Session.Key || stage.Command.Actor != registeredCommand.Actor {
			t.Fatal("actual moved Task lost separate move proof/original execution and Group subject", err)
		}
		revokedGroup = verifyNativeCDGroupRevocation(t, ctx, target, root, controls.cdSource, controls.cdTarget, p, read, change, wait)
		a, err = p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
	} else if !ok || identity.Signature == nil || identity.Change.Action != "begin-volume-move" {
		t.Fatal("target lost original signed move")
	}
	if scenario == managedAppVolumeMoveReverse {
		source = verifyReverseMoveTarget(t, ctx, source, target, root, compose, original, ready, job, p, read, reject, wait, controls)
		a, err = p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
	}
	i, _ := a.Inventory(job.Binding.Scope.Tenant, job.Binding.Scope.App)
	if scenario == managedAppCDVolumeMove {
		// Exercise the same durable user intent and target-scoped down CAS as
		// ordinary CLI use, including the currently revoked input approval.
		_, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"compose", "down", "--tenant", job.Binding.Scope.Tenant, "-p", job.Binding.Scope.App, "--operation", "stop-moved-app"}, nil)
		if err != nil {
			t.Fatal("CD target CLI down preserves original intent", err, string(diagnostic))
		}
	} else {
		change("target-app-down", "down-app", i.Revision(), control.AppDown{Tenant: job.Binding.Scope.Tenant, App: job.Binding.Scope.App, Operation: "stop-moved-app"})
	}
	wait("target app actual retirement and references returned", func() bool {
		view := read()
		a, e := p.Apps(view.State)
		if e != nil {
			t.Fatal(e)
		}
		i, _ := a.Inventory(job.Binding.Scope.Tenant, job.Binding.Scope.App)
		_, active := i.Execution()
		_, retiring := i.Retirement()
		v, e := p.Volumes(view.State)
		if e != nil {
			t.Fatal(e)
		}
		volume, _ := v.Volume(job.Binding.Scope)
		return !active && !retiring && len(a.Bindings().Live()) == 0 && len(volume.Consumers()) == 0
	})
	scope := job.Binding.Scope
	users, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"--tenant", scope.Tenant, "volume", "users", scope.App + "/" + scope.ID}, nil)
	var rows []any
	if err != nil || json.Unmarshal(users, &rows) != nil || len(rows) != 0 {
		t.Fatal("retired moved app retained public Volume users", err, string(diagnostic), string(users))
	}
	if page := nativePublicCLI(t, ctx, root, "vault-usages", job.Binding.Scope.Tenant, control.PublicReadQuery{Name: "group"}); len(page.Rows) != 0 {
		t.Fatal("retired moved app retained public Secret uses", page)
	}
	if scenario == managedAppCDVolumeMove {
		wait("original CD source ticket and local readers settle after moved app down", func() bool {
			a, err := p.Apps(read().State)
			d, found := a.Delivery(job.Binding.Scope.Tenant, job.Binding.Scope.App)
			vault, vaultErr := p.Vault(read().State)
			return err == nil && vaultErr == nil && found && d.Quiescent() && source.deliverySourceActive.Load() == 0 && target.deliverySourceActive.Load() == 0 && !vault.Approvals.RevocationPending(revokedGroup)
		})
	}
	for _, member := range []struct {
		runtime *Runtime
		name    string
		node    string
	}{{source, "shared-services", "node-a"}, {target, "move-target-network", "node-b"}} {
		key := (tenancy.SourceIdentity{Kind: "bridge", Tenant: job.Binding.Scope.Tenant, Network: member.name, Node: member.node}).Key()
		original := managementBefore.Object(key)
		if !original.Present || read().State.Object(key) != original {
			t.Fatal("app retirement replaced or deleted original management source", key)
		}
		if _, err := member.runtime.network.Inspect(ctx, key); err != nil {
			t.Fatal("app retirement deleted original management native Bridge", key, err)
		}
		row, err := member.runtime.network.View(key)
		if err != nil || len(row.Consumers) != 0 || !row.State.Desired.Present || !row.State.Applied.Present || row.State.Pending != nil {
			t.Fatal("app retirement did not return all management Bridge borrows", key, err)
		}
	}
	if err = source.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("normal source and target Runtime loops: separate management network creation -> app.yaml named borrows -> original signed move -> target preparation/Group approval/static IP holds -> original retirement/fence/transfer/restore -> automatic atomic owner/native CAS+Arm+same Inventory target execution -> exact target activation/both transfer cleanup proofs/Completed -> actual target Secret/Volume/Task/HTTP and preserved original sentinel -> normal app down/whole borrow return with both management sources/native Bridges preserved/Snapshot; HTTP fixture with two single-member networks, shared Engine with independent owners, no multi-peer TUN/DNS/SQL or retained-source deletion claim; reverse coverage only in the explicit reverse scenario")
}
