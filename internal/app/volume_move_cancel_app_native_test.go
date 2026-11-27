// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

func verifyMoveCancelSourceRedeploy(t *testing.T, ctx context.Context, source, target *Runtime, root string, document []byte, original volumes.NativeReady, job control.VolumeMove, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), approve func(control.UserOperation), wait func(string, func() bool), fault *managedCreateReplyFault, reopenSource func() *Runtime) {
	t.Helper()
	if fault == nil || target.backupArtifacts == nil || reopenSource == nil {
		t.Fatal("owned Stop/receive barriers, original source reopen and full real target required")
	}
	taskKey := deployment.ResourceKey("task", "tenant", "app", "web")
	old, err := source.workload.Status(ctx, taskKey)
	if err != nil || !old.Running || old.NativeID == "" {
		t.Fatal("original source Task", err)
	}
	oldRow, err := source.workload.View(taskKey)
	if err != nil || !oldRow.State.Applied.Present {
		t.Fatal(err)
	}
	actual, err := source.docker.API.ContainerInspect(ctx, old.NativeID, client.ContainerInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fault.holdStop(old.NativeID, actual.Container.Name)
	t.Cleanup(fault.releaseStop) // Before producer Close, including t.Fatal.
	// Preparation/private inputs do not consume the receive store. Pause only
	// that original file worker so it cannot race into copy/owner commit after
	// we observe retirement. The provider/Engine/normal producers stay running.
	target.backupArtifacts.mu.Lock()
	var released sync.Once
	resumeTarget := func() { released.Do(target.backupArtifacts.mu.Unlock) }
	t.Cleanup(resumeTarget)
	approve(job.Origin)
	wait("actual original Stop request held during source retirement", func() bool {
		select {
		case <-fault.stopEntered:
			return true
		default:
			return false
		}
	})
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	i, _ := apps.Inventory("tenant", "app")
	if _, retiring := i.Retirement(); !retiring {
		t.Fatal("Stop barrier did not cover the original source retirement")
	}
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, ok := registry.Volume(job.Binding.Scope)
	_, before, found := registry.Move(job.Selection())
	if !ok || !found || before.Phase != volumes.Prepared || before.Fence != nil || before.Manifest != nil || len(core.Consumers()) != 1 {
		t.Fatal("held original Stop already lost its writer or committed a move")
	}
	oldConsumer := core.Consumers()[0]
	call := func(files []*os.File, args ...string) []byte {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, files)
		if err != nil {
			t.Fatal("cancel/redeploy CLI", args, err, string(diagnostic), string(out))
		}
		return out
	}
	payload, _ := json.Marshal(job.Selection())
	changeRaw, err := json.Marshal(control.ChangeDocument{Schema: 1, Action: "cancel-volume-move", Expected: core.Revision(), Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	changeFile := filepath.Join(root, "cancel-retiring-source.json")
	if err = os.WriteFile(changeFile, changeRaw, 0600); err != nil {
		t.Fatal(err)
	}
	call(nil, "manage", "apply", "--request-id", "cancel-retiring-source", "--change", changeFile)
	call(nil, "manage", "result", "--request-id", "cancel-retiring-source")
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	_, cancelling, _ := registry.Move(job.Selection())
	actual, err = source.docker.API.ContainerInspect(ctx, old.NativeID, client.ContainerInspectOptions{})
	if err != nil || actual.Container.State == nil || !actual.Container.State.Running || cancelling.Phase != volumes.Cancelling || cancelling.SourceCleanup != nil || cancelling.CommitRevision != 0 {
		t.Fatal("cancellation fabricated source closure while original Stop was held", err)
	}
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, foundTenant := catalog.Tenant(job.Binding.Scope.Tenant)
	if !foundTenant {
		t.Fatal("original tenant missing")
	}
	change("cancel-revoke-source-placement", "set-nodes", tenant.Revision, control.NodeChangeTo(tenant.ID, tenant.AllowedNodes, []string{job.Binding.Target.Node}))
	catalog, err = p.Catalog(read().State)
	if err != nil || catalog.Authorize("admin", tenant.ID, access.ManageVolumes, job.Binding.Source.Node) == nil {
		t.Fatal("source placement revocation did not take effect", err)
	}
	fault.releaseStop()
	wait("original source closure while target cancellation remains outstanding", func() bool {
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		_, move, ok := v.Move(job.Selection())
		if !ok || move.CancelledTarget != nil || move.CommitRevision != 0 || move.CancelRevision != 0 {
			t.Fatal("held target worker fabricated final cancellation")
		}
		return move.Phase == volumes.Cancelling && move.SourceCleanup != nil
	})
	// The original target file-worker barrier remains held across this actual
	// source restart. Only the source fact is committed; no second operation
	// or fixture-signed closure is allowed to finish the outstanding target.
	source = reopenMoveCancelSource(t, ctx, source, original, job, p, read, reopenSource, volumes.Cancelling)
	call(nil, "manage", "result", "--request-id", "cancel-retiring-source")
	resumeTarget()
	wait("normal source retirement/fence and both original cancellation facts", func() bool {
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		_, move, ok := v.Move(job.Selection())
		return ok && move.Phase == volumes.Cancelled
	})
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, _ = registry.Volume(job.Binding.Scope)
	_, cancelled, _ := registry.Move(job.Selection())
	owner, revision := core.Owner()
	if owner != original.Owner || revision != cancelled.CancelRevision || revision <= job.Binding.SourceOwnerRevision || cancelled.SourceCleanup == nil || cancelled.SourceCleanup.Unchanged || !cancelled.SourceCleanup.RetainedFenced || cancelled.CancelledTarget == nil || cancelled.Fence == nil || cancelled.CommitRevision != 0 || cancelled.Irreversible || core.CheckActivation(oldConsumer) == nil {
		t.Fatal("fenced cancellation did not preserve original source/native and new owner revision")
	}
	if _, err := source.docker.API.ContainerInspect(ctx, old.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("old source Task not actually removed", err)
	}
	if _, err := target.docker.API.VolumeInspect(ctx, job.Binding.Target.Native, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("original prepared target not actually removed", err)
	}
	if len(core.Consumers()) != 0 {
		t.Fatal("cancelled source retains shared consumers")
	}
	apps, err = p.Apps(read().State)
	if err != nil || len(apps.Bindings().Live()) != 0 {
		t.Fatal("cancelled original input/Secret/Volume bindings remain", err)
	}
	source = reopenMoveCancelSource(t, ctx, source, original, job, p, read, reopenSource, volumes.Cancelled)
	cold, err := source.activations.ColdSource(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := source.activations.Checkpoint(cold.Writer)
	if err != nil {
		t.Fatal(err)
	}
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, _ = registry.Volume(job.Binding.Scope)
	call(nil, "manage", "result", "--request-id", "cancel-retiring-source")
	catalog, err = p.Catalog(read().State)
	if err != nil || catalog.Authorize("admin", tenant.ID, access.ManageVolumes, job.Binding.Source.Node) == nil {
		t.Fatal("source restart reset current placement revocation", err)
	}
	_, _, err = core.Acquire(catalog, "admin", core.Revision(), "source-after-cancel", oldConsumer.Generation+1, true)
	if err == nil {
		t.Fatal("cancelled source acquired a new writer through revoked placement")
	}
	tenant, _ = catalog.Tenant(tenant.ID)
	change("cancel-restore-source-placement", "set-nodes", tenant.Revision, control.NodeChangeTo(tenant.ID, tenant.AllowedNodes, []string{job.Binding.Source.Node, job.Binding.Target.Node}))
	file := filepath.Join(root, "source-after-cancel.yaml")
	if err = os.WriteFile(file, document, 0600); err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err = writer.Write([]byte("private-native-group-password\n")); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	writer.Close()
	call([]*os.File{reader}, "compose", "up", "--tenant", "tenant", "--operation", "source-after-cancel", "-f", file, "--no-input", "--group-password-fd", "tenant/group=3")
	reader.Close()
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 {
		t.Fatal("original cancellation fixture deadline unavailable or elapsed")
	}
	remaining := min(time.Until(deadline), 5*time.Minute)
	call(nil, "--timeout", remaining.String(), "compose", "wait", "--tenant", "tenant", "-p", "app", "--operation", "source-after-cancel", "--condition", "healthy")
	resumed, err := source.workload.Status(ctx, taskKey)
	row, rowErr := source.workload.View(taskKey)
	registry, registryErr := p.Volumes(read().State)
	current, found := registry.Native("tenant", "app", "data")
	core, _ = registry.Volume(job.Binding.Scope)
	consumers := core.Consumers()
	if err != nil || rowErr != nil || registryErr != nil || !resumed.Ready || !resumed.Running || resumed.NativeID == old.NativeID || row.State.Applied.Generation <= oldRow.State.Applied.Generation || !found || current.Spec != original.Spec || current.Generation != original.Generation || current.Owner != original.Owner || len(consumers) != 1 || consumers[0].Generation != row.State.Applied.Generation || consumers[0].OwnerRevision != revision || consumers[0] == oldConsumer || core.CheckActivation(oldConsumer) == nil {
		t.Fatal("explicit redeploy did not reuse original Volume with a fresh Task/current consumer", err, rowErr, registryErr)
	}
	gateAfter, err := source.activations.Checkpoint(cold.Writer)
	retainedJob, retainedMove, retained := registry.Move(job.Selection())
	if err != nil || gateAfter.FenceThrough < gate.FenceThrough || !retained || retainedJob.Digest() != job.Digest() || retainedMove.Phase != volumes.Cancelled || retainedMove.CancelRevision != cancelled.CancelRevision {
		t.Fatal("explicit redeploy reset the original fence or cancelled move", err)
	}
	disk, err := source.docker.API.VolumeInspect(ctx, original.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "move-sentinel"))
	if err != nil || string(data) != "original-data-before-move" {
		t.Fatal("explicit source redeploy lost original data", err)
	}
	call(nil, "compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "stop-source-after-cancel")
	wait("explicitly resumed app retires with all original bindings/consumers returned", func() bool {
		a, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		i, _ := a.Inventory("tenant", "app")
		_, active := i.Execution()
		_, retiring := i.Retirement()
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		volume, _ := v.Volume(job.Binding.Scope)
		return !active && !retiring && len(a.Bindings().Live()) == 0 && len(volume.Consumers()) == 0
	})
	for _, member := range []struct {
		runtime    *Runtime
		name, node string
	}{{source, "shared-services", "node-a"}, {target, "move-target-network", "node-b"}} {
		key := (tenancy.SourceIdentity{Kind: "bridge", Tenant: "tenant", Network: member.name, Node: member.node}).Key()
		row, err := member.runtime.network.View(key)
		if err != nil || len(row.Consumers) != 0 || !row.State.Applied.Present {
			t.Fatal("cancel/redeploy retained management network borrow", key, err)
		}
	}
	if err = source.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("actual original Engine Stop held -> current CLI cancel during original retirement -> revoke source placement/no invented closure/owner commit -> release real Stop/receive worker -> normal clean source/fence despite revocation -> source same-DB/key reopen while original target cleanup is still outstanding -> release target worker/normal Cancelled -> source same-DB/key reopen and confirm original result/fence/current revocation/no old writer -> explicit current CAS restores placement -> explicit CLI source app with same physical Volume/data and new Task generation/current consumer -> normal app down/reference return/Snapshot; no old task/fence reset or target activation")
}

// Reopen the actual original source at a caller-selected cancellation phase.
// The normal Runtime owns recovery; this helper only compares durable shared
// evidence and the actual native/gate, and never publishes a cleanup fact.
func reopenMoveCancelSource(t *testing.T, ctx context.Context, source *Runtime, original volumes.NativeReady, job control.VolumeMove, p control.Policy, read func() cluster.View, reopen func() *Runtime, phase volumes.Phase) *Runtime {
	t.Helper()
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	stored, move, found := registry.Move(job.Selection())
	core, haveCore := registry.Volume(job.Binding.Scope)
	if !found || !haveCore || stored.Digest() != job.Digest() || move.Phase != phase || move.SourceCleanup == nil || move.SourceCleanup.Unchanged || !move.SourceCleanup.RetainedFenced || move.Fence == nil || move.CommitRevision != 0 || move.Irreversible || len(core.Consumers()) != 0 {
		t.Fatal("original source closure is not at the requested cancellation phase", phase)
	}
	if phase == volumes.Cancelling && (move.CancelledTarget != nil || move.CancelRevision != 0) || phase == volumes.Cancelled && (move.CancelledTarget == nil || move.CancelRevision == 0) {
		t.Fatal("one-sided cancellation was confused with final cancellation", phase)
	}
	beforeMove, err := json.Marshal(move)
	if err != nil {
		t.Fatal(err)
	}
	beforeCore, err := core.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cold, err := source.activations.ColdSource(ctx, original)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := source.activations.Checkpoint(cold.Writer)
	if err != nil || gate.Starting != nil || gate.FenceThrough < job.Binding.SourceOwnerRevision {
		t.Fatal("source closure lacks its original durable writer fence", phase, err)
	}
	source = reopen()
	if source.Identity.Public != job.Binding.Source.Key {
		t.Fatal("source restart replaced the original identity")
	}
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	stored, move, found = registry.Move(job.Selection())
	core, haveCore = registry.Volume(job.Binding.Scope)
	afterMove, moveErr := json.Marshal(move)
	afterCore, coreErr := core.Encode()
	if !found || !haveCore || moveErr != nil || coreErr != nil || stored.Digest() != job.Digest() || string(afterMove) != string(beforeMove) || string(afterCore) != string(beforeCore) {
		t.Fatal("source restart changed the original cancellation/owner/consumer evidence", phase, moveErr, coreErr)
	}
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	inventory, _ := apps.Inventory(job.Binding.Scope.Tenant, job.Binding.Scope.App)
	_, active := inventory.Execution()
	_, retiring := inventory.Retirement()
	if active || retiring || len(apps.Bindings().Live()) != 0 {
		t.Fatal("source restart resurrected original app/input bindings", phase)
	}
	coldAfter, err := source.activations.ColdSource(ctx, original)
	if err != nil || coldAfter.Writer != cold.Writer || coldAfter.NativeID != cold.NativeID {
		t.Fatal("source restart replaced the original cold source", phase, err)
	}
	reopened, err := source.activations.Checkpoint(cold.Writer)
	if err != nil || reopened.Boot == gate.Boot || reopened.Starting != nil || reopened.FenceThrough != gate.FenceThrough {
		t.Fatal("source restart reset its durable writer fence or old Start", phase, err)
	}
	mounted, err := source.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", original.Owner.Native)})
	if err != nil || len(mounted.Items) != 0 {
		t.Fatal("source restart resurrected an old task or mount", phase, err)
	}
	return source
}
