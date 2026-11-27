// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestInventoryFencedCancelRedeployPreservesVolumeAndUsesNewTaskConsumer(t *testing.T) {
	x := newInventoryFixture(t)
	volumeKey := "tenant/php-mysql/mysql-data"
	volumeGoal := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	dbTask := ResourceKey("task", "tenant", "php-mysql", "db")
	original := x.f.v[volumeKey]
	source, ownerRevision := original.Owner()
	for _, step := range x.b.Steps() {
		completeInventoryVolumeStep(t, x, step.Key, source.Native)
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	oldVolumeGoal := x.shared.Object(volumeGoal)
	oldTask := x.a.d.Claims[x.a.claim(dbTask)]
	core, oldConsumer, err := original.Acquire(x.f.c, "alice", original.Revision(), "database", oldTask.Result.Generation, true)
	if err != nil {
		t.Fatal(err)
	}
	target := volumes.Owner{Node: "node-a", Key: public(x.f.na), Native: "sfc-cancelled-stage"}
	core, err = core.Prepare(x.f.c, "alice", core.Revision(), ownerRevision, "move", target, [32]byte{51}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := core.Move("move")
	core, err = core.Cancel(x.f.c, "alice", m.Binding.ID, core.Revision())
	if err != nil {
		t.Fatal(err)
	}
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "move-stop", "submitter", 1, nil, true))
	for _, step := range x.b.ReleaseOrder() {
		if !step.Retain {
			x.remove(step.Key)
			continue
		}
		claim := x.a.d.Retirement.Targets[x.a.target(step.Key)].Original
		proof := RetainReceipt{Cluster: x.f.cluster, Retirement: x.a.d.Retirement.ID, StopRevision: x.a.d.Retirement.Revision, Key: step.Key, Native: claim.Native, Owner: step.Owner, Command: state.Digest(claim.Command), Generation: claim.Result.Generation, Revision: claim.Result.Revision, Released: true, Stopped: true, Retained: true, Fenced: true}
		key := x.f.nb
		if step.Owner == public(x.f.na) {
			key = x.f.na
		}
		proof.Signature = ed25519.Sign(key, RetainReceiptBytes(proof))
		x.keep(x.a.Retained(x.a.Revision(), step.Key, &proof))
	}
	x.keep(x.a.FinishRetirement(x.a.Revision()))
	closed := volumes.Gone{Scope: core.Scope(), Consumer: oldConsumer, Stopped: true, MountsGone: true}
	closed.Signature = ed25519.Sign(x.f.nb, volumes.GoneBytes(closed))
	core, err = core.Release(closed)
	if err != nil {
		t.Fatal(err)
	}
	fence := volumes.FenceProof{Binding: m.Binding, FenceThrough: ownerRevision, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
	fence.Signature = ed25519.Sign(x.f.nb, volumes.FenceBytes(fence))
	core, err = core.RecordFence(fence)
	if err != nil {
		t.Fatal(err)
	}
	targetGone := volumes.CancelProof{Binding: m.Binding, StagingGone: true, StartsSettled: true, MountsGone: true, TransferClosed: true}
	targetGone.Signature = ed25519.Sign(x.f.na, volumes.CancelBytes(targetGone))
	core, err = core.RecordCancelTarget(targetGone)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := volumes.CleanupProof{Binding: m.Binding, Owner: source, TransferClosed: true, RetainedFenced: true}
	cleanup.Signature = ed25519.Sign(x.f.nb, volumes.CleanupBytes(cleanup))
	core, err = core.RecordCleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.SettleCancel(m.Binding, core.Revision())
	if err != nil {
		t.Fatal(err)
	}
	x.f.v[volumeKey] = core
	plan, ctx := x.current(smallCompose(t))
	x.keep(x.a.Begin(x.a.Revision(), x.f.c, ctx, plan, "explicit-source-redeploy", "submitter", 1, false))
	x.b = plan
	x.e, _ = x.a.Execution()
	for _, step := range x.b.Steps() {
		completeInventoryVolumeStep(t, x, step.Key, source.Native)
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	currentTask := x.a.d.Claims[x.a.claim(dbTask)]
	if x.shared.Object(volumeGoal) != oldVolumeGoal || currentTask.Result.Generation <= oldTask.Result.Generation {
		t.Fatal("explicit source redeploy recreated its Volume or reused a retired Task")
	}
	if _, _, err = core.Acquire(x.f.c, "alice", core.Revision(), "database", oldConsumer.Generation, true); err == nil {
		t.Fatal("old Task generation reacquired its fenced writer")
	}
	core, consumer, err := core.Acquire(x.f.c, "alice", core.Revision(), "database", currentTask.Result.Generation, true)
	if err != nil || consumer.Owner != source || consumer.OwnerRevision <= ownerRevision || core.CheckActivation(oldConsumer) == nil || core.CheckActivation(consumer) != nil {
		t.Fatal("redeployed Task did not use the new source ownership authority", err)
	}
}
