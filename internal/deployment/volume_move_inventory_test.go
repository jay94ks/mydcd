// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func completeInventoryVolumeStep(t *testing.T, x *inventoryFixture, key, native string) {
	t.Helper()
	x.prepare(key)
	stage, _ := x.e.Stage(key)
	if !stage.Noop {
		cmd := x.send(key)
		result := x.apply(cmd)
		x.save(x.e.Commit(x.e.Revision(), key, cmd, result))
	}
	// Only admitted native observations are fixtures. Ordering still consumes
	// the SAME product activation predicate, command results and Inventory.
	for changed := true; changed; {
		changed = false
		for _, step := range x.b.Steps() {
			record, _ := x.e.Stage(step.Key)
			if step.Node == "" || record.Result == nil || record.Result.Code != state.Applied || record.Observation != nil || !x.e.activationReady(x.e.index(step.Key)) {
				continue
			}
			observation := x.observation(step.Key, true, false)
			if step.Key == ResourceKey("volume", "tenant", "php-mysql", "mysql-data") {
				observation.Native = native
				signer := x.f.nb
				if step.Owner == public(x.f.na) {
					signer = x.f.na
				}
				observation.Signature = ed25519.Sign(signer, ObservationBytes(observation))
			}
			x.save(x.e.Observe(x.e.Revision(), observation, x.now))
			changed = true
		}
	}
}

func TestInventoryMovedVolumeRequiresRetainedProofAndArmedOwner(t *testing.T) {
	x := newInventoryFixture(t)
	key := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	originalOwner, _ := x.f.v["tenant/php-mysql/mysql-data"].Owner()
	complete := func(key, native string) { completeInventoryVolumeStep(t, x, key, native) }
	for _, step := range x.b.Steps() {
		complete(step.Key, originalOwner.Native)
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "move-stop", "submitter", 1, nil, true))
	for _, step := range x.b.ReleaseOrder() {
		if !step.Retain {
			x.remove(step.Key)
			continue
		}
		claim := x.a.d.Retirement.Targets[x.a.target(step.Key)].Original
		proof := RetainReceipt{Cluster: x.f.cluster, Retirement: x.a.d.Retirement.ID, StopRevision: x.a.d.Retirement.Revision, Key: step.Key, Native: claim.Native, Owner: step.Owner, Command: state.Digest(claim.Command), Generation: claim.Result.Generation, Revision: claim.Result.Revision, Released: true, Stopped: true, Retained: true, Fenced: true}
		proof.Signature = ed25519.Sign(x.f.nb, RetainReceiptBytes(proof))
		x.keep(x.a.Retained(x.a.Revision(), step.Key, &proof))
	}
	x.keep(x.a.FinishRetirement(x.a.Revision()))
	old := x.a.d.Claims[x.a.claim(key)]
	scope := x.f.v["tenant/php-mysql/mysql-data"].Scope()
	source := volumes.Owner{Node: old.Step.Node, Key: old.Step.Owner, Native: old.Native}
	core, err := volumes.New(x.f.c, "alice", scope, source, 2)
	if err != nil {
		t.Fatal(err)
	}
	target := volumes.Owner{Node: "node-a", Key: public(x.f.na), Native: "target-mysql"}
	_, revision := core.Owner()
	core, err = core.Prepare(x.f.c, "alice", core.Revision(), revision, "move", target, [32]byte{2}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	m, _ := core.Move("move")
	fence := volumes.FenceProof{Binding: m.Binding, FenceThrough: revision, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
	fence.Signature = ed25519.Sign(x.f.nb, volumes.FenceBytes(fence))
	core, err = core.RecordFence(fence)
	if err != nil {
		t.Fatal(err)
	}
	manifest := volumes.Manifest{Binding: m.Binding, Artifact: [32]byte{3}, Bytes: 4096, Files: 3, ReadOnly: true}
	manifest.Signature = ed25519.Sign(x.f.nb, volumes.ManifestBytes(manifest))
	core, err = core.BeginCopy(manifest)
	if err != nil {
		t.Fatal(err)
	}
	copy := volumes.CopyProof{Binding: m.Binding, Artifact: manifest.Artifact, Bytes: manifest.Bytes, DigestVerified: true, Synced: true, NoWriters: true}
	copy.Signature = ed25519.Sign(x.f.na, volumes.CopyBytes(copy))
	core, err = core.VerifyCopy(copy)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.CommitOwner(x.f.c, "alice", "move", core.Revision(), revision)
	if err != nil {
		t.Fatal(err)
	}
	input := smallCompose(t)
	db := input.Services["db"]
	db.MyDC.Node = "node-a"
	db.Networks["app"] = Attachment{IPv4: "10.240.10.20"}
	input.Services["db"] = db
	v := input.Volumes["mysql-data"]
	v.MyDC.Node = "node-a"
	input.Volumes["mysql-data"] = v
	ctx := contextFor(t, x.f)
	ctx.Current = x.shared.Objects("")
	ctx.Volumes = map[string]volumes.State{"tenant/php-mysql/mysql-data": core}
	if _, err = Compile(input, x.f.c, ctx); err == nil {
		t.Fatal("owner commit alone admitted retained source Goal")
	}
	core, err = core.Arm(x.f.c, "alice", "move", core.Revision())
	if err != nil {
		t.Fatal(err)
	}
	ctx.Volumes["tenant/php-mysql/mysql-data"] = core
	plan, err := Compile(input, x.f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.a.Begin(x.a.Revision(), x.f.c, ctx, plan, "target", "submitter", 1, false); err == nil {
		t.Fatal("ordinary Begin bypassed retained handoff")
	}
	wrong := m.Binding
	wrong.Source.Native = "other-source"
	if _, err = x.a.BeginMoved(x.a.Revision(), x.f.c, ctx, plan, wrong, "target", "submitter", 1); err == nil {
		t.Fatal("wrong source closure accepted")
	}
	x.keep(x.a.BeginMoved(x.a.Revision(), x.f.c, ctx, plan, m.Binding, "target", "submitter", 1))
	x.b = plan
	x.e, _ = x.a.Execution()
	for _, step := range x.b.Steps() {
		complete(step.Key, target.Native)
		if step.Key == key {
			if _, err = x.a.Advance(x.a.Revision(), x.e, x.shared); err == nil {
				t.Fatal("ordinary Advance changed retained owner")
			}
		}
		x.keep(x.a.AdvanceWithVolumes(x.a.Revision(), x.e, x.shared, ctx.Volumes))
	}
	claim := x.a.d.Claims[x.a.claim(key)]
	if claim.Native != target.Native || claim.RetainProof != nil || claim.Retained || len(core.Retained()) != 1 || core.Retained()[0].Owner != source {
		t.Fatal("source evidence copied into target or physical source lost")
	}
}
