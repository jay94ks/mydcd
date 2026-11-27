// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Native observations/copy facts are explicit failure-injection fixtures. The
// actual preview, retirement, owner/fence/Arm and retained handoff are the same
// product cores; this test is not evidence of Docker/disk transfer success.
func TestCDExplicitMoveKeepsSourceAndRequiresPositiveRetainedHandoff(t *testing.T) {
	f, _, ctx, _ := externalFixture(t)
	ctx.Features["git-cd"] = true
	input := smallCompose(t)
	db := input.Services["db"]
	db.Secrets, db.Sfc.Sources = nil, nil
	db.Networks = map[string]Attachment{"source": {IPv4: "10.240.20.10"}}
	input.Services = map[string]ComposeService{"db": db}
	input.Secrets = nil
	input.Networks = map[string]ComposeNetwork{"source": {External: true, Name: "db-services"}}
	var err error
	ctx.Networks, err = ctx.Networks.Create(f.c, "alice", ctx.Networks.Revision(), tenancy.Network{Tenant: "tenant", ID: "db-services", Node: "node-b", Owner: public(f.nb), Pools: []tenancy.Subnet{{ID: "pool", Prefix: mustPrefix("10.240.20.0/24"), Gateway: mustAddr("10.240.20.1"), MTU: 1280}}})
	if err != nil {
		t.Fatal(err)
	}
	sourceKey := ResourceKey("bridge", "tenant", "shared-db", "lan/node-b")
	nodeKey := public(f.nb)
	owner := hex.EncodeToString(f.cluster[:]) + "/" + hex.EncodeToString(nodeKey[:])
	sourceSpec := network.BridgeSpec{Schema: 1, Network: "db-services", Owner: owner, MTU: 1280, Pools: []network.Pool{{ID: "pool", Network: "db-services", Owner: owner, Prefix: mustPrefix("10.240.20.0/24"), Gateway: mustAddr("10.240.20.1"), MTU: 1280}}}
	rawSource, _ := json.Marshal(sourceSpec)
	ctx.Current[sourceKey] = state.Object{Present: true, Revision: 32, Generation: 18, Value: string(rawSource)}
	ctx.ExternalNetworks["source"] = map[string]NetworkBinding{"node-b": {NetworkID: "db-services", SourceKey: sourceKey}}
	ctx.ExternalNetworks["target"] = ctx.ExternalNetworks["app"]
	external := map[string]state.Object{}
	for key, object := range ctx.Current {
		external[key] = object
	}
	_, _, sample, _ := acceptedDeliveryAdapterFixture(t)
	policy, _ := sample.DeliveryPolicy()
	input.Sfc.Delivery = &policy
	b, err := CompileApp(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	i, _ := NewInventory(ctx.Cluster, "tenant", "php-mysql", "deploy")
	i, err = i.Begin(i.Revision(), f.c, ctx, b, "original", "submitter", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewAcceptedDelivery(b, i, f.c)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := i.Execution()
	shared, _ := state.New("submitter")
	x := &inventoryFixture{executionFixture: &executionFixture{f: f, b: b, e: e, shared: shared, now: 100}, a: i}
	core := f.v["tenant/php-mysql/mysql-data"]
	source, revision := core.Owner()
	for _, step := range b.Steps() {
		completeInventoryVolumeStep(t, x, step.Key, source.Native)
	}
	x.save(x.e.Finish(x.e.Revision(), 100))
	x.sync()
	d, err = d.FollowInventory(d.Revision(), x.a)
	if err != nil {
		t.Fatal(err)
	}
	for key, object := range x.shared.Objects("") {
		ctx.Current[key] = object
	}
	body, _ := marshalApp(b.d.Input)
	next, err := ParseApp(body)
	if err != nil {
		t.Fatal(err)
	}
	db = next.Services["db"]
	db.Sfc.Node = "node-a"
	db.Networks = map[string]Attachment{"target": {IPv4: "10.240.10.20"}}
	next.Services["db"] = db
	next.Networks = map[string]ComposeNetwork{"target": {External: true, Name: "shared-lan"}}
	volume := next.Volumes["mysql-data"]
	volume.Sfc.Node = "node-a"
	next.Volumes["mysql-data"] = volume
	target := volumes.Owner{Node: "node-a", Key: public(f.na), Native: "target-data"}
	placement := VolumeMovePlacement{Scope: core.Scope(), Source: source, SourceOwnerRevision: revision, Target: target}
	frozen, err := d.PlanMoved(next, f.c, ctx, placement)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Scope().Actor != d.Principal() || frozen.AppInputDigest() == ([32]byte{}) {
		t.Fatal("move preview changed registered principal or lost input")
	}
	before, _ := core.Encode()
	unchanged, _ := ctx.Volumes[VolumeKey(core.Scope())].Encode()
	if !bytes.Equal(before, unchanged) {
		t.Fatal("preview changed real Volume owner")
	}
	df := &deliveryFixture{executionFixture: x.executionFixture, d: d, ctx: ctx}
	df.beginTransition("move-stop", DeliveryDown)
	if _, err := df.d.StartMoved(df.d.Revision(), f.c, ctx, frozen, volumes.Binding{}, "admin", "target", "submitter", 1); err == nil {
		t.Fatal("move bypassed original retirement/fence")
	}
	df.closeTargets()
	df.finishRetirement()
	core, err = core.Prepare(f.c, "alice", core.Revision(), revision, "explicit-move", target, [32]byte{2}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	move, _ := core.Move("explicit-move")
	fence := volumes.FenceProof{Binding: move.Binding, FenceThrough: revision, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
	fence.Signature = ed25519.Sign(f.nb, volumes.FenceBytes(fence))
	core, err = core.RecordFence(fence)
	if err != nil {
		t.Fatal(err)
	}
	manifest := volumes.Manifest{Binding: move.Binding, Artifact: [32]byte{3}, Bytes: 4096, Files: 3, ReadOnly: true}
	manifest.Signature = ed25519.Sign(f.nb, volumes.ManifestBytes(manifest))
	core, err = core.BeginCopy(manifest)
	if err != nil {
		t.Fatal(err)
	}
	verified := volumes.CopyProof{Binding: move.Binding, Artifact: manifest.Artifact, Bytes: manifest.Bytes, DigestVerified: true, Synced: true, NoWriters: true}
	verified.Signature = ed25519.Sign(f.na, volumes.CopyBytes(verified))
	core, err = core.VerifyCopy(verified)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.CommitOwner(f.c, "alice", move.Binding.ID, core.Revision(), revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Arm(f.c, "alice", move.Binding.ID, core.Revision())
	if err != nil {
		t.Fatal(err)
	}
	ctx = df.ctx
	// These are explicitly modeled management observations, independent of
	// the app retirement above. A down must not erase a borrowed source.
	for key, object := range external {
		ctx.Current[key] = object
	}
	ctx.Volumes = map[string]volumes.State{VolumeKey(core.Scope()): core}
	plan, err := frozen.Rebase(f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	wrong := move.Binding
	wrong.Source.Native = "another-source"
	original, _ := df.d.Encode()
	if _, err := df.d.StartMoved(df.d.Revision(), f.c, ctx, plan, wrong, "admin", "target", "submitter", 1); err == nil {
		t.Fatal("wrong source fence was adopted")
	}
	after, _ := df.d.Encode()
	if !bytes.Equal(original, after) {
		t.Fatal("rejected handoff rewrote source state")
	}
	moved, err := df.d.StartMoved(df.d.Revision(), f.c, ctx, plan, move.Binding, "admin", "target", "submitter", 1)
	if err != nil {
		t.Fatal(err)
	}
	selected, ok := moved.Selection()
	if !ok || selected.Intent != frozen.IntentDigest() || selected.Artifact != frozen.AppInputDigest() || selected.Operation != "target" || selected.Submitter != "submitter" || moved.Principal() != "alice" || moved.Policy().Source.Repository != policy.Source.Repository || moved.Paused() {
		t.Fatal("explicit move replaced CD registration/choice")
	}
	if moved.d.Candidate.Artifact.Digest != d.d.Candidate.Artifact.Digest {
		t.Fatal("move file replaced queued Git source")
	}
	if raw, err := moved.Encode(); err != nil {
		t.Fatal(err)
	} else if _, err := DecodeDelivery(raw); err != nil {
		t.Fatal("moved source could not restore", err)
	}
}
