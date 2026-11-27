// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/schema"
)

type inventoryFixture struct {
	*executionFixture
	a Inventory
}

func inventoryFor(t *testing.T, x *executionFixture, ctx PlanningContext) *inventoryFixture {
	t.Helper()
	a, err := NewInventory(x.f.cluster, "tenant", "php-mysql", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	a, err = a.Begin(a.Revision(), x.f.c, ctx, x.b, "operation", "submitter", 1, false)
	if err != nil {
		t.Fatal(err)
	}
	x.e, _ = a.Execution()
	return &inventoryFixture{x, a}
}
func newInventoryFixture(t *testing.T) *inventoryFixture {
	x := runFixture(t)
	return inventoryFor(t, x, contextFor(t, x.f))
}
func (x *inventoryFixture) keep(a Inventory, err error) {
	x.f.t.Helper()
	if err != nil {
		x.f.t.Fatal(err)
	}
	raw, err := a.Encode()
	if err != nil {
		x.f.t.Fatal("inventory encode", err)
	}
	x.a, err = DecodeInventory(raw)
	if err != nil {
		x.f.t.Fatal("inventory restore", err)
	}
}
func (x *inventoryFixture) sync() {
	x.f.t.Helper()
	x.keep(x.a.Advance(x.a.Revision(), x.e, x.shared))
}
func (x *inventoryFixture) all() {
	x.f.t.Helper()
	for _, s := range x.b.Steps() {
		x.completeStep(s.Key)
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
}
func (x *inventoryFixture) current(c Compose) (Blueprint, PlanningContext) {
	x.f.t.Helper()
	ctx := contextFor(x.f.t, x.f)
	ctx.Current = x.shared.Objects("")
	b, err := Compile(c, x.f.c, ctx)
	if err != nil {
		x.f.t.Fatal(err)
	}
	return b, ctx
}
func (x *inventoryFixture) phase(key, phase string) {
	x.f.t.Helper()
	m, ok := x.a.Removal(key, phase)
	if !ok {
		x.f.t.Fatal("missing original phase", key, phase)
	}
	x.keep(x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, phase))
	x.apply(m.Command)
	x.keep(x.a.SettleRemoval(x.a.Revision(), key, phase, x.shared))
}
func (x *inventoryFixture) remove(key string) {
	x.f.t.Helper()
	if m, ok := x.a.Removal(key, "drain"); ok {
		x.phase(key, "drain")
		c := x.a.d.Retirement.Targets[x.a.target(key)].Original
		owner := x.f.na
		if c.Step.Owner == public(x.f.nb) {
			owner = x.f.nb
		}
		proof := ed25519.Sign(owner, schema.GoneBytes(x.f.cluster, key, c.Result.Generation, []byte(m.Command.Value)))
		x.keep(x.a.Gone(x.a.Revision(), key, proof))
		x.phase(key, "proof")
	}
	x.phase(key, "delete")
}

func TestInventoryExecutionViewPreservesOriginalAndOwnsPublicValues(t *testing.T) {
	x := newInventoryFixture(t)
	unchanged := func(a Inventory, before []byte) {
		t.Helper()
		after, err := a.Encode()
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("execution reader changed original inventory", err)
		}
	}
	before, _ := x.a.Encode()
	view, _ := x.a.Execution()
	key := x.b.Steps()[0].Key
	prepared, _, err := view.Prepare(x.f.c, view.Revision(), key, x.shared.Object(key), x.now)
	if err != nil {
		t.Fatal(err)
	}
	unchanged(x.a, before)
	a, err := x.a.Advance(x.a.Revision(), prepared, x.shared)
	if err != nil {
		t.Fatal(err)
	}
	before, _ = a.Encode()
	view, _ = a.Execution()
	stage, _ := view.Stage(key)
	stage.Command.Value = "foreign"
	stage.Journal.Pending.Phase++
	steps := view.Steps()
	steps[0].Goal[0] ^= 1
	unchanged(a, before)
	sent, _, err := view.Send(x.f.c, view.Revision(), key, x.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sent.Unknown(sent.Revision(), key); err != nil {
		t.Fatal(err)
	}
	unchanged(a, before)
	other, _ := a.Execution()
	left, _ := view.Encode()
	right, _ := other.Encode()
	if !bytes.Equal(left, right) {
		t.Fatal("one transition changed another execution reader")
	}
	x = newInventoryFixture(t)
	x.all()
	before, _ = x.a.Encode()
	view, _ = x.a.Execution()
	for _, step := range view.Steps() {
		stage, _ := view.Stage(step.Key)
		if stage.Result != nil {
			stage.Result.Generation++
		}
		if stage.Observation != nil && len(stage.Observation.Signature) > 0 {
			stage.Observation.Signature[0] ^= 1
		}
	}
	if _, err = view.Stop(x.f.c, "alice", view.Revision()); err != nil {
		t.Fatal(err)
	}
	unchanged(x.a, before)
}

func TestInventoryPreservesUnknownOriginalAndRejectsFabricatedResults(t *testing.T) {
	x := newInventoryFixture(t)
	key := x.b.Steps()[0].Key
	cmd := x.prepare(key)
	x.send(key)
	x.save(x.e.Unknown(x.e.Revision(), key))
	x.sync()
	_, err := x.a.Begin(x.a.Revision(), x.f.c, contextFor(t, x.f), x.b, "replacement", "submitter", 1, false)
	deny(t, err)
	_, err = x.a.Begin(x.a.Revision()-1, x.f.c, contextFor(t, x.f), x.b, "operation", "submitter", 1, false)
	deny(t, err)
	r := x.apply(cmd)
	x.save(x.e.Commit(x.e.Revision(), key, cmd, r))
	empty, _ := state.New("submitter")
	_, err = x.a.Advance(x.a.Revision(), x.e, empty)
	deny(t, err)
	x.sync()
	if len(x.a.Claims()) != 1 || x.a.Claims()[0].Command != cmd {
		t.Fatal("original ownership lost")
	}
	prior, _ := x.a.Encode()
	claims := x.a.Claims()
	claims[0].Command.Value = "corrupt"
	after, _ := x.a.Encode()
	if !bytes.Equal(prior, after) {
		t.Fatal("caller mutated inventory")
	}
}

func TestInventoryNoopAndOrphanUnionAcrossOperations(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	originalClaims := x.a.Claims()
	c := smallCompose(t)
	delete(c.Services, "web")
	b, ctx := x.current(c)
	changes, err := x.a.Changes(b, false)
	if err != nil {
		t.Fatal(err)
	}
	web := ResourceKey("task", "tenant", "php-mysql", "web")
	for _, change := range changes {
		if change.Key == web && change.Action != "KeepOrphan" {
			t.Fatal("implicit prune")
		}
	}
	_, err = x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "pruned", "submitter", 1, true)
	deny(t, err)
	x.keep(x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "next", "submitter", 1, false))
	x.b = b
	x.e, _ = x.a.Execution()
	index := x.shared.Index()
	x.all()
	if x.shared.Index() != index || len(x.a.Claims()) != len(originalClaims) || len(x.a.d.History) != 1 {
		t.Fatal("noop reset ownership or submitted again")
	}
	for _, original := range originalClaims {
		current := x.a.d.Claims[x.a.claim(original.Step.Key)]
		if current.Command != original.Command || current.Result != original.Result || current.Operation != original.Operation || current.Plan != original.Plan || current.Native != original.Native {
			t.Fatal("Noop replaced the original native/binding provenance", original.Step.Key)
		}
	}
	for _, step := range x.e.Steps() {
		stage, _ := x.e.Stage(step.Key)
		if stage.Observation != nil && (stage.Observation.Operation != "next" || stage.Observation.Plan != b.Digest()) {
			t.Fatal("current execution reused an old health proof")
		}
	}
	for _, tamper := range []func(*inventoryRecord){
		func(d *inventoryRecord) { d.Active.Stages[0].Noop = false },
		func(d *inventoryRecord) { d.Claims[0].Command.Value += " " },
		func(d *inventoryRecord) { d.Claims[0].Removed = true },
	} {
		raw, _ := x.a.Encode()
		var corrupt inventoryRecord
		_ = json.Unmarshal(raw, &corrupt)
		tamper(&corrupt)
		raw, _ = json.Marshal(corrupt)
		if _, err := DecodeInventory(raw); err == nil {
			t.Fatal("mismatched original Noop claim survived checkpoint decoding")
		}
	}
	_, err = x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "operation", "submitter", 1, false)
	deny(t, err)
}

func TestInventoryChangedTaskOrProducerRequiresOriginalDependentClosure(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	c := smallCompose(t)
	db := c.Services["db"]
	db.Image = strings.ReplaceAll(db.Image, strings.Repeat("a", 64), strings.Repeat("b", 64))
	c.Services["db"] = db
	b, ctx := x.current(c)
	changes, err := x.a.Changes(b, false)
	if err != nil {
		t.Fatal(err)
	}
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	originalGeneration := x.shared.Object(key).Generation
	for _, change := range changes {
		if change.Key == key && change.Action != "Replace" {
			t.Fatal("changed native was in-place noop")
		}
	}
	_, err = x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "update", "submitter", 1, false)
	deny(t, err)
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "update", "submitter", 1, []string{key}, false))
	for _, kind := range []string{"task", "inputs"} {
		for _, id := range []string{"db", "web"} {
			if x.a.target(ResourceKey(kind, "tenant", "php-mysql", id)) < 0 {
				t.Fatal("missing affected consumer", kind, id)
			}
		}
	}
	if x.a.target(ResourceKey("volume", "tenant", "php-mysql", "mysql-data")) >= 0 {
		t.Fatal("task replacement erased retained volume")
	}
	_, err = x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, "drain")
	deny(t, err) // web must stop before its database.
	x.remove(ResourceKey("task", "tenant", "php-mysql", "web"))
	x.remove(key)
	x.remove(ResourceKey("inputs", "tenant", "php-mysql", "web"))
	x.remove(ResourceKey("inputs", "tenant", "php-mysql", "db"))
	x.keep(x.a.FinishRetirement(x.a.Revision()))
	b, ctx = x.current(c)
	x.keep(x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "updated", "submitter", 1, false))
	x.b = b
	x.e, _ = x.a.Execution()
	x.all()
	i := x.a.claim(key)
	if x.a.d.Claims[i].Removed || x.a.d.Claims[i].Result.Generation <= originalGeneration {
		t.Fatal("new generation not created")
	}
}

func TestInventoryDownSettlesOriginalLateCommitAndRemovalUnknown(t *testing.T) {
	x := newInventoryFixture(t)
	key := x.b.Steps()[0].Key
	cmd := x.prepare(key)
	x.send(key)
	x.save(x.e.Unknown(x.e.Revision(), key))
	x.sync()
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "down", "submitter", 1, nil, true))
	x.e, _ = x.a.Execution()
	_, err := x.a.FinishRetirement(x.a.Revision())
	deny(t, err)
	x.save(x.e.Commit(x.e.Revision(), key, cmd, x.apply(cmd)))
	x.sync()
	m, ok := x.a.Removal(key, "drain")
	if !ok {
		t.Fatal("late applied object escaped inventory")
	}
	x.keep(x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, "drain"))
	x.keep(x.a.UnknownRemoval(x.a.Revision(), key, "drain"))
	_, err = x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, "drain")
	deny(t, err)
	_, err = x.a.SettleRemoval(x.a.Revision(), key, "drain", x.shared)
	deny(t, err)
	x.apply(m.Command)
	x.keep(x.a.SettleRemoval(x.a.Revision(), key, "drain", x.shared))
	c := x.a.d.Retirement.Targets[x.a.target(key)].Original
	proof := ed25519.Sign(x.f.na, schema.GoneBytes(x.f.cluster, key, c.Result.Generation, []byte(m.Command.Value)))
	wrong := bytes.Clone(proof)
	wrong[0] ^= 1
	_, err = x.a.Gone(x.a.Revision(), key, wrong)
	deny(t, err)
	x.keep(x.a.Gone(x.a.Revision(), key, proof))
	x.phase(key, "proof")
	x.phase(key, "delete")
	x.keep(x.a.FinishRetirement(x.a.Revision()))
	if x.shared.Object(key).Present || !x.a.d.Claims[0].Removed {
		t.Fatal("original native reservation not settled")
	}
}

func TestInventoryDownRetainsFencedDataAndRequiresFreshStopReceipt(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	volume := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	original := x.shared.Object(volume)
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "down", "submitter", 1, nil, true))
	_, err := x.a.FinishRetirement(x.a.Revision())
	deny(t, err)
	for _, step := range x.b.ReleaseOrder() {
		if step.Retain {
			if step.Owner == ([32]byte{}) {
				x.keep(x.a.Retained(x.a.Revision(), step.Key, nil))
				continue
			}
			claim := x.a.d.Retirement.Targets[x.a.target(step.Key)].Original
			o := RetainReceipt{Cluster: x.f.cluster, Retirement: x.a.d.Retirement.ID, StopRevision: x.a.d.Retirement.Revision, Key: step.Key, Native: claim.Native, Owner: step.Owner, Command: state.Digest(claim.Command), Generation: claim.Result.Generation, Revision: claim.Result.Revision, Released: true, Stopped: true, Retained: true, Fenced: true}
			o.Signature = ed25519.Sign(x.f.nb, RetainReceiptBytes(o))
			for _, alter := range []func(*RetainReceipt){func(v *RetainReceipt) { v.StopRevision-- }, func(v *RetainReceipt) { v.Fenced = false }, func(v *RetainReceipt) { v.Pins = 1 }} {
				bad := o
				alter(&bad)
				bad.Signature = ed25519.Sign(x.f.nb, RetainReceiptBytes(bad))
				_, err = x.a.Retained(x.a.Revision(), step.Key, &bad)
				deny(t, err)
			}
			a, err := x.a.Retained(x.a.Revision(), step.Key, &o)
			o.Signature[0] ^= 1 // candidate must own proof bytes.
			x.keep(a, err)
		} else {
			x.remove(step.Key)
		}
	}
	x.keep(x.a.FinishRetirement(x.a.Revision()))
	if x.shared.Object(volume) != original || !x.a.d.Claims[x.a.claim(volume)].Retained || x.a.d.Claims[x.a.claim(volume)].Removed {
		t.Fatal("retained data erased or unfenced")
	}
}

func TestInventorySnapshotRejectsLostOwnershipUnknownOrFrozenRemoval(t *testing.T) {
	x := newInventoryFixture(t)
	x.completeStep(x.b.Steps()[0].Key)
	x.sync()
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "down", "submitter", 1, nil, true))
	key := x.b.Steps()[0].Key
	x.keep(x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, "drain"))
	x.keep(x.a.UnknownRemoval(x.a.Revision(), key, "drain"))
	raw, _ := x.a.Encode()
	for _, alter := range []func(*inventoryRecord){
		func(d *inventoryRecord) { d.Claims = nil },
		func(d *inventoryRecord) { d.Retirement.Targets = nil },
		func(d *inventoryRecord) { d.Retirement.Targets[0].Drain.Command.RequestID = "replacement" },
		func(d *inventoryRecord) { d.Retirement.Targets[0].Drain.Journal.Pending = nil },
		func(d *inventoryRecord) { d.Retirement.Targets[0].Closed = true },
	} {
		var d inventoryRecord
		_ = json.Unmarshal(raw, &d)
		alter(&d)
		bad, _ := json.Marshal(d)
		_, err := DecodeInventory(bad)
		deny(t, err)
	}
}

func TestInventoryBorrowedNetworkDownNeverDeletesManagedSource(t *testing.T) {
	f, c, ctx, source := externalFixture(t)
	shared, _ := state.New("submitter")
	shared, _, err := state.Apply(shared, 1, state.Command{Actor: "submitter", Epoch: 1, RequestID: "managed-source", Key: source, Value: ctx.Current[source].Value})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Current[source] = shared.Object(source)
	b, err := Compile(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	x := inventoryFor(t, &executionFixture{f: f, b: b, shared: shared, now: 100}, ctx)
	x.all()
	before := x.shared.Object(source)
	x.keep(x.a.Retire(x.a.Revision(), f.c, "alice", "down", "submitter", 1, nil, true))
	for _, step := range b.ReleaseOrder() {
		x.remove(step.Key)
	}
	x.keep(x.a.FinishRetirement(x.a.Revision()))
	if x.shared.Object(source) != before || x.a.claim(source) >= 0 {
		t.Fatal("borrowed source was taken over or erased")
	}
}

func TestInventoryChangedProducerPositionInvalidatesConsumers(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	volume := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	old := x.shared.Object(volume)
	x.apply(state.Command{Actor: "submitter", Epoch: 1, RequestID: "changed-producer", Key: volume, Value: old.Value, Expected: old.Revision})
	b, ctx := x.current(smallCompose(t))
	changes, err := x.a.Changes(b, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"db", "web"} {
		key := ResourceKey("task", "tenant", "php-mysql", id)
		found := false
		for _, c := range changes {
			if c.Key == key {
				found = c.Action == "Replace"
			}
		}
		if !found {
			t.Fatal("unchanged config hid stale producer binding", id)
		}
	}
	_, err = x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "stale", "submitter", 1, false)
	deny(t, err)
}

func TestInventoryDuplicateProofResultCannotResetUnknownDelete(t *testing.T) {
	x := newInventoryFixture(t)
	key := x.b.Steps()[0].Key
	x.completeStep(key)
	x.sync()
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "down", "submitter", 1, nil, true))
	x.phase(key, "drain")
	m, _ := x.a.Removal(key, "drain")
	c := x.a.d.Retirement.Targets[x.a.target(key)].Original
	proof := ed25519.Sign(x.f.na, schema.GoneBytes(x.f.cluster, key, c.Result.Generation, []byte(m.Command.Value)))
	x.keep(x.a.Gone(x.a.Revision(), key, proof))
	x.phase(key, "proof")
	x.keep(x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, "delete"))
	x.keep(x.a.UnknownRemoval(x.a.Revision(), key, "delete"))
	before, _ := x.a.Encode()
	x.keep(x.a.SettleRemoval(x.a.Revision(), key, "proof", x.shared))
	after, _ := x.a.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("duplicate ACK reset original unknown delete")
	}
	_, err := x.a.SendRemoval(x.a.Revision(), x.f.c, "alice", key, "delete")
	deny(t, err)
}

func TestInventoryWindowRotationRequiresCommittedEpochAndPreservesNativeClaims(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	before := goal(x.a.Claims())
	_, err := x.a.RotateWindow(x.a.Revision(), x.f.c, "alice", x.shared)
	deny(t, err)
	_, _, revision, _ := x.shared.Principal("submitter")
	r := x.apply(state.Command{Actor: "submitter", Epoch: 1, RequestID: "rotate-ledger", Kind: state.RotateLedger, Target: "submitter", Expected: revision})
	if r.Code != state.Applied {
		t.Fatal("fixture did not commit ledger rotation")
	}
	x.keep(x.a.RotateWindow(x.a.Revision(), x.f.c, "alice", x.shared))
	if !bytes.Equal(before, goal(x.a.Claims())) || x.a.d.Active != nil || len(x.a.d.History) != 0 {
		t.Fatal("compaction lost owned native state")
	}
	b, ctx := x.current(smallCompose(t))
	_, err = x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "operation", "submitter", 1, false)
	deny(t, err)
	x.keep(x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "operation", "submitter", 2, false))
	x.b = b
	x.e, _ = x.a.Execution()
	index := x.shared.Index()
	x.all()
	if x.shared.Index() != index {
		t.Fatal("new epoch recreated unchanged native objects")
	}
}

func TestInventoryWindowRotationCannotDiscardUnknownAfterLedgerRotation(t *testing.T) {
	x := newInventoryFixture(t)
	key := x.b.Steps()[0].Key
	x.prepare(key)
	x.send(key)
	x.save(x.e.Unknown(x.e.Revision(), key))
	x.sync()
	_, _, revision, _ := x.shared.Principal("submitter")
	x.apply(state.Command{Actor: "submitter", Epoch: 1, RequestID: "rotate-ledger", Kind: state.RotateLedger, Target: "submitter", Expected: revision})
	_, err := x.a.RotateWindow(x.a.Revision(), x.f.c, "alice", x.shared)
	deny(t, err)
}

func TestInventoryRetainedRedeployUsesSameVolumeAndFreshTaskGenerations(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	volume := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	originalVolume := x.shared.Object(volume)
	oldGenerations := map[string]uint64{}
	for _, c := range x.a.Claims() {
		oldGenerations[c.Step.Key] = c.Result.Generation
	}
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "down", "submitter", 1, nil, true))
	for _, step := range x.b.ReleaseOrder() {
		if !step.Retain {
			x.remove(step.Key)
			continue
		}
		c := x.a.d.Retirement.Targets[x.a.target(step.Key)].Original
		o := RetainReceipt{Cluster: x.f.cluster, Retirement: x.a.d.Retirement.ID, StopRevision: x.a.d.Retirement.Revision, Key: step.Key, Native: c.Native, Owner: step.Owner, Command: state.Digest(c.Command), Generation: c.Result.Generation, Revision: c.Result.Revision, Released: true, Stopped: true, Retained: true, Fenced: true}
		o.Signature = ed25519.Sign(x.f.nb, RetainReceiptBytes(o))
		x.keep(x.a.Retained(x.a.Revision(), step.Key, &o))
	}
	x.keep(x.a.FinishRetirement(x.a.Revision()))
	b, ctx := x.current(smallCompose(t))
	x.keep(x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "redeploy", "submitter", 1, false))
	x.b = b
	x.e, _ = x.a.Execution()
	x.all()
	if x.shared.Object(volume) != originalVolume {
		t.Fatal("retained volume was replaced or rewritten")
	}
	for _, c := range x.a.Claims() {
		if c.Removed || c.Retained {
			t.Fatal("new deployment kept retired native state", c.Step.Key)
		}
		if c.Step.Kind == "task" && c.Result.Generation <= oldGenerations[c.Step.Key] {
			t.Fatal("old task generation reactivated")
		}
	}
}

func TestInventorySecondDownAfterSelectingRestoredVolume(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	closeAll := func(id string) {
		t.Helper()
		x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", id, "submitter", 1, nil, true))
		for {
			r, _ := x.a.Retirement()
			left, progressed := 0, false
			for _, target := range r.Targets {
				if target.Closed {
					continue
				}
				left++
				c := target.Original
				if !x.a.CanRetire(c.Step.Key) {
					continue
				}
				if !c.Step.Retain {
					x.remove(c.Step.Key)
				} else {
					proof := RetainReceipt{Cluster: x.f.cluster, Retirement: r.ID, StopRevision: r.Revision, Key: c.Step.Key, Native: c.Native, Owner: c.Step.Owner, Command: state.Digest(c.Command), Generation: c.Result.Generation, Revision: c.Result.Revision, Released: true, Stopped: true, Retained: true, Fenced: true}
					owner := x.f.nb
					if c.Step.Owner == public(x.f.na) {
						owner = x.f.na
					}
					proof.Signature = ed25519.Sign(owner, RetainReceiptBytes(proof))
					x.keep(x.a.Retained(x.a.Revision(), c.Step.Key, &proof))
				}
				progressed = true
			}
			if left == 0 {
				break
			}
			if !progressed {
				t.Fatal("retirement dependency deadlock", id, left)
			}
		}
		x.keep(x.a.FinishRetirement(x.a.Revision()))
	}
	closeAll("cold-down")
	c := smallCompose(t)
	c.Volumes["restored"] = c.Volumes["mysql-data"]
	delete(c.Volumes, "mysql-data")
	db := c.Services["db"]
	for i := range db.Volumes {
		if db.Volumes[i].Source == "mysql-data" {
			db.Volumes[i].Source = "restored"
		}
	}
	c.Services["db"] = db
	b, ctx := x.current(c)
	x.keep(x.a.Begin(x.a.Revision(), x.f.c, ctx, b, "restored-rollout", "submitter", 1, false))
	x.b, x.e = b, Execution{}
	x.e, _ = x.a.Execution()
	x.all()
	closeAll("restored-down")
}
