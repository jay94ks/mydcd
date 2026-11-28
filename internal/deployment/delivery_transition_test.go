// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"gopkg.in/yaml.v3"
)

func newTransitionFixture(t *testing.T, prune, empty bool) *deliveryFixture {
	t.Helper()
	f := newDeliveryFixture(t, "automatic")
	c, err := ParseCompose(f.body)
	if err != nil {
		t.Fatal(err)
	}
	c.Sfc.Delivery.Sync.Prune = prune
	_ = empty // an empty services map is allowed whenever x-sfc.cd is present
	f.body, err = yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	f.saveDelivery(NewDelivery(f.f.c, f.ctx, f.body))
	f.receive(f.body)
	f.start("first")
	f.completeDelivery()
	return f
}
func (f *deliveryFixture) imageChange(digit string) []byte {
	f.f.t.Helper()
	c, err := ParseCompose(f.body)
	if err != nil {
		f.f.t.Fatal(err)
	}
	service := c.Services["db"]
	service.Image = "docker.io/library/mysql@sha256:" + strings.Repeat(digit, 64)
	c.Services["db"] = service
	raw, err := yaml.Marshal(c)
	if err != nil {
		f.f.t.Fatal(err)
	}
	return raw
}
func (f *deliveryFixture) beginTransition(id string, mode DeliveryTransitionMode) {
	f.f.t.Helper()
	f.saveDelivery(f.d.BeginTransition(f.d.Revision(), f.f.c, f.ctx, "alice", id, f.e.d.Submitter, f.e.d.Epoch, mode))
	if e, ok := f.d.Inventory().Execution(); ok {
		f.e = e
		f.b = Blueprint{e.d.Plan}
	}
}
func (f *deliveryFixture) retirementPhase(key, phase string) {
	f.f.t.Helper()
	m, ok := f.d.Inventory().Removal(key, phase)
	if !ok {
		f.f.t.Fatal("missing original removal", key, phase)
	}
	f.saveDelivery(f.d.SendRemoval(f.d.Revision(), f.f.c, "alice", key, phase))
	result := f.apply(m.Command)
	if result.Code != state.Applied {
		f.f.t.Fatal("retirement command did not commit", key, phase, m.Command.Actor, result)
	}
	f.saveDelivery(f.d.SettleRemoval(f.d.Revision(), key, phase, f.shared))
	f.ctx.Current = f.shared.Objects("")
}
func (f *deliveryFixture) closeTarget(key string) {
	f.f.t.Helper()
	a := f.d.Inventory()
	at := a.target(key)
	if at < 0 {
		f.f.t.Fatal("missing selected target")
	}
	target := a.d.Retirement.Targets[at]
	if target.Original.Step.Retain {
		var proof *RetainReceipt
		if target.Original.Step.Owner != ([32]byte{}) {
			claim := target.Original
			p := RetainReceipt{Cluster: f.f.cluster, Retirement: a.d.Retirement.ID, Key: key, Native: claim.Native, StopRevision: a.d.Retirement.Revision, Owner: claim.Step.Owner, Command: state.Digest(claim.Command), Generation: claim.Result.Generation, Revision: claim.Result.Revision, Released: true, Stopped: true, Retained: true, Fenced: true}
			signer := f.f.na
			if p.Owner == public(f.f.nb) {
				signer = f.f.nb
			}
			p.Signature = ed25519.Sign(signer, RetainReceiptBytes(p))
			proof = &p
		}
		f.saveDelivery(f.d.Retained(f.d.Revision(), key, proof))
		return
	}
	if m, ok := a.Removal(key, "drain"); ok {
		f.retirementPhase(key, "drain")
		signer := f.f.na
		if target.Original.Step.Owner == public(f.f.nb) {
			signer = f.f.nb
		}
		signature := ed25519.Sign(signer, schema.GoneBytes(f.f.cluster, key, target.Original.Result.Generation, []byte(m.Command.Value)))
		f.saveDelivery(f.d.Gone(f.d.Revision(), key, signature))
		f.retirementPhase(key, "proof")
	}
	f.retirementPhase(key, "delete")
}
func (f *deliveryFixture) closeTargets() {
	f.f.t.Helper()
	for count := 0; count < 1025; count++ {
		a := f.d.Inventory()
		remaining := false
		key := ""
		for _, target := range a.d.Retirement.Targets {
			if !target.Closed {
				remaining = true
				if a.canRetire(target.Original.Step.Key) {
					key = target.Original.Step.Key
					break
				}
			}
		}
		if !remaining {
			return
		}
		if key == "" {
			f.f.t.Fatal("original dependency/unknown prevents retirement")
		}
		f.closeTarget(key)
	}
	f.f.t.Fatal("unbounded retirement fixture")
}
func (f *deliveryFixture) finishRetirement() {
	f.f.t.Helper()
	f.saveDelivery(f.d.FinishRetirement(f.d.Revision(), f.f.c, "alice"))
	f.ctx.Current = f.shared.Objects("")
}
func (f *deliveryFixture) continueTransition() {
	f.f.t.Helper()
	f.saveDelivery(f.d.ContinueTransition(f.d.Revision(), f.f.c, f.ctx, "alice"))
	if e, ok := f.d.Inventory().Execution(); ok {
		f.e = e
		f.b = Blueprint{e.d.Plan}
	}
}

func TestDeliveryRequestQuiescencePinsFetchAndReadyTransition(t *testing.T) {
	f := newTransitionFixture(t, true, true)
	if !f.d.Quiescent() {
		t.Fatal("settled execution and idle candidate should not pin receipts")
	}
	next, ticket, err := f.d.Fetch(f.d.Revision(), f.f.c, f.ctx)
	f.saveDelivery(next, err)
	if f.d.Quiescent() {
		t.Fatal("fetch without any uploaded bytes allowed expiry")
	}
	before, _ := f.d.Encode()
	if _, err := f.d.RotateWindow(f.d.Revision(), f.f.c, "alice", f.shared); err == nil {
		t.Fatal("explicit CD history rotation erased a live fetch")
	}
	after, _ := f.d.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("rejected history rotation changed the original ticket")
	}
	f.saveDelivery(f.d.SourceFailed(f.d.Revision(), ticket, "policy"))
	if !f.d.Quiescent() {
		t.Fatal("closed read-only fetch still pinned receipts")
	}
	f.receive(f.imageChange("b"))
	f.approve()
	f.beginTransition("new-operation", DeliveryUpdate)
	f.closeTargets()
	f.finishRetirement()
	transition, found := f.d.Transition()
	if !found || transition.Phase != "ready" || !f.d.Inventory().Quiescent() || f.d.Quiescent() {
		t.Fatal("ready transition was confused with completed request ownership")
	}
}

func TestDeliveryTransitionReplacementUsesOriginalClosureThenFreshTaskGeneration(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	oldTask := f.shared.Object(ResourceKey("task", "tenant", "php-mysql", "db"))
	volumeKey := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	oldVolume := f.shared.Object(volumeKey)
	accepted := f.receive(f.imageChange("b"))
	if _, err := f.d.BeginTransition(f.d.Revision(), f.f.c, f.ctx, "alice", "second", "submitter", 1, DeliveryUpdate); err == nil {
		t.Fatal("destructive transition lacked exact approval")
	}
	f.approve()
	f.beginTransition("second", DeliveryUpdate)
	frozen := f.d.d.Transition.Selection.Candidate.ID
	queued := f.receive(f.imageChange("c"))
	if queued == accepted || f.d.d.Transition.Selection.Candidate.ID != frozen {
		t.Fatal("queued source replaced accepted original")
	}
	if _, err := f.d.ContinueTransition(f.d.Revision(), f.f.c, f.ctx, "alice"); err == nil {
		t.Fatal("new Apply before original closure")
	}
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	if f.d.d.Running.Candidate.Artifact.Commit != accepted || f.d.d.Candidate.Artifact.Commit != queued {
		t.Fatal("handoff used latest branch instead of accepted source")
	}
	f.completeDelivery()
	current := f.shared.Object(ResourceKey("task", "tenant", "php-mysql", "db"))
	if current.Generation <= oldTask.Generation || f.shared.Object(volumeKey) != oldVolume {
		t.Fatal("replacement lost fresh generation/retained volume identity")
	}
}

func TestDeliveryNoopRetirementKeepsOriginalClosureInCheckpoint(t *testing.T) {
	for _, mode := range []DeliveryTransitionMode{DeliveryUpdate, DeliveryDown} {
		t.Run(string(mode), func(t *testing.T) {
			f := newTransitionFixture(t, true, false)
			before := f.shared.Index()
			f.receive(append([]byte("# next source, same native goals\n"), f.body...))
			f.start("noop")
			f.completeDelivery()
			if f.shared.Index() != before {
				t.Fatal("Noop submitted a new native goal")
			}
			if mode == DeliveryUpdate {
				f.receive(f.imageChange("b"))
				f.approve()
			}
			f.beginTransition("after-noop", mode)
			f.closeTargets()
			// Each closeTarget round-trips the checkpoint, including the moment
			// an original claim becomes Removed/Retained while Noop stays active.
			raw := deliveryRaw(t, f.d)
			for _, kind := range []string{"task", "volume"} {
				var corrupt deliveryRecord
				if err := json.Unmarshal(raw, &corrupt); err != nil {
					t.Fatal(err)
				}
				for i, target := range corrupt.Inventory.Retirement.Targets {
					if target.Original.Step.Kind != kind {
						continue
					}
					corrupt.Inventory.Retirement.Targets[i].Closed = false
					bad, _ := json.Marshal(corrupt)
					if _, err := DecodeDelivery(bad); err == nil {
						t.Fatal("Noop accepted a retired claim without its current closed target", kind)
					}
					break
				}
			}
			f.finishRetirement()
			if mode == DeliveryUpdate {
				f.continueTransition()
				f.completeDelivery()
			}
		})
	}
}
func TestDeliveryTransitionUnknownDeleteKeepsOriginalIDThroughDuplicateProofAndRestart(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	f.receive(f.imageChange("b"))
	f.approve()
	f.beginTransition("second", DeliveryUpdate)
	// Web is the first removable task, before its DB and original inputs.
	key := ResourceKey("task", "tenant", "php-mysql", "web")
	a := f.d.Inventory()
	original, _ := a.Removal(key, "drain")
	f.retirementPhase(key, "drain")
	at := a.target(key)
	target := a.d.Retirement.Targets[at]
	proof := ed25519.Sign(f.f.na, schema.GoneBytes(f.f.cluster, key, target.Original.Result.Generation, []byte(original.Command.Value)))
	f.saveDelivery(f.d.Gone(f.d.Revision(), key, proof))
	f.retirementPhase(key, "proof")
	deletion, _ := f.d.Inventory().Removal(key, "delete")
	f.saveDelivery(f.d.SendRemoval(f.d.Revision(), f.f.c, "alice", key, "delete"))
	f.saveDelivery(f.d.UnknownRemoval(f.d.Revision(), key, "delete"))
	before := deliveryRaw(t, f.d)
	f.saveDelivery(f.d.SettleRemoval(f.d.Revision(), key, "proof", f.shared))
	if !bytes.Equal(before, deliveryRaw(t, f.d)) {
		t.Fatal("duplicate original proof rewrote unknown deletion")
	}
	f.saveDelivery(DecodeDelivery(deliveryRaw(t, f.d)))
	pending, _ := f.d.Inventory().Removal(key, "delete")
	if pending.Command != deletion.Command || pending.Journal.Pending == nil || pending.Journal.Pending.Phase != reconcile.RecoveryRequired {
		t.Fatal("original deletion identity lost")
	}
	f.apply(deletion.Command)
	f.saveDelivery(f.d.SettleRemoval(f.d.Revision(), key, "delete", f.shared))
	f.ctx.Current = f.shared.Objects("")
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	f.completeDelivery()
}
func TestDeliveryTransitionPruneFalseKeepsOrphanAndVolumeWithoutSubmittingDelete(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	key := ResourceKey("task", "tenant", "php-mysql", "web")
	old := f.shared.Object(key)
	c, _ := ParseCompose(f.body)
	delete(c.Services, "web")
	body, _ := yaml.Marshal(c)
	f.receive(body)
	f.start("second")
	f.completeDelivery()
	if f.shared.Object(key) != old {
		t.Fatal("prune=false deleted orphan")
	}
	found := false
	changes, err := f.d.Inventory().Changes(f.b, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range changes {
		if change.Key == key && change.Action == "KeepOrphan" {
			found = true
		}
	}
	if !found {
		t.Fatal("retained inventory omitted old orphan")
	}
}
func TestDeliveryTransitionEmptySourceRequiresPolicyAndRetainsData(t *testing.T) {
	f := newTransitionFixture(t, true, true)
	key := ResourceKey("volume", "tenant", "php-mysql", "mysql-data")
	old := f.shared.Object(key)
	c, _ := ParseCompose(f.body)
	c.Services = map[string]ComposeService{}
	c.Networks = nil
	c.Volumes = nil
	c.Secrets = nil
	body, _ := yaml.Marshal(c)
	f.receive(body)
	f.approve()
	f.beginTransition("empty", DeliveryUpdate)
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	f.completeDelivery()
	if f.shared.Object(key) != old {
		t.Fatal("allow_empty destroyed retained volume")
	}
	for _, claim := range f.d.Inventory().Claims() {
		if claim.Step.Kind == "task" && !claim.Removed {
			t.Fatal("prune empty left unclosed task")
		}
	}
	c.Sfc.Delivery = nil
	bad, _ := yaml.Marshal(c)
	if _, err := ParseCompose(bad); err == nil {
		t.Fatal("empty services without x-sfc.cd")
	}
	if _, err := ParseCompose([]byte("name: app\nx-sfc: {schema: 1, cd: {repository: r, branch: b, path: p}}\n")); err == nil {
		t.Fatal("absent services treated as explicit empty map")
	}
}
func TestDeliveryTransitionDownPreservesAndSettlesLateUnknownBeforeDrain(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("first")
	key := f.b.Steps()[0].Key
	original := f.prepare(key)
	f.send(key)
	f.save(f.e.Unknown(f.e.Revision(), key))
	f.syncDelivery()
	f.beginTransition("stop", DeliveryDown)
	if !f.d.d.Paused {
		t.Fatal("down did not stop new polling")
	}
	if _, err := f.d.FinishRetirement(f.d.Revision(), f.f.c, "alice"); err == nil {
		t.Fatal("unknown original treated as absent")
	}
	result := f.apply(original)
	f.save(f.e.Commit(f.e.Revision(), key, original, result))
	f.syncDelivery()
	a := f.d.Inventory()
	at := a.target(key)
	if at < 0 || a.d.Retirement.Targets[at].Original.Command != original {
		t.Fatal("late accepted resource missing from original down")
	}
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	if !f.d.d.Paused || f.d.d.Inventory.Active != nil || f.shared.Object(key).Present {
		t.Fatal("down reopened dispatch or retained unknown resource")
	}
}
func TestDeliveryTransitionFailedIntentCannotRetryByCommentAndRequiresExplicitRecovery(t *testing.T) {
	f := newDeliveryFixture(t, "automatic")
	f.receive(f.body)
	f.start("first")
	key := f.b.Steps()[0].Key
	original := f.prepare(key)
	f.send(key)
	shared, result, err := state.ApplyChecked(f.shared, f.shared.Index()+1, original, func(state.State, state.State, state.Command) error {
		return errors.New("injected deterministic policy rejection")
	})
	if err != nil || result.Code != state.Invalid {
		t.Fatal(result, err)
	}
	f.shared = shared
	f.save(f.e.Commit(f.e.Revision(), key, original, result))
	f.syncDelivery()
	f.receive(append([]byte("# same failed intent at a new commit\n"), f.body...))
	_, err = f.d.Start(f.d.Revision(), f.f.c, f.ctx, "automatic-second", "submitter", 1)
	failure, ok := err.(*InputError)
	if !ok || failure.Code != "CD_FAILED_REVISION" {
		t.Fatal("comment bypassed failed intent block", err)
	}
	f.approve()
	f.beginTransition("retry", DeliveryRecover)
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	f.completeDelivery()
	if f.d.d.LastFailure != nil || f.d.d.LastSuccess.Operation != "retry" {
		t.Fatal("explicit settled recovery did not resolve original failure")
	}
	prior, found := f.shared.LookupResult(original)
	if !found || prior != result {
		t.Fatal("original rejected result lost")
	}
}
func TestDeliveryTransitionPolicyChangeKeepsClosureAndRequiresExplicitAbandon(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	f.receive(f.imageChange("b"))
	f.approve()
	f.beginTransition("second", DeliveryUpdate)
	f.closeTargets()
	f.finishRetirement()
	policy := f.d.d.Policy
	policy.Poll++
	f.saveDelivery(f.d.Configure(f.d.Revision(), f.d.d.PolicyRevision, f.f.c, f.ctx, "alice", policy))
	before := deliveryRaw(t, f.d)
	if _, err := f.d.ContinueTransition(f.d.Revision(), f.f.c, f.ctx, "alice"); err == nil {
		t.Fatal("new policy silently authorized old target")
	}
	if !bytes.Equal(before, deliveryRaw(t, f.d)) {
		t.Fatal("blocked Apply erased positive closure")
	}
	f.saveDelivery(f.d.AbandonTransition(f.d.Revision(), f.f.c, "alice"))
	if f.d.d.Transition != nil || len(f.d.d.Transitions) != 1 || f.d.d.Transitions[0].Outcome != "abandoned" {
		t.Fatal("abandon lost immutable original identity")
	}
	if _, err := f.d.Start(f.d.Revision(), f.f.c, f.ctx, "second", "submitter", 1); err == nil {
		t.Fatal("abandoned transition ID reused")
	}
}
func TestDeliveryTransitionSnapshotRejectsErasedActiveAndPositiveClosure(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	f.receive(f.imageChange("b"))
	f.approve()
	stale := f.d.Revision()
	f.beginTransition("second", DeliveryUpdate)
	if _, err := f.d.BeginTransition(stale, f.f.c, f.ctx, "alice", "other", "submitter", 1, DeliveryUpdate); err == nil {
		t.Fatal("stale controller won transition CAS")
	}
	raw := deliveryRaw(t, f.d)
	var r deliveryRecord
	json.Unmarshal(raw, &r)
	r.Transition = nil
	bad, _ := json.Marshal(r)
	if _, err := DecodeDelivery(bad); err == nil {
		t.Fatal("erased active retirement transition accepted")
	}
	f.closeTargets()
	f.finishRetirement()
	raw = deliveryRaw(t, f.d)
	for _, change := range []func(*deliveryRecord){
		func(r *deliveryRecord) { r.Transition.Receipt = nil },
		func(r *deliveryRecord) { r.Transition.Required = nil },
		func(r *deliveryRecord) { r.Transition.Receipt.Targets[0].Closed = false },
		func(r *deliveryRecord) { r.Transition.Receipt.Targets[0].Gone = nil },
		func(r *deliveryRecord) { r.Transition.Selection.Operation = "other" },
	} {
		var r deliveryRecord
		json.Unmarshal(raw, &r)
		change(&r)
		bad, _ := json.Marshal(r)
		if _, err := DecodeDelivery(bad); err == nil {
			t.Fatal("positive original closure or accepted target was erased")
		}
	}
}

func (f *deliveryFixture) rotateCommittedEpoch() {
	f.f.t.Helper()
	_, epoch, revision, known := f.shared.Principal("submitter")
	if !known {
		f.f.t.Fatal("missing original submitter")
	}
	result := f.apply(state.Command{Actor: "submitter", Epoch: epoch, RequestID: "rotate-explicit", Kind: state.RotateLedger, Target: "submitter", Expected: revision})
	if result.Code != state.Applied {
		f.f.t.Fatal("explicit epoch did not commit", result)
	}
}
func TestDeliveryWindowConsumesCommittedEpochAndPreservesNativeClaimsAndSuccess(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	before := goal(f.d.Inventory().Claims())
	if _, err := f.d.RotateWindow(f.d.Revision(), f.f.c, "alice", f.shared); err == nil {
		t.Fatal("CD automatically advanced its sender epoch")
	}
	f.rotateCommittedEpoch()
	f.saveDelivery(f.d.RotateWindow(f.d.Revision(), f.f.c, "alice", f.shared))
	if !bytes.Equal(before, goal(f.d.Inventory().Claims())) || f.d.d.Running != nil || f.d.d.Inventory.Active != nil || len(f.d.d.Inventory.History) != 0 || f.d.d.CompactedSuccess == nil || f.d.d.LastSuccess.Operation != "first" {
		t.Fatal("compaction erased owned native state/known success")
	}
	f.saveDelivery(f.d.Replan(f.d.Revision(), f.f.c, f.ctx))
	if _, err := f.d.Start(f.d.Revision(), f.f.c, f.ctx, "first", "submitter", 1); err == nil {
		t.Fatal("old source epoch replayed after compaction")
	}
	f.saveDelivery(f.d.Start(f.d.Revision(), f.f.c, f.ctx, "first", "submitter", 2))
	f.e, _ = f.d.Inventory().Execution()
	f.b = Blueprint{f.e.d.Plan}
	index := f.shared.Index()
	f.completeDelivery()
	if f.shared.Index() != index || f.d.d.LastSuccess.Epoch != 2 || f.d.d.CompactedSuccess != nil {
		t.Fatal("new epoch recreated unchanged resources or lost current success")
	}
}
func TestDeliveryWindowFencesAbandonedTransitionIdentityAndCannotEraseUnknown(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	f.receive(f.imageChange("b"))
	f.approve()
	f.beginTransition("second", DeliveryUpdate)
	f.closeTargets()
	f.finishRetirement()
	f.saveDelivery(f.d.AbandonTransition(f.d.Revision(), f.f.c, "alice"))
	f.rotateCommittedEpoch()
	f.saveDelivery(f.d.RotateWindow(f.d.Revision(), f.f.c, "alice", f.shared))
	if len(f.d.d.Transitions) != 0 || f.d.d.Inventory.MinEpoch["submitter"] != 2 {
		t.Fatal("abandoned identity lost its committed epoch fence")
	}
	f.saveDelivery(f.d.Replan(f.d.Revision(), f.f.c, f.ctx))
	if _, err := f.d.Start(f.d.Revision(), f.f.c, f.ctx, "second", "submitter", 1); err == nil {
		t.Fatal("abandoned sender epoch accepted")
	}
	pending := newDeliveryFixture(t, "automatic")
	pending.receive(pending.body)
	pending.start("first")
	key := pending.b.Steps()[0].Key
	pending.prepare(key)
	pending.send(key)
	pending.save(pending.e.Unknown(pending.e.Revision(), key))
	pending.syncDelivery()
	pending.rotateCommittedEpoch()
	if _, err := pending.d.RotateWindow(pending.d.Revision(), pending.f.c, "alice", pending.shared); err == nil {
		t.Fatal("ledger epoch rotation erased unknown original work")
	}
}
func TestDeliveryWindowCompactedOutcomeNeedsOriginalSelectionAndEpochFloor(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	f.rotateCommittedEpoch()
	f.saveDelivery(f.d.RotateWindow(f.d.Revision(), f.f.c, "alice", f.shared))
	raw := deliveryRaw(t, f.d)
	for _, change := range []func(*deliveryRecord){func(r *deliveryRecord) { r.Inventory.MinEpoch = nil }, func(r *deliveryRecord) { r.CompactedSuccess.Plan[0]++ }, func(r *deliveryRecord) { r.CompactedSuccess.CompletedAt = 0 }, func(r *deliveryRecord) { r.LastSuccess = nil }} {
		var record deliveryRecord
		json.Unmarshal(raw, &record)
		change(&record)
		bad, _ := json.Marshal(record)
		if _, err := DecodeDelivery(bad); err == nil {
			t.Fatal("compacted outcome forged or detached from epoch fence")
		}
	}
}

func TestDeliveryTransitionRuntimeOverrideUsesSameResultJournalAndDownCanReleaseFields(t *testing.T) {
	f := newOverrideFixture(t)
	index := f.shared.Index()
	f.overrideMode("debug")
	tracePath := []string{"services", "web", "environment", "APP_TRACE"}
	f.saveDelivery(f.d.PutOverride(f.d.Revision(), 0, f.f.c, f.ctx, "alice", tracePath, goal("enabled"), f.currentTaskRefs("web")))
	if f.shared.Index() != index {
		t.Fatal("override intent bypassed ordinary app mutation journal")
	}
	f.approve()
	f.beginTransition("second", DeliveryUpdate)
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	f.completeDelivery()
	for _, claim := range f.d.Inventory().Claims() {
		if claim.Step.Kind == "task" && !claim.Removed {
			current := f.shared.Object(claim.Step.Key)
			if current.Revision != claim.Result.Revision || current.Value != claim.Command.Value {
				t.Fatal("runtime Desired and Inventory result diverged")
			}
		}
	}
	f.beginTransition("stop", DeliveryDown)
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	f.saveDelivery(f.d.ReleaseOverride(f.d.Revision(), 1, f.f.c, f.ctx, "alice", appModeOverridePath()))
	f.saveDelivery(f.d.ReleaseOverride(f.d.Revision(), 2, f.f.c, f.ctx, "alice", tracePath))
	if len(f.d.Overrides()) != 0 || f.d.d.Approval != nil || f.d.d.Candidate.OverrideRevision == f.d.d.OverrideRevision {
		t.Fatal("stopped field release invented a current executable candidate")
	}
	f.saveDelivery(f.d.Replan(f.d.Revision(), f.f.c, f.ctx))
	if f.d.d.Candidate.OverrideRevision != f.d.d.OverrideRevision || !f.d.d.Paused {
		t.Fatal("replan lost explicit stopped state")
	}
}
func TestDeliveryTransitionApprovedAppOverrideRecreationRetainsFieldOwnership(t *testing.T) {
	f := newOverrideFixture(t)
	refs := f.currentTaskRefs("web")
	management := map[string]state.Object{}
	for key, object := range f.shared.Objects("control/network-sources/") {
		management[key] = object
	}
	f.overrideMode("debug")
	f.approve()
	f.beginTransition("app-mode", DeliveryUpdate)
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	f.completeDelivery()
	for _, original := range refs {
		if f.shared.Object(original.Key).Generation <= original.Generation {
			t.Fatal("approved native recreation did not use fresh generation")
		}
	}
	f.receive(append([]byte("# fresh source still honors logical field claim\n"), f.body...))
	if f.d.d.Candidate.Plan.Input.Services["web"].Environment["APP_MODE"] != "debug" || len(f.d.Overrides()) != 1 {
		t.Fatal("authorized generation transition lost field ownership")
	}
	for key, object := range management {
		if f.shared.Object(key) != object {
			t.Fatal("app override changed borrowed management source", key)
		}
	}
	// An out-of-band resource write remains untracked and cannot be adopted.
	key := refs[0].Key
	current := f.ctx.Current[key]
	current.Revision++
	f.ctx.Current[key] = current
	if _, err := f.d.Replan(f.d.Revision(), f.f.c, f.ctx); err == nil {
		t.Fatal("external untracked metadata adopted as app-owned runtime result")
	}
}

func TestAppliedOverrideKeepsGitDivergenceWithoutRepeatingEffectiveSelection(t *testing.T) {
	f := newOverrideFixture(t)
	f.overrideMode("debug")
	f.approve()
	f.beginTransition("apply-field", DeliveryUpdate)
	f.closeTargets()
	f.finishRetirement()
	f.continueTransition()
	f.completeDelivery()
	status, err := f.d.Status(f.f.c, f.ctx, f.now)
	if err != nil || status.Sync != "OutOfSync" || status.EffectiveSync != "InSync" || !f.d.CandidateApplied() {
		t.Fatal("applied field mask became repeated native work", status, err)
	}
	// A distinct Git revision with identical effective goals still needs one
	// logical source selection, with no new native mutation or binding owner.
	commit := f.receive(append([]byte("# distinct revision; same effective goals\n"), f.body...))
	status, err = f.d.Status(f.f.c, f.ctx, f.now)
	if err != nil || status.EffectiveSync != "InSync" || f.d.CandidateApplied() {
		t.Fatal("new source selection was erased by identical native goals", err)
	}
	before := f.shared.Index()
	f.start("select-next-source")
	f.completeDelivery()
	selection, found := f.d.Selection()
	if !found || selection.Commit != commit || !f.d.CandidateApplied() || f.shared.Index() != before {
		t.Fatal("logical Noop did not retain native effects and source selection")
	}
	// Incidental base/health replan must not re-execute the selected source.
	f.saveDelivery(f.d.Replan(f.d.Revision(), f.f.c, f.ctx))
	if !f.d.CandidateApplied() {
		t.Fatal("current CAS bases invalidated an already applied source intent")
	}
}

// A health report of the running Noop execution can arrive after a target
// closed. Advancing it must not rewrite the removed original claim, or the
// retirement can never finish (its target no longer matches the claim).
func TestDeliveryNoopObservationAfterClosedTargetKeepsOriginalClaim(t *testing.T) {
	f := newTransitionFixture(t, true, false)
	f.receive(append([]byte("# next source, same native goals\n"), f.body...))
	f.start("noop")
	f.completeDelivery()
	f.receive(f.imageChange("b"))
	f.approve()
	f.beginTransition("after-noop", DeliveryUpdate)
	f.closeTargets()
	e, ok := f.d.Inventory().Execution()
	if !ok || e.d.Operation != "noop" {
		t.Fatal("the Noop execution is not the one kept during retirement")
	}
	f.e, f.b = e, Blueprint{e.d.Plan}
	refreshed := false
	for _, target := range f.d.Inventory().d.Retirement.Targets {
		key := target.Original.Step.Key
		if s, exists := f.e.Stage(key); exists && s.Noop && s.Observation != nil && target.Closed {
			f.now++
			f.observe(key, true, false)
			refreshed = true
			break
		}
	}
	if !refreshed {
		t.Fatal("fixture has no closed Noop target to refresh")
	}
	f.syncDelivery()
	f.finishRetirement()
	f.continueTransition()
	f.completeDelivery()
}
