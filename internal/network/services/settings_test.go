// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/miekg/dns"
)

type settingsFixture struct {
	d     dnsFixture
	m     Settings
	scope NativeScope
	key   string
}

func newSettingsFixture(t *testing.T) settingsFixture {
	t.Helper()
	d := newDNSFixture(t)
	d = grantDNS(t, d, d.cfg)
	m, e := NewSettings(d.f.a.cluster, pub(d.f.key), d.f.boot, 16, 8)
	if e != nil {
		t.Fatal(e)
	}
	return settingsFixture{d, m, NativeScope{Namespace: [32]byte{88}, Interface: "bridge-original"}, "dns/first/dns"}
}
func settingsRaw(t *testing.T, m Settings) []byte {
	t.Helper()
	raw, e := m.Encode()
	if e != nil {
		t.Fatal("invalid settings candidate", e)
	}
	return raw
}
func settingsTarget(t *testing.T, f settingsFixture, cfg DNSConfig, scope NativeScope) (settingsFixture, uint64) {
	t.Helper()
	f.d = grantDNS(t, f.d, cfg)
	target, e := DNSSettings(f.d.f.c, f.d.f.n, f.d.f.a, "admin", cfg, scope)
	if e != nil {
		t.Fatal(e)
	}
	expected := f.m.scopes[f.key].Desired.revision
	f.m, e = f.m.Desired(f.d.f.c, f.d.f.n, f.d.f.a, "admin", expected, target)
	if e != nil {
		t.Fatal(e)
	}
	var id uint64
	f.m, id, e = f.m.Stage(f.d.f.c, f.d.f.n, f.d.f.a, f.key)
	if e != nil {
		t.Fatal(e)
	}
	return f, id
}
func settingsProof(m Settings, step SettingsStep, key ed25519.PrivateKey) SettingsProof {
	p := SettingsProof{Cluster: m.cluster, Owner: m.owner, Boot: m.boot, Action: step.Action, Key: step.Key, Group: step.Group, Operation: step.Operation.ID, Kind: step.Operation.Kind, Generation: step.Operation.Target.Generation, Spec: step.Operation.Target.Spec, Outcome: reconcile.EffectApplied, Synced: true, NoPending: true}
	if p.Kind == reconcile.Remove {
		p.Gone = true
		p.OldAdmissionStopped = p.Action == SettingsActivate
	} else if p.Action == SettingsPrepare {
		p.Inactive = true
	} else {
		p.Serving = true
		p.OldAdmissionStopped = true
	}
	p.Signature = ed25519.Sign(key, SettingsProofBytes(p))
	return p
}
func settingsDispatch(t *testing.T, f settingsFixture, step SettingsStep) settingsFixture {
	t.Helper()
	plan, e := f.m.NativePlan(step)
	if e != nil || len(plan) == 0 {
		t.Fatal("original native plan", e)
	}
	f.m, e = f.m.Dispatch(f.d.f.c, f.d.f.n, f.d.f.a, step)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func settingsGroupStep(t *testing.T, f settingsFixture, id uint64) settingsFixture {
	t.Helper()
	g := f.m.groups[id]
	var op *reconcile.Operation
	var e error
	f.m, op, e = f.m.PlanGroup(id)
	if e != nil || op == nil {
		t.Fatal("group plan", op, e)
	}
	step := SettingsStep{SettingsPrepare, g.Key, id, *op}
	f = settingsDispatch(t, f, step)
	f.m, e = f.m.Observe(settingsProof(f.m, step, f.d.f.key))
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func settingsSwitch(t *testing.T, f settingsFixture) settingsFixture {
	t.Helper()
	var op *reconcile.Operation
	var e error
	f.m, op, e = f.m.PlanSwitch(f.d.f.c, f.d.f.n, f.d.f.a, f.key)
	if e != nil || op == nil {
		t.Fatal("switch plan", op, e)
	}
	step := SettingsStep{SettingsActivate, f.key, 0, *op}
	f = settingsDispatch(t, f, step)
	f.m, e = f.m.Observe(settingsProof(f.m, step, f.d.f.key))
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func settingsPublish(t *testing.T, f settingsFixture, at int64) settingsFixture {
	t.Helper()
	var e error
	f.m, f.d.m, e = f.m.PublishDNS(f.d.f.c, f.d.f.n, f.d.f.a, f.d.m, "admin", f.key, f.d.clock(at))
	if e != nil {
		t.Fatal("publish same DNS core", e)
	}
	settingsRaw(t, f.m)
	return f
}
func settingsServing(t *testing.T) settingsFixture {
	t.Helper()
	f := newSettingsFixture(t)
	f, id := settingsTarget(t, f, f.d.cfg, f.scope)
	f = settingsGroupStep(t, f, f.m.slots[id].Group)
	f = settingsSwitch(t, f)
	return settingsPublish(t, f, 190)
}
func settingsUseProof(t *testing.T, f settingsFixture, h SettingsUse) SettingsUseClose {
	t.Helper()
	p, e := f.m.UseFacts(h)
	if e != nil {
		t.Fatal(e)
	}
	if p.Synced || p.Stopped || p.NoPending {
		t.Fatal("metadata claimed native request ended")
	}
	p.Synced = true
	p.Stopped = true
	p.NoPending = true
	p.Signature = ed25519.Sign(f.d.f.key, SettingsUseCloseBytes(p))
	return p
}
func settingsQuery(t *testing.T, f settingsFixture, at int64) (settingsFixture, SettingsDNSUse) {
	t.Helper()
	var h SettingsDNSUse
	var e error
	f.m, f.d.m, h, e = f.m.AcquireDNS(f.d.f.c, f.d.f.n, f.d.f.a, f.d.m, "first", "dns", f.d.origin, dnsWire("web.app.mydc.test.", dns.TypeA), f.d.clock(at))
	if e != nil {
		t.Fatal(e)
	}
	return f, h
}
func TestSettingsColdAndHotDNSUseSameCoreSocketAndOriginalQuery(t *testing.T) {
	f := settingsServing(t)
	f, h := settingsQuery(t, f, 200)
	old := h.Runtime.slot
	oldGroup := f.m.slots[old].Group
	cfg := ownDNSConfig(f.d.cfg)
	cfg.Source++
	cfg.Serial++
	cfg.TTL = 10
	f, id := settingsTarget(t, f, cfg, f.scope)
	if f.m.slots[id].Group != oldGroup || len(f.m.groups) != 1 {
		t.Fatal("hot policy reopened original socket")
	}
	f = settingsSwitch(t, f)
	f = settingsPublish(t, f, 201)
	if f.m.Status(f.key).Applied != cfg.Source || f.m.Status(f.key).Observed != cfg.Source {
		t.Fatal("desired/applied/observed conflated")
	}
	if _, e := f.m.CollectSlot(old); e == nil {
		t.Fatal("old native request pin erased")
	}
	if _, e := f.m.Return(h.Runtime, SettingsUseClose{}); e == nil {
		t.Fatal("unsigned request return accepted")
	}
	var e error
	f.m, f.d.m, e = f.m.ReleaseDNS(f.d.m, h, f.d.clock(205), settingsUseProof(t, f, h.Runtime))
	if e != nil {
		t.Fatal(e)
	}
	f.m, e = f.m.CollectSlot(old)
	if e != nil {
		t.Fatal(e)
	}
	if len(f.m.groups) != 1 || len(f.m.groups[oldGroup].Pins.Active) != 1 {
		t.Fatal("hot replacement closed current FD dependency")
	}
	if len(f.d.m.views) < 2 {
		t.Fatal("native slot cleanup erased DNS TTL/view hold")
	}
	settingsRaw(t, f.m)
}
func TestSettingsSerialPortReplacementWaitsOriginalRequestAndPositiveNativeGone(t *testing.T) {
	f := settingsServing(t)
	f, h := settingsQuery(t, f, 200)
	old := f.m.scopes[f.key].Current
	oldGroup := f.m.slots[old].Group
	cfg := ownDNSConfig(f.d.cfg)
	cfg.Source++
	cfg.Serial++
	scope := f.scope
	scope.Interface = "replacement-interface"
	f, id := settingsTarget(t, f, cfg, scope)
	newGroup := f.m.slots[id].Group
	if !f.m.scopes[f.key].Serial {
		t.Fatal("same namespace/53 collision prepared in parallel")
	}
	if _, _, e := f.m.PlanGroup(newGroup); e == nil {
		t.Fatal("new conflicting bind planned before original gone")
	}
	if _, _, e := f.m.PlanSwitch(f.d.f.c, f.d.f.n, f.d.f.a, f.key); e == nil {
		t.Fatal("serial stop erased original user")
	}
	if _, _, _, e := f.m.AcquireDNS(f.d.f.c, f.d.f.n, f.d.f.a, f.d.m, "first", "dns", f.d.origin, dnsWire("web.app.mydc.test.", dns.TypeA), f.d.clock(201)); e == nil {
		t.Fatal("serial drain admitted new old request")
	}
	var e error
	f.m, f.d.m, e = f.m.ReleaseDNS(f.d.m, h, f.d.clock(202), settingsUseProof(t, f, h.Runtime))
	if e != nil {
		t.Fatal(e)
	}
	f = settingsSwitch(t, f)
	f.m, e = f.m.CollectSlot(old)
	if e != nil {
		t.Fatal(e)
	}
	var op *reconcile.Operation
	f.m, op, e = f.m.PlanGroup(oldGroup)
	if e != nil || op == nil || op.Kind != reconcile.Remove {
		t.Fatal(op, e)
	}
	step := SettingsStep{SettingsPrepare, f.key, oldGroup, *op}
	f = settingsDispatch(t, f, step)
	p := settingsProof(f.m, step, f.d.f.key)
	f.m, e = f.m.Unknown(step)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.m.DropGroup(oldGroup); e == nil {
		t.Fatal("unknown native close treated as Gone")
	}
	if _, _, e = f.m.PlanGroup(newGroup); e == nil {
		t.Fatal("unknown old close allowed conflicting bind")
	}
	f.m, e = f.m.Observe(p)
	if e != nil {
		t.Fatal(e)
	}
	f.m, e = f.m.DropGroup(oldGroup)
	if e != nil {
		t.Fatal(e)
	}
	f = settingsGroupStep(t, f, newGroup)
	f = settingsSwitch(t, f)
	f = settingsPublish(t, f, 210)
	if f.m.Status(f.key).Applied != cfg.Source {
		t.Fatal("serial replacement not published")
	}
}
func TestSettingsFailedPreparationPreservesLastGoodAndOriginalUnknown(t *testing.T) {
	f := settingsServing(t)
	cfg := ownDNSConfig(f.d.cfg)
	cfg.Source++
	cfg.Serial++
	scope := f.scope
	scope.Namespace = [32]byte{99}
	f, id := settingsTarget(t, f, cfg, scope)
	g := f.m.slots[id].Group
	var op *reconcile.Operation
	var e error
	f.m, op, e = f.m.PlanGroup(g)
	if e != nil {
		t.Fatal(e)
	}
	step := SettingsStep{SettingsPrepare, f.key, g, *op}
	f = settingsDispatch(t, f, step)
	original, _ := f.m.NativePlan(step)
	f.m, e = f.m.Unknown(step)
	if e != nil {
		t.Fatal(e)
	}
	f, h := settingsQuery(t, f, 200)
	f.m, f.d.m, e = f.m.ReleaseDNS(f.d.m, h, f.d.clock(201), settingsUseProof(t, f, h.Runtime))
	if e != nil {
		t.Fatal(e)
	}
	if f.m.Status(f.key).Applied != 100 || f.m.Status(f.key).Desired != 101 || f.m.Status(f.key).Pending != 1 {
		t.Fatal("failed candidate became Applied or lost LKG")
	}
	f.m, e = DecodeSettings(settingsRaw(t, f.m))
	if e != nil {
		t.Fatal(e)
	}
	after, _ := f.m.NativePlan(step)
	if !bytes.Equal(original, after) || f.m.groups[g].State.Pending.ID != op.ID {
		t.Fatal("recovery changed original target")
	}
	if _, e = f.m.AbortPrepared(step); e == nil {
		t.Fatal("dispatched unknown was cancelled")
	}
	p := settingsProof(f.m, step, f.d.f.key)
	f.m, e = f.m.Observe(p)
	if e != nil {
		t.Fatal(e)
	}
	f = settingsSwitch(t, f)
	f = settingsPublish(t, f, 202)
}
func TestSettingsLateActivationCannotPublishOverNewDesiredOrReissueOriginal(t *testing.T) {
	f := settingsServing(t)
	cfg := ownDNSConfig(f.d.cfg)
	cfg.Source++
	cfg.Serial++
	f, _ = settingsTarget(t, f, cfg, f.scope)
	var op *reconcile.Operation
	var e error
	f.m, op, e = f.m.PlanSwitch(f.d.f.c, f.d.f.n, f.d.f.a, f.key)
	if e != nil {
		t.Fatal(e)
	}
	step := SettingsStep{SettingsActivate, f.key, 0, *op}
	f = settingsDispatch(t, f, step)
	payload, _ := f.m.NativePlan(step)
	p := settingsProof(f.m, step, f.d.f.key)
	f.m, e = f.m.Unknown(step)
	if e != nil {
		t.Fatal(e)
	}
	cfg.Source++
	cfg.Serial++
	f, _ = settingsTarget(t, f, cfg, f.scope)
	if _, _, e = f.m.PlanSwitch(f.d.f.c, f.d.f.n, f.d.f.a, f.key); e == nil {
		t.Fatal("original unknown activation replaced")
	}
	original, _ := f.m.NativePlan(step)
	if !bytes.Equal(payload, original) {
		t.Fatal("new Desired rewrote original activation")
	}
	f.m, e = f.m.Observe(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.m.PublishDNS(f.d.f.c, f.d.f.n, f.d.f.a, f.d.m, "admin", f.key, f.d.clock(203)); e == nil {
		t.Fatal("late source101 published over102")
	}
	if f.m.Status(f.key).Observed != 101 || f.m.Status(f.key).Applied != 100 {
		t.Fatal("observed late effect rewritten as latest Applied")
	}
	f = settingsSwitch(t, f)
	f = settingsPublish(t, f, 204)
	if f.m.Status(f.key).Applied != 102 {
		t.Fatal("latest desired not published")
	}
}
func TestSettingsBootRecoveryRetainsUsersAndRevalidatesBothNativeStages(t *testing.T) {
	f := settingsServing(t)
	f, h := settingsQuery(t, f, 200)
	group := f.m.slots[h.Runtime.slot].Group
	gp := *f.m.groups[group].Proof
	sp := *f.m.scopes[f.key].Proof
	var e error
	f.m, e = f.m.ResumeBoot([32]byte{55})
	if e != nil {
		t.Fatal(e)
	}
	f.m, e = DecodeSettings(settingsRaw(t, f.m))
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.m.Borrow(f.d.f.c, f.d.f.n, f.d.f.a, f.key, [32]byte{2}, false); e == nil {
		t.Fatal("old boot advertised native Ready")
	}
	gp.Boot = f.m.boot
	gp.Signature = ed25519.Sign(f.d.f.key, SettingsProofBytes(gp))
	f.m, e = f.m.Revalidate(gp)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.m.Borrow(f.d.f.c, f.d.f.n, f.d.f.a, f.key, [32]byte{2}, false); e == nil {
		t.Fatal("group revalidation skipped original serving switch")
	}
	sp.Boot = f.m.boot
	sp.Signature = ed25519.Sign(f.d.f.key, SettingsProofBytes(sp))
	f.m, e = f.m.Revalidate(sp)
	if e != nil {
		t.Fatal(e)
	}
	if len(f.m.slots[h.Runtime.slot].Users) != 1 {
		t.Fatal("restart cleared original request")
	}
	f.m, e = f.m.Return(h.Runtime, settingsUseProof(t, f, h.Runtime))
	if e != nil {
		t.Fatal(e)
	}
	settingsRaw(t, f.m)
}
func TestSettingsCheckpointRejectsErasedUnknownPinsOriginalPayloadAndForgedProof(t *testing.T) {
	f := settingsServing(t)
	f, h := settingsQuery(t, f, 200)
	cfg := ownDNSConfig(f.d.cfg)
	cfg.Source++
	cfg.Serial++
	scope := f.scope
	scope.Namespace = [32]byte{99}
	f, id := settingsTarget(t, f, cfg, scope)
	g := f.m.slots[id].Group
	var op *reconcile.Operation
	var e error
	f.m, op, e = f.m.PlanGroup(g)
	if e != nil {
		t.Fatal(e)
	}
	step := SettingsStep{SettingsPrepare, f.key, g, *op}
	f = settingsDispatch(t, f, step)
	f.m, e = f.m.Unknown(step)
	if e != nil {
		t.Fatal(e)
	}
	raw := settingsRaw(t, f.m)
	for _, change := range []func(*settingsDisk){func(s *settingsDisk) { s.Groups[1].State.Pending = nil }, func(s *settingsDisk) { s.Slots[0].Users = nil }, func(s *settingsDisk) { s.Slots[0].GroupPin.Token++ }, func(s *settingsDisk) { s.Groups[0].Proof.Signature = nil }, func(s *settingsDisk) { s.Slots[0].Target.DNS.Config.Source++ }, func(s *settingsDisk) { s.Scopes[0].Switch.Applied.Spec = "unknown" }} {
		var s settingsDisk
		json.Unmarshal(raw, &s)
		change(&s)
		bad, _ := json.Marshal(s)
		if _, e = DecodeSettings(bad); e == nil {
			t.Fatal("incomplete/changed original state restored")
		}
	}
	if h.Runtime.pin.Token == 0 {
		t.Fatal("missing request")
	}
}

func TestSettingsDisabledStopsNewAdmissionAndRetainsOriginalUsersUntilNativeClose(t *testing.T) {
	f := settingsServing(t)
	f, h := settingsQuery(t, f, 200)
	old := f.m.scopes[f.key].Current
	g := f.m.slots[old].Group
	cfg := ownDNSConfig(f.d.cfg)
	cfg.Source++
	cfg.Serial++
	cfg.Enabled = false
	f, _ = settingsTarget(t, f, cfg, f.scope)
	if _, _, e := f.m.Borrow(f.d.f.c, f.d.f.n, f.d.f.a, f.key, [32]byte{2}, false); e == nil {
		t.Fatal("disabled Desired accepted new old request")
	}
	if _, _, e := f.m.PlanSwitch(f.d.f.c, f.d.f.n, f.d.f.a, f.key); e == nil {
		t.Fatal("disable discarded original request")
	}
	var e error
	f.m, f.d.m, e = f.m.ReleaseDNS(f.d.m, h, f.d.clock(201), settingsUseProof(t, f, h.Runtime))
	if e != nil {
		t.Fatal(e)
	}
	f = settingsSwitch(t, f)
	f = settingsPublish(t, f, 202)
	f.m, e = f.m.CollectSlot(old)
	if e != nil {
		t.Fatal(e)
	}
	f = settingsGroupStep(t, f, g)
	f.m, e = f.m.DropGroup(g)
	if e != nil {
		t.Fatal(e)
	}
	if len(f.m.groups) != 0 || f.d.m.Applied("first", "dns") != cfg.Source {
		t.Fatal("disable kept physical group or lost disabled policy")
	}
	settingsRaw(t, f.m)
}

func TestSettingsDisabledCleanupSurvivesParentDrainWithoutNewAdmission(t *testing.T) {
	f := settingsServing(t)
	old := f.m.scopes[f.key].Current
	group := f.m.slots[old].Group
	cfg := ownDNSConfig(f.d.cfg)
	cfg.Source++
	cfg.Serial++
	cfg.Enabled = false
	f, _ = settingsTarget(t, f, cfg, f.scope)
	for _, name := range append([]string{cfg.Network}, cfg.Members...) {
		row, ok := f.d.f.n.Network(cfg.Tenant, name)
		if !ok {
			t.Fatal("original member missing")
		}
		var err error
		f.d.f.n, err = f.d.f.n.Drain(f.d.f.c, "admin", cfg.Tenant, name, row.Revision)
		if err != nil {
			t.Fatal(err)
		}
	}
	var err error
	f.d.f.a, err = f.d.f.a.SyncPools(f.d.f.n)
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct the SAME disabled target after parent drain, as a resumed
	// owner must. Its source/generation/hash must not be replaced to close it.
	target, err := DNSSettings(f.d.f.c, f.d.f.n, f.d.f.a, "admin", cfg, f.scope)
	if err != nil || target.hash() != f.m.scopes[f.key].Desired.hash() {
		t.Fatal("original disabled target lost at parent drain", err)
	}
	if _, err = DNSSettings(f.d.f.c, f.d.f.n, f.d.f.a, "admin", f.d.cfg, f.scope); err == nil {
		t.Fatal("drained parent admitted enabled DNS")
	}
	if _, _, err = f.m.Borrow(f.d.f.c, f.d.f.n, f.d.f.a, f.key, [32]byte{2}, false); err == nil {
		t.Fatal("drained parent admitted new use")
	}
	f = settingsSwitch(t, f)
	f = settingsPublish(t, f, 202)
	f.m, err = f.m.CollectSlot(old)
	if err != nil {
		t.Fatal(err)
	}
	f = settingsGroupStep(t, f, group)
	f.m, err = f.m.DropGroup(group)
	if err != nil || len(f.m.groups) != 0 {
		t.Fatal("positive native close did not settle original group", err)
	}
}
func TestSettingsNodeBudgetShrinkKeepsPinsAndBlocksCrossScopePortConflict(t *testing.T) {
	f := settingsServing(t)
	var a, b SettingsUse
	var e error
	f.m, a, e = f.m.Borrow(f.d.f.c, f.d.f.n, f.d.f.a, f.key, [32]byte{1}, false)
	if e != nil {
		t.Fatal(e)
	}
	f.m, b, e = f.m.Borrow(f.d.f.c, f.d.f.n, f.d.f.a, f.key, [32]byte{2}, false)
	if e != nil {
		t.Fatal(e)
	}
	f.m, e = f.m.Resize(16, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.m.Borrow(f.d.f.c, f.d.f.n, f.d.f.a, f.key, [32]byte{3}, false); e == nil {
		t.Fatal("shrink evicted users/admitted over limit")
	}
	f.m, e = f.m.Return(a, settingsUseProof(t, f, a))
	if e != nil {
		t.Fatal(e)
	}
	f.m, e = f.m.Return(b, settingsUseProof(t, f, b))
	if e != nil {
		t.Fatal(e)
	}
	cfg := ownDNSConfig(f.d.cfg)
	cfg.ID = "other"
	f.d = grantDNS(t, f.d, cfg)
	target, e := DNSSettings(f.d.f.c, f.d.f.n, f.d.f.a, "admin", cfg, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	f.m, e = f.m.Desired(f.d.f.c, f.d.f.n, f.d.f.a, "admin", 0, target)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.m.Stage(f.d.f.c, f.d.f.n, f.d.f.a, target.Key()); e == nil {
		t.Fatal("different service shared original namespace/53")
	}
	settingsRaw(t, f.m)
}
func TestSettingsPreparedOldSwitchCannotDispatchAfterNewDesired(t *testing.T) {
	f := settingsServing(t)
	cfg := ownDNSConfig(f.d.cfg)
	cfg.Source++
	cfg.Serial++
	f, _ = settingsTarget(t, f, cfg, f.scope)
	var op *reconcile.Operation
	var e error
	f.m, op, e = f.m.PlanSwitch(f.d.f.c, f.d.f.n, f.d.f.a, f.key)
	if e != nil {
		t.Fatal(e)
	}
	step := SettingsStep{SettingsActivate, f.key, 0, *op}
	cfg.Source++
	cfg.Serial++
	f, _ = settingsTarget(t, f, cfg, f.scope)
	if _, e = f.m.Dispatch(f.d.f.c, f.d.f.n, f.d.f.a, step); e == nil {
		t.Fatal("unsent old source dispatched as latest")
	}
	f.m, e = f.m.AbortPrepared(step)
	if e != nil {
		t.Fatal(e)
	}
	settingsRaw(t, f.m)
	f = settingsSwitch(t, f)
	f = settingsPublish(t, f, 203)
}
func TestSettingsNetworkCandidateFreezesCommittedGenerationAndAdoptsSameNative(t *testing.T) {
	lease, _ := networkChangeFixture(t, false)
	m, e := NewSettings(lease.a.cluster, pub(private(32)), [32]byte{9}, 16, 8)
	if e != nil {
		t.Fatal(e)
	}
	f := settingsFixture{d: dnsFixture{f: lease}, m: m, scope: NativeScope{Namespace: [32]byte{99}, Interface: "network-candidate"}, key: "network/first/lan"}
	f.d.f.key = private(32)
	target, e := NetworkSettings(lease.c, lease.n, lease.a, "admin", "first", "lan", true, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	f.m, e = f.m.Desired(lease.c, lease.n, lease.a, "admin", 0, target)
	if e != nil {
		t.Fatal(e)
	}
	var id uint64
	f.m, id, e = f.m.Stage(lease.c, lease.n, lease.a, f.key)
	if e != nil {
		t.Fatal(e)
	}
	group := f.m.slots[id].Group
	f = settingsGroupStep(t, f, group)
	if _, _, e = f.m.PlanSwitch(lease.c, lease.n, lease.a, f.key); e == nil {
		t.Fatal("Reserved target served before source fence/owner CAS")
	}
	lease = changeCommit(t, sourceFence(t, changeDrain(t, lease)))
	f.d.f = lease
	f.d.f.key = private(32)
	var op *reconcile.Operation
	f.m, op, e = f.m.PlanSwitch(lease.c, lease.n, lease.a, f.key)
	if e != nil {
		t.Fatal(e)
	}
	step := SettingsStep{SettingsActivate, f.key, 0, *op}
	payload, e := f.m.NativePlan(step)
	if e != nil {
		t.Fatal(e)
	}
	assigned, _ := lease.n.Network("first", "lan")
	if f.m.slots[id].ActivationNetwork == nil || f.m.slots[id].ActivationNetwork.Generation != assigned.Generation {
		t.Fatal("native activation lacks exact assigned generation")
	}
	f = settingsDispatch(t, f, step)
	p := settingsProof(f.m, step, private(32))
	f.m, e = f.m.Unknown(step)
	if e != nil {
		t.Fatal(e)
	}
	next := assigned
	next.Generation = 0
	next.Revision = 0
	next.Draining = false
	next.Node = "node-a"
	next.Owner = pub(private(31))
	f.d.f.n, e = f.d.f.n.PlanChange(lease.c, "admin", "first", "lan", "next", assigned.Revision, next)
	if e != nil {
		t.Fatal(e)
	}
	original, _ := f.m.NativePlan(step)
	if !bytes.Equal(original, payload) {
		t.Fatal("current root rewrote original assigned native generation")
	}
	f.m, e = f.m.Observe(p)
	if e != nil {
		t.Fatal(e)
	}
	target, e = NetworkSettings(lease.c, f.d.f.n, lease.a, "admin", "first", "lan", false, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	f.m, e = f.m.Desired(lease.c, f.d.f.n, lease.a, "admin", f.m.scopes[f.key].Desired.revision, target)
	if e != nil {
		t.Fatal(e)
	}
	f.m, id, e = f.m.Stage(lease.c, f.d.f.n, lease.a, f.key)
	if e != nil {
		t.Fatal(e)
	}
	if f.m.slots[id].Group != group {
		t.Fatal("committed role recreated the original candidate native group")
	}
	f = settingsSwitch(t, f)
	f.m, e = f.m.Publish(lease.c, f.d.f.n, lease.a, f.key)
	if e != nil {
		t.Fatal(e)
	}
	settingsRaw(t, f.m)
	if _, e = DecodeSettings(settingsRaw(t, f.m)); e != nil {
		t.Fatal(e)
	}
}
func TestSettingsRevokedNodeDeniesLastGoodAndStaleRootAdmission(t *testing.T) {
	f := settingsServing(t)
	old := f.d.f.c
	tenant, _ := old.Tenant("first")
	var e error
	f.d.f.c, e = f.d.f.c.SetNodes("admin", "first", tenant.Revision, []string{"node-b"})
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = f.m.Borrow(f.d.f.c, f.d.f.n, f.d.f.a, f.key, [32]byte{1}, false); e == nil {
		t.Fatal("last good bypassed node grant revocation")
	}
	f = settingsSwitch(t, f)
	if _, _, e = f.m.Borrow(old, f.d.f.n, f.d.f.a, f.key, [32]byte{1}, false); e == nil {
		t.Fatal("old catalog resurrected original admission")
	}
	settingsRaw(t, f.m)
}

func TestSettingsDNSReturnCannotMixOriginalRuntimeAndOtherQueryPins(t *testing.T) {
	f := settingsServing(t)
	f, first := settingsQuery(t, f, 200)
	f, second := settingsQuery(t, f, 200)
	// Identical packet bytes are still two distinct original query lifetimes.
	mixed := SettingsDNSUse{Runtime: first.Runtime, Query: second.Query}
	beforeM, beforeD := settingsRaw(t, f.m), encodeDNS(t, f.d.m)
	m, d, e := f.m.ReleaseDNS(f.d.m, mixed, f.d.clock(201), settingsUseProof(t, f, first.Runtime))
	if e == nil || !bytes.Equal(beforeM, settingsRaw(t, m)) || !bytes.Equal(beforeD, encodeDNS(t, d)) {
		t.Fatal("runtime completion returned a different original DNS query")
	}
	if _, _, e = f.m.ReleaseDNS(f.d.m, second, f.d.clock(201), settingsUseProof(t, f, first.Runtime)); e == nil {
		t.Fatal("another original native completion authorized this query")
	}
	f.m, f.d.m, e = f.m.ReleaseDNS(f.d.m, first, f.d.clock(201), settingsUseProof(t, f, first.Runtime))
	if e != nil || len(f.d.m.Queries()) != 1 || f.d.m.Queries()[0].ID() != second.Query.ID() {
		t.Fatal("first exact return did not preserve the second original query", e)
	}
	f.m, f.d.m, e = f.m.ReleaseDNS(f.d.m, second, f.d.clock(202), settingsUseProof(t, f, second.Runtime))
	if e != nil || len(f.d.m.Queries()) != 0 {
		t.Fatal("second exact return did not settle its own query", e)
	}
	settingsRaw(t, f.m)
}
