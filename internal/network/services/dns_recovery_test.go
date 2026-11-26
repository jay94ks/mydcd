// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"testing"
)

func TestDNSOriginalQueryUsesPreserveBothPinnedViews(t *testing.T) {
	f := settingsServing(t)
	f, first := settingsQuery(t, f, 200)
	cfg := f.d.cfg
	cfg.Source++
	cfg.Serial++
	f, _ = settingsTarget(t, f, cfg, f.scope)
	f = settingsSwitch(t, f)
	f = settingsPublish(t, f, 201)
	f, second := settingsQuery(t, f, 202)
	before := settingsRaw(t, f.m)
	uses, err := f.m.originalDNSUses(f.d.m)
	if err != nil || len(uses) != 2 || uses[0] == uses[1] {
		t.Fatal("original uses", uses, err)
	}
	if !bytes.Equal(before, settingsRaw(t, f.m)) {
		t.Fatal("handle recovery changed journals")
	}
	for _, want := range []SettingsDNSUse{first, second} {
		found := false
		for _, got := range uses {
			found = found || got == want
		}
		if !found {
			t.Fatal("recovery changed original slot/query handle")
		}
	}
	group := f.m.slots[first.Runtime.slot].Group
	groupBefore := f.m.groups[group]
	for _, use := range uses {
		f.m, f.d.m, err = f.m.ReleaseDNS(f.d.m, use, f.d.clock(210), settingsUseProof(t, f, use.Runtime))
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(f.d.m.Queries()) != 0 || f.m.groups[group].State.LastID != groupBefore.State.LastID || len(f.m.groups[group].Pins.Active) != len(groupBefore.Pins.Active) {
		t.Fatal("query settlement discarded group dependency or original operation")
	}
	view := f.d.m.views[first.Query.view]
	if !view.Retired || view.Hold != f.d.clock(210) || view.Last != f.d.clock(210) {
		t.Fatal("original retired view did not retain full TTL after completion", view.Hold)
	}
	if _, err = f.d.m.Collect(first.Query.view, f.d.clock(210+int64(view.Projection.Config.TTL)-1)); err == nil {
		t.Fatal("released address before full original TTL")
	}
	if _, err = f.d.m.Collect(first.Query.view, f.d.clock(210+int64(view.Projection.Config.TTL))); err != nil {
		t.Fatal("original TTL could not settle", err)
	}
	if uses, err = f.m.originalDNSUses(f.d.m); err != nil || len(uses) != 0 {
		t.Fatal("settlement not empty", err)
	}
}

func TestDNSOriginalQueryUsesRejectOrphansAndWrongBindings(t *testing.T) {
	f := settingsServing(t)
	f, h := settingsQuery(t, f, 200)
	for _, name := range []string{"missing-user", "missing-query", "wrong-request", "wrong-scope", "wrong-source", "wrong-boot", "foreign-owner"} {
		t.Run(name, func(t *testing.T) {
			m, d := f.m.clone(), f.d.m.clone()
			slot := m.slots[h.Runtime.slot]
			switch name {
			case "missing-user":
				delete(slot.Users, h.Runtime.pin.Token)
			case "missing-query":
				var err error
				d, err = d.Release(h.Query, f.d.clock(201))
				if err != nil {
					t.Fatal(err)
				}
			case "wrong-request":
				slot.Users[h.Runtime.pin.Token] = [32]byte{99}
			case "wrong-scope":
				slot.Target.key = "dns/other/dns"
			case "wrong-source":
				slot.Target.revision++
			case "wrong-boot":
				m.boot[0]++
			case "foreign-owner":
				d.owner[0]++
			}
			m.slots[slot.ID] = slot
			if _, err := m.originalDNSUses(d); err == nil {
				t.Fatal("mismatched original request accepted")
			}
		})
	}
}
