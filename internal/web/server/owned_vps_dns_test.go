// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/dns"
	"github.com/jay94ks/seafield/internal/web/seal"
	"github.com/jay94ks/seafield/internal/web/store"
)

// An owned VPS held for traffic in exclude mode leaves DNS like a stopped
// VPS, and comes back once the hold ends; low-weight leaves DNS alone.
func TestOwnedVPSTrafficHoldTakesItsAddressOutOfDNS(t *testing.T) {
	f, fake := newFakeFixture(t)
	world := dns.NewFakeWorld()
	reg := &dns.Registry{}
	reg.Register(dns.FakeVendor(world))
	box, _ := seal.Open(t.TempDir(), bytes.Repeat([]byte{3}, seal.KeySize))
	f.srv.opt.DNS, f.srv.opt.Seal = reg, box
	addExampleDomain(t, f)
	fakeLogin(t, f, "admin")
	makeAutomation(t, f, "sfc-web", "a1b2c3d4-0000-4000-8000-0000000000e2", true, true)
	op := opSeq("ab15cdef")
	shop := map[string]any{"name": "shop", "type": "A", "records": []map[string]any{{"content": "203.0.113.11"}, {"content": "203.0.113.31"}}}
	_, plan := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{shop}})
	if code, out := f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": op(), "upsert": []any{shop}, "basis": basisOf(t, plan)}); code != 200 {
		t.Fatalf("apply: %d %v", code, out)
	}
	if _, err := f.store.UpdateDNSServerLinks("example.com", 0, func(l *store.DNSServerLinks) error {
		l.Rows["edge-9"] = &store.DNSServerLink{AddressSource: "manual", Addresses: []string{"203.0.113.31"}, By: "u-admin", At: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ws, err := f.srv.watchSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	round := func() {
		f.srv.vpsDNS.polled = time.Time{}
		f.srv.vpsDNSPoll(t.Context(), ws)
	}
	f.srv.hooks.vpsReach = func(context.Context, []string) bool { return true }
	now := time.Now().Unix()
	v := control.OwnedVPS{Name: "edge-9", Account: "home", InstanceID: "9", Install: control.OwnedInstallManual, Port: 7443, Protect: control.OwnedProtectLowWeight,
		Phase: control.OwnedRunning, PublicIP: "203.0.113.31", Request: "op-9", AttachedBy: "admin", AttachedAt: now, UpdatedBy: "admin", UpdatedAt: now}
	hold := func(mode string) *control.OwnedLimit {
		return &control.OwnedLimit{At: now, Month: control.OwnedMonthOf(time.Unix(now, 0)), Mode: mode, UsedMB: 96, MonthMB: 100}
	}

	v.Limit = hold(control.OwnedProtectLowWeight)
	fake.SetOwnedVPS(v)
	round()
	if got := vpsDNSShop(t, f); fmt.Sprint(got) != "[203.0.113.11 203.0.113.31]" {
		t.Fatalf("low-weight changed DNS: %v", got)
	}

	v.Protect, v.Limit = control.OwnedProtectExclude, hold(control.OwnedProtectExclude)
	fake.SetOwnedVPS(v)
	round()
	if got := vpsDNSShop(t, f); fmt.Sprint(got) != "[203.0.113.11]" {
		t.Fatalf("held, still in DNS: %v", got)
	}
	round() // kept: an owned server is not "gone" from the managed page
	if hs, _ := f.store.ListVPSDNSHolds(); len(hs) != 1 {
		t.Fatalf("holds: %v", hs)
	}

	v.Limit, v.Restored = nil, &control.OwnedRestore{At: now, Month: control.OwnedMonthOf(time.Unix(now, 0)), By: "admin"}
	fake.SetOwnedVPS(v)
	round()
	if got := vpsDNSShop(t, f); fmt.Sprint(got) != "[203.0.113.11 203.0.113.31]" {
		t.Fatalf("not put back: %v", got)
	}
	if hs, _ := f.store.ListVPSDNSHolds(); len(hs) != 0 {
		t.Fatalf("holds kept: %v", hs)
	}
}
