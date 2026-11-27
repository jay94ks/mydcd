// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/dns"
	"github.com/jay94ks/seafield/internal/web/seal"
	"github.com/jay94ks/seafield/internal/web/store"
)

func vpsDNSShop(t *testing.T, f *fixture) []string {
	t.Helper()
	_, out := f.do("GET", "/api/v1/dns/domains/example.com/records", nil)
	for _, it := range out["items"].([]any) {
		r := it.(map[string]any)
		if r["name"] == "shop" && r["type"] == "A" {
			var got []string
			for _, rec := range r["records"].([]any) {
				got = append(got, rec.(map[string]any)["content"].(string))
			}
			return got
		}
	}
	t.Fatalf("no shop A in %v", out)
	return nil
}

func TestVPSStopTakesItsAddressOutOfDNS(t *testing.T) {
	f, fake := newFakeFixture(t)
	world := dns.NewFakeWorld()
	reg := &dns.Registry{}
	reg.Register(dns.FakeVendor(world))
	box, _ := seal.Open(t.TempDir(), bytes.Repeat([]byte{3}, seal.KeySize))
	f.srv.opt.DNS, f.srv.opt.Seal = reg, box
	addExampleDomain(t, f)
	fakeLogin(t, f, "admin")
	makeAutomation(t, f, "sfc-web", "a1b2c3d4-0000-4000-8000-0000000000e1", true, true)
	op := opSeq("ab14cdef")

	// shop A → node-a and vps-seoul-1; blog A → vps-seoul-1 only.
	apply := func(sets ...map[string]any) {
		t.Helper()
		_, plan := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": sets})
		if code, out := f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": op(), "upsert": sets, "basis": basisOf(t, plan)}); code != 200 {
			t.Fatalf("apply: %d %v", code, out)
		}
	}
	shop := map[string]any{"name": "shop", "type": "A", "records": []map[string]any{{"content": "203.0.113.11"}, {"content": "203.0.113.21"}}}
	blog := map[string]any{"name": "x.shop", "type": "A", "records": []map[string]any{{"content": "203.0.113.21"}}, "ttl": 120}
	apply(shop, blog)
	if _, err := f.store.UpdateDNSServerLinks("example.com", 0, func(l *store.DNSServerLinks) error {
		l.Rows["vps-seoul-1"] = &store.DNSServerLink{AddressSource: "manual", Addresses: []string{"203.0.113.21"}, By: "u-admin", At: time.Now()}
		l.Rows["node-a"] = &store.DNSServerLink{AddressSource: "node", By: "u-admin", At: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The stop dialog's plan.
	code, out := f.do("GET", "/api/v1/system/vps/servers/vps-seoul-1/dns-plan", nil)
	if code != 200 || !strings.Contains(fmt.Sprint(out["rows"]), "name:shop others:1 outcome:withdraw") || !strings.Contains(fmt.Sprint(out["rows"]), "name:x.shop others:0 outcome:keep-last") {
		t.Fatalf("plan: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/system/vps/servers/vps-seoul-1/stop", map[string]any{"opId": op()}); opState(t, code, out) != "applied" {
		t.Fatalf("stop: %d %v", code, out)
	}
	ws, err := f.srv.watchSession(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	round := func() {
		f.srv.vpsDNS.polled = time.Time{}
		f.srv.vpsDNSPoll(t.Context(), ws)
	}
	round()
	if got := vpsDNSShop(t, f); fmt.Sprint(got) != "[203.0.113.11]" {
		t.Fatalf("shop after stop: %v", got)
	}
	_, out = f.do("GET", "/api/v1/system/vps", nil)
	if r := vpsRow(t, out, "vps-seoul-1"); !strings.Contains(fmt.Sprint(r["dnsHolds"]), "domain:example.com") || out["dnsAuto"] != true {
		t.Fatalf("holds: %v %v", r, out["dnsAuto"])
	}
	round() // a second round changes nothing
	if got := vpsDNSShop(t, f); fmt.Sprint(got) != "[203.0.113.11]" {
		t.Fatalf("shop after a second round: %v", got)
	}

	// Running again: the address goes back once it answers from outside.
	reachable := false
	f.srv.hooks.vpsReach = func(_ context.Context, addrs []string) bool {
		if fmt.Sprint(addrs) != "[203.0.113.21]" {
			t.Errorf("reach checked %v", addrs)
		}
		return reachable
	}
	fake.SetVPSPhase("vps-seoul-1", control.VPSRunning)
	round()
	if got := vpsDNSShop(t, f); fmt.Sprint(got) != "[203.0.113.11]" {
		t.Fatalf("put back before it answers: %v", got)
	}
	reachable = true
	round()
	if got := vpsDNSShop(t, f); fmt.Sprint(got) != "[203.0.113.11 203.0.113.21]" {
		t.Fatalf("shop after start: %v", got)
	}
	if hs, _ := f.store.ListVPSDNSHolds(); len(hs) != 0 {
		t.Fatalf("holds kept: %v", hs)
	}

	// Stopped again, and someone edits shop meanwhile: not overwritten.
	fake.SetVPSPhase("vps-seoul-1", control.VPSStopped)
	round()
	apply(map[string]any{"name": "shop", "type": "A", "records": []map[string]any{{"content": "203.0.113.12"}}})
	fake.SetVPSPhase("vps-seoul-1", control.VPSRunning)
	round()
	if got := vpsDNSShop(t, f); fmt.Sprint(got) != "[203.0.113.12]" {
		t.Fatalf("edited shop overwritten: %v", got)
	}
	_, out = f.do("GET", "/api/v1/system/vps", nil)
	if r := vpsRow(t, out, "vps-seoul-1"); !strings.Contains(fmt.Sprint(r["dnsHolds"]), "blocked:[map[after:") {
		t.Fatalf("blocked not shown: %v", r["dnsHolds"])
	}
	if code, out := f.do("DELETE", "/api/v1/system/vps/servers/vps-seoul-1/dns-holds/example.com", nil); code != 200 {
		t.Fatalf("dismiss: %d %v", code, out)
	}

	// Deleted: unlinked from the domain.
	fake.SetVPSPhase("vps-seoul-1", control.VPSStopped)
	round()
	fake.SetVPSPhase("vps-seoul-1", "")
	round()
	if l, _ := f.store.GetDNSServerLinks("example.com"); l.Rows["vps-seoul-1"] != nil || l.Rows["node-a"] == nil {
		t.Fatalf("links after delete: %v", l.Rows)
	}
	if hs, _ := f.store.ListVPSDNSHolds(); len(hs) != 0 {
		t.Fatalf("holds of a deleted server: %v", hs)
	}
}

func TestVPSDNSPutsBackAfterTheReachWait(t *testing.T) {
	f, _ := newFakeFixture(t)
	s := f.srv
	s.hooks.vpsReach = func(context.Context, []string) bool { return false }
	held := map[string]*store.VPSDNSHold{"example.com": {Sets: []store.VPSDNSSet{{Name: "shop", Type: "A", Removed: []string{"203.0.113.21"}}}}}
	if s.vpsDNSReady(t.Context(), control.VPSServer{PhaseAt: s.now().Unix()}, held) {
		t.Fatal("ready before it answers")
	}
	if !s.vpsDNSReady(t.Context(), control.VPSServer{PhaseAt: s.now().Add(-vpsDNSReachWait).Unix()}, held) {
		t.Fatal("still waiting after the reach wait")
	}
}
