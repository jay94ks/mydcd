// SPDX-License-Identifier: Apache-2.0

package services

import (
	"github.com/miekg/dns"
	"testing"
)

func TestDNSDisabledCleanupAfterNodeRevocationNeverEnablesAdmission(t *testing.T) {
	f := settingsServing(t)
	tenant, _ := f.d.f.c.Tenant("first")
	var err error
	f.d.f.c, err = f.d.f.c.SetNodes("admin", "first", tenant.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ownDNSConfig(f.d.cfg)
	cfg.Source++
	cfg.Serial++
	if _, err = DNSSettings(f.d.f.c, f.d.f.n, f.d.f.a, "admin", cfg, f.scope); err == nil {
		t.Fatal("revoked node acquired an enabled target")
	}
	cfg.Enabled = false
	f, _ = settingsTarget(t, f, cfg, f.scope)
	f = settingsSwitch(t, f)
	f = settingsPublish(t, f, 220)
	if _, _, _, err = f.m.AcquireDNS(f.d.f.c, f.d.f.n, f.d.f.a, f.d.m, "first", "dns", f.d.origin, dnsWire("web.app.sfc.test.", dns.TypeA), f.d.clock(221)); err == nil {
		t.Fatal("disabled cleanup admitted a query")
	}
	if f.m.Status(f.key).Applied != cfg.Source || f.m.scopes[f.key].Switch.Applied.Present {
		t.Fatal("cleanup left serving transition")
	}
	settingsRaw(t, f.m)
	encodeDNS(t, f.d.m)
}

func TestDNSClusterPrivateZoneProtectionIsPersistentAndAdditive(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	var err error
	d.m, err = d.m.ProtectZones([]string{"tenant-private.example."})
	if err != nil {
		t.Fatal(err)
	}
	d.m, err = DecodeDNSManager(encodeDNS(t, d.m))
	if err != nil {
		t.Fatal(err)
	}
	d.m, err = d.m.ProtectZones(nil)
	if err != nil {
		t.Fatal(err)
	}
	d, answer := askDNS(t, d, "hidden.tenant-private.example.", dns.TypeA, 200)
	if answer.Forward != nil || answer.Response == nil || answer.Response.Rcode != dns.RcodeRefused {
		t.Fatal("other owner's private zone leaked to configured upstream")
	}
	before := encodeDNS(t, d.m)
	if _, err = d.m.ProtectZones([]string{"bad..example."}); err == nil {
		t.Fatal("invalid private namespace accepted")
	}
	if string(before) != string(encodeDNS(t, d.m)) {
		t.Fatal("invalid policy mutated published state")
	}
}
