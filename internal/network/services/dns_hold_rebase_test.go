// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"

	"github.com/miekg/dns"
)

func TestDNSDriftRebaseRequiresSettledQueriesAndFreshFullTTL(t *testing.T) {
	d := newDNSFixture(t)
	d.cfg.TTL, d.cfg.NegativeTTL = 3, 1
	d = publishDNS(t, d, d.cfg, 190)
	d, h, _ := startDNS(t, d, "web.app.mydc.test.", dns.TypeA, 200)
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	d = publishDNS(t, d, cfg, 201)
	// The observed native failure had 153 wall seconds vs 142 monotonic
	// seconds between retained holds. Do not weaken elapsed's five-second rule.
	now := Clock{Boot: d.f.boot, Wall: 354, Mono: 343, Certain: true}
	if _, known := elapsed(d.m.views[h.view].Hold, now); known {
		t.Fatal("drift unexpectedly counted as original TTL expiry")
	}
	if _, err := d.m.RebaseHold(h.view, now); err == nil {
		t.Fatal("active original I/O pin discarded by rebase")
	}
	var err error
	d.m, err = d.m.Release(h, d.clock(201))
	if err != nil {
		t.Fatal(err)
	}
	before := d.m
	d.m, err = d.m.RebaseHold(h.view, now)
	if err != nil || d.m.views[h.view].Hold != now || before.views[h.view].Hold == now || d.m.Applied("first", "dns") != cfg.Source {
		t.Fatal("settled view could not start a new full TTL or mutated original/source", err)
	}
	if _, err := d.m.Collect(h.view, Clock{Boot: d.f.boot, Wall: 356, Mono: 345, Certain: true}); err == nil {
		t.Fatal("fresh original TTL bypassed")
	}
	d.m, err = d.m.Collect(h.view, Clock{Boot: d.f.boot, Wall: 357, Mono: 346, Certain: true})
	if err != nil {
		t.Fatal("full fresh TTL did not settle", err)
	}
	encodeDNS(t, d.m)
}

func TestDNSFutureRoundedHoldCannotBeRebasedOnEveryPoll(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	old := d.m.current["first/dns"]
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	d = publishDNS(t, d, cfg, 201)
	// A native ceil event may be ahead of the floor check. This is a wait,
	// not permission to keep replacing the hold deadline on every poll.
	if _, err := d.m.RebaseHold(old, d.clock(200)); err == nil {
		t.Fatal("future hold was moved backward/rebased")
	}
	if _, err := d.m.RebaseHold(old, d.clock(201)); err == nil {
		t.Fatal("known unexpired hold was moved forward")
	}
}
