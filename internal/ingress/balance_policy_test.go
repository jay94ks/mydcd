// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"fmt"
	"net/netip"
	"testing"
)

func policyBalancer(t *testing.T, weights map[string]int) (*Balancer, map[string]BackendSpec) {
	t.Helper()
	b, err := NewBalancer(100000)
	if err != nil {
		t.Fatal(err)
	}
	specs := map[string]BackendSpec{}
	for id, w := range weights {
		if err = b.Update(Backend{ID: id, Generation: 1, Weight: w, Capacity: 128, Healthy: true, ObservedAt: 100}); err != nil {
			t.Fatal(err)
		}
		specs[id] = BackendSpec{ID: id, Node: "node-a", Labels: map[string]string{"track": "stable"}}
	}
	return b, specs
}
func TestBalanceSmoothWeightsAndJournalRetainInterleaving(t *testing.T) {
	b, specs := policyBalancer(t, map[string]int{"a": 5, "b": 1, "c": 1})
	counts := map[string]int{}
	last := ""
	run, maxRun := 0, 0
	for n := 0; n < 70; n++ {
		pin, err := b.AcquireWith(100, Balance{}, Selection{Backends: specs})
		if err != nil {
			t.Fatal(err)
		}
		counts[pin.Backend]++
		if last == pin.Backend {
			run++
		} else {
			last = pin.Backend
			run = 1
		}
		maxRun = max(maxRun, run)
		if b.Release(pin) != nil {
			t.Fatal("release")
		}
		if n == 20 {
			b, err = RestoreBalancer(b.Checkpoint())
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if counts["a"] != 50 || counts["b"] != 10 || counts["c"] != 10 || maxRun >= 5 {
		t.Fatal("blocked weighted schedule", counts, maxRun)
	}
}
func TestBalanceLeastRequestUsesActiveLeaseAndWeight(t *testing.T) {
	b, specs := policyBalancer(t, map[string]int{"a": 1, "b": 1})
	p := Balance{Method: "least-request"}
	first, err := b.AcquireWith(100, p, Selection{Backends: specs})
	if err != nil {
		t.Fatal(err)
	}
	next, err := b.AcquireWith(100, p, Selection{Backends: specs})
	if err != nil || first.Backend == next.Backend {
		t.Fatal("active load ignored", first, next, err)
	}
	if b.Release(first) != nil || b.Release(next) != nil {
		t.Fatal("release")
	}
}

func TestBalanceRandomUsesSuppliedEntropyAndWeights(t *testing.T) {
	b, specs := policyBalancer(t, map[string]int{"a": 1, "b": 3})
	counts := map[string]int{}
	for entropy := range uint64(120) {
		pin, err := b.AcquireWith(100, Balance{Method: "random"}, Selection{Backends: specs, Entropy: entropy})
		if err != nil {
			t.Fatal(err)
		}
		counts[pin.Backend]++
		if err = b.Release(pin); err != nil {
			t.Fatal(err)
		}
	}
	if counts["a"] != 30 || counts["b"] != 90 {
		t.Fatal("weighted random entropy slots", counts)
	}
}
func TestBalanceRendezvousRetainsEverySurvivingBackendAssignment(t *testing.T) {
	b, specs := policyBalancer(t, map[string]int{"a": 1, "b": 1, "c": 1})
	p := Balance{Method: "hash", Key: "cookie:session"}
	before := map[string]string{}
	for n := 0; n < 1000; n++ {
		key := fmt.Sprint(n)
		pin, err := b.AcquireWith(100, p, Selection{Backends: specs, Cookies: map[string]string{"session": key}})
		if err != nil {
			t.Fatal(err)
		}
		before[key] = pin.Backend
		if b.Release(pin) != nil {
			t.Fatal("release")
		}
	}
	if err := b.Update(Backend{ID: "c", Generation: 1, Weight: 1, Capacity: 128, Healthy: true, Draining: true, ObservedAt: 100}); err != nil {
		t.Fatal(err)
	}
	if b.Remove("c", 1) != nil {
		t.Fatal("remove")
	}
	for key, original := range before {
		pin, err := b.AcquireWith(100, p, Selection{Backends: specs, Cookies: map[string]string{"session": key}})
		if err != nil || original != "c" && pin.Backend != original {
			t.Fatal("surviving assignment moved", key, original, pin, err)
		}
		if b.Release(pin) != nil {
			t.Fatal("release")
		}
	}
}
func TestBalanceConditionsPercentFallbackAndLocality(t *testing.T) {
	ten := 10
	one := "1"
	p := Balance{Groups: map[string]BackendGroup{"canary": {Labels: map[string]string{"track": "canary"}}}, Match: []BalanceCondition{{ID: "header", Group: "canary", Headers: map[string]ValueMatch{"X-Canary": {Equal: &one}}}, {ID: "sample", Group: "canary", Percent: &ten, Key: "cookie:session"}}}
	if p.Validate() != nil {
		t.Fatal("valid condition refused")
	}
	if group, condition := p.Select(Selection{Headers: map[string]string{"X-Canary": "1"}}); group != "canary" || condition != "header" {
		t.Fatal(group, condition)
	}
	count := 0
	for n := 0; n < 10000; n++ {
		key := fmt.Sprint(n)
		q := Selection{Cookies: map[string]string{"session": key}, Source: netip.MustParseAddr("192.0.2.1")}
		g, c := p.Select(q)
		again, againC := p.Select(q)
		if g != again || c != againC {
			t.Fatal("nondeterministic condition")
		}
		if g != "" {
			count++
		}
	}
	if count < 850 || count > 1150 {
		t.Fatal("10 percent sample", count)
	}
	b, specs := policyBalancer(t, map[string]int{"a": 1, "b": 1})
	specs["a"] = BackendSpec{ID: "a", Node: "node-a", Labels: map[string]string{"track": "canary"}}
	specs["b"] = BackendSpec{ID: "b", Node: "node-b"}
	p.Locality = "same-node"
	for n := 0; n < 10; n++ {
		pin, err := b.AcquireWith(100, p, Selection{Node: "node-a", Backends: specs})
		if err != nil || pin.Backend != "a" {
			t.Fatal("locality", pin, err)
		}
		b.Release(pin)
	}
	p.Fallback = "503"
	if _, err := b.AcquireWith(100, p, Selection{Backends: specs, Group: "canary", Exclude: map[string]bool{"a": true}}); err == nil {
		t.Fatal("empty selected group silently used default")
	}
}
func TestBalanceRejectsMalformedPolicyAndSlowStartUsesOriginalHealthyTime(t *testing.T) {
	hundred := 100
	for _, p := range []Balance{{Method: "hash", Key: "header:bad name"}, {Method: "hash"}, {Retry: 9}, {Groups: map[string]BackendGroup{"x": {Version: "v1"}}, Match: []BalanceCondition{{ID: "a", Group: "x", Percent: &hundred}, {ID: "b", Group: "x", Percent: &hundred}}}, {Match: []BalanceCondition{{ID: "a", Group: "missing"}}}} {
		if p.Validate() == nil {
			t.Fatal("unsafe balance policy accepted", p)
		}
	}
	b, specs := policyBalancer(t, map[string]int{"a": 1000, "b": 1000})
	b.backends["b"].healthySince = 1
	counts := map[string]int{}
	for n := 0; n < 100; n++ {
		pin, err := b.AcquireWith(100, Balance{SlowStartMS: 100}, Selection{Backends: specs})
		if err != nil {
			t.Fatal(err)
		}
		counts[pin.Backend]++
		b.Release(pin)
	}
	if counts["a"] > 2 {
		t.Fatal("new backend received full share", counts)
	}
}
