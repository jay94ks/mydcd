// SPDX-License-Identifier: Apache-2.0

package ingress

import "testing"

func holdCounts(t *testing.T, b *Balancer, q Selection, n int) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for range n {
		pin, err := b.AcquireWith(100, Balance{}, q)
		if err != nil {
			t.Fatal(err)
		}
		counts[pin.Backend]++
		if b.Release(pin) != nil {
			t.Fatal("release")
		}
	}
	return counts
}

func TestTrafficHoldsSteerBackends(t *testing.T) {
	m := &Manager{}
	b, specs := policyBalancer(t, map[string]int{"a": 1, "b": 1})
	specs["a"] = BackendSpec{ID: "a", Node: "vps-a"}
	specs["b"] = BackendSpec{ID: "b", Node: "home"}

	// exclude: the held node takes nothing while another backend serves.
	m.SetTrafficHolds(map[string]string{"vps-a": HoldExclude, "other": "bogus"})
	q := Selection{Backends: specs}
	m.holdSelection(&q)
	if c := holdCounts(t, b, q, 34); c["a"] != 0 || c["b"] != 34 {
		t.Fatal("exclude hold still served", c)
	}

	// exclude never takes out the last backend of a route.
	only := Selection{Backends: map[string]BackendSpec{"a": specs["a"]}, Exclude: map[string]bool{"b": true}}
	m.holdSelection(&only)
	if c := holdCounts(t, b, only, 5); c["a"] != 5 {
		t.Fatal("last backend dropped", c)
	}

	// low-weight: a small share next to the others.
	m.SetTrafficHolds(map[string]string{"vps-a": HoldLowWeight})
	q = Selection{Backends: specs}
	m.holdSelection(&q)
	if c := holdCounts(t, b, q, 34); c["a"] != 2 || c["b"] != 32 {
		t.Fatal("low-weight share", c)
	}

	// Restored: no hold, even split.
	m.SetTrafficHolds(nil)
	q = Selection{Backends: specs}
	m.holdSelection(&q)
	if c := holdCounts(t, b, q, 34); c["a"] != 17 || c["b"] != 17 {
		t.Fatal("restored split", c)
	}
}
