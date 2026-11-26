// SPDX-License-Identifier: Apache-2.0

package reconcile

import "testing"

func TestDrainAndGenerationReplacement(t *testing.T) {
	b, err := NewLeases(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := b.Acquire()
	second, _ := b.Acquire()
	if _, err := b.Acquire(); err == nil {
		t.Fatal("capacity ignored")
	}
	b.Drain()
	if _, err := b.Acquire(); err == nil {
		t.Fatal("draining accepted new borrow")
	}
	if err := b.Replace(2); err == nil {
		t.Fatal("replaced generation with live users")
	}
	if err := b.Release(a); err != nil {
		t.Fatal(err)
	}
	if b.CanRetire() {
		t.Fatal("one release retired two users")
	}
	if err := b.Release(a); err == nil || b.Count() != 1 {
		t.Fatal("duplicate release consumed another user")
	}
	if err := b.Release(second); err != nil || !b.CanRetire() {
		t.Fatal("final user did not permit retirement")
	}
	if err := b.Replace(2); err != nil {
		t.Fatal(err)
	}
	fresh, err := b.Acquire()
	if err != nil || fresh.Token == a.Token || fresh.Token == second.Token || fresh.Generation != 2 {
		t.Fatal("new generation reused old lease", fresh, err)
	}
	if err := b.Release(a); err == nil || b.Count() != 1 {
		t.Fatal("stale token released new generation")
	}
	if err := b.Release(Lease{Token: fresh.Token, Generation: 1}); err == nil || b.Count() != 1 {
		t.Fatal("wrong generation released current lease")
	}
	if err := b.Release(fresh); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseInvalidConfigurationAndOverflow(t *testing.T) {
	for _, c := range []struct {
		g uint64
		n int
	}{{0, 1}, {1, 0}, {1, -1}} {
		if _, err := NewLeases(c.g, c.n); err == nil {
			t.Fatal("invalid lease book accepted")
		}
	}
	b, _ := NewLeases(1, 1)
	if b.CanRetire() {
		t.Fatal("empty active book is not drained")
	}
	b.next = ^uint64(0)
	if _, err := b.Acquire(); err == nil {
		t.Fatal("token wrapped")
	}
	b.Drain()
	if err := b.Replace(1); err == nil {
		t.Fatal("generation did not increase")
	}
}
