// SPDX-License-Identifier: Apache-2.0

package ingress

import "testing"

func TestHealthTimeoutPreservesOnlyOriginalFreshSuccess(t *testing.T) {
	b, _ := NewBalancer(10)
	s := Backend{ID: "a", Generation: 1, Weight: 1, Capacity: 2, Healthy: true, ObservedAt: 100}
	if err := b.ObserveHealth(s, true); err != nil {
		t.Fatal(err)
	}
	held, err := b.Acquire(101)
	if err != nil {
		t.Fatal(err)
	}
	s.Healthy = false
	s.ObservedAt = 105
	if err := b.ObserveHealth(s, false); err != nil {
		t.Fatal(err)
	}
	probe, err := b.Acquire(109)
	if err != nil {
		t.Fatal("timeout erased a still-fresh successful observation", err)
	}
	if err = b.Release(probe); err != nil {
		t.Fatal(err)
	}
	if b.Checkpoint().Backends[0].Spec.ObservedAt != 100 {
		t.Fatal("timeout renewed successful observation")
	}
	s.ObservedAt = 110
	if err = b.ObserveHealth(s, false); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Acquire(111); err == nil {
		t.Fatal("unknown probe extended freshness")
	}
	s.ObservedAt = 112
	if err = b.ObserveHealth(s, true); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Acquire(112); err == nil {
		t.Fatal("known HTTP failure ignored")
	}
	s.Healthy = true
	s.ObservedAt = 113
	if err = b.ObserveHealth(s, true); err != nil {
		t.Fatal(err)
	}
	s.Draining = true
	s.ObservedAt = 114
	if err = b.ObserveHealth(s, false); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Acquire(114); err == nil {
		t.Fatal("unknown probe ignored drain")
	}
	if err = b.Release(held); err != nil {
		t.Fatal("original lease lost", err)
	}
	other, _ := NewBalancer(10)
	s.ID = "first"
	s.Draining = false
	s.Healthy = true
	if err = other.ObserveHealth(s, false); err != nil {
		t.Fatal(err)
	}
	if _, err = other.Acquire(114); err == nil {
		t.Fatal("first unknown invented success")
	}
}
