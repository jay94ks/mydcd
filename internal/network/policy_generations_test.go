// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net/netip"
	"testing"
)

// A surged Task's new generation holds its own address under the same
// endpoint while the original still holds its one; never a third.
func TestBookHoldsTwoGenerationsOfOneEndpoint(t *testing.T) {
	b, _ := NewBook(8)
	b, err := b.AddPool(Pool{ID: "p", Network: "n", Owner: "o", Prefix: netip.MustParsePrefix("10.1.0.0/24"), Gateway: netip.MustParseAddr("10.1.0.1"), MTU: 1500})
	if err != nil {
		t.Fatal(err)
	}
	b, old, err := b.Reserve("task/app/0", "o", "n", "", 3, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Reserve("task/app/0", "o", "n", "", 3, netip.MustParseAddr("10.1.0.9")); err == nil {
		t.Fatal("same generation took a second address")
	}
	b, next, err := b.Reserve("task/app/0", "o", "n", "", 5, netip.Addr{})
	if err != nil || next.Address == old.Address || b.Count() != 2 {
		t.Fatal("new generation did not get its own address", next, err)
	}
	if a, _ := b.Allocation("task/app/0"); a != next {
		t.Fatal("endpoint does not name its newest generation")
	}
	if a, ok := b.AllocationOf("task/app/0", 3); !ok || a != old {
		t.Fatal("original generation lost")
	}
	if _, _, err := b.Reserve("task/app/0", "o", "n", "", 7, netip.Addr{}); err == nil {
		t.Fatal("third generation held an address")
	}
	if _, _, err := b.Reserve("task/app/0", "o", "n", "", 4, netip.Addr{}); err == nil {
		t.Fatal("older generation reserved after a newer one")
	}
	restored, err := Restore(b.Checkpoint())
	if err != nil || restored.Count() != 2 {
		t.Fatal("two generations did not survive a checkpoint", err)
	}
	if a, ok := restored.AllocationOf("task/app/0", 3); !ok || a != old {
		t.Fatal("restored book lost the original")
	}
	b, err = b.Release(old)
	if err != nil || b.Count() != 1 {
		t.Fatal("original did not release", err)
	}
	if a, _ := b.Allocation("task/app/0"); a != next {
		t.Fatal("release of the original moved the new generation")
	}
	// Releasing the newest while an older one is held makes it newest again.
	b, again, err := b.Reserve("other/app/0", "o", "n", "", 1, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	b, newer, err := b.Reserve("other/app/0", "o", "n", "", 2, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if b, err = b.Release(newer); err != nil {
		t.Fatal(err)
	}
	if a, _ := b.Allocation("other/app/0"); a != again {
		t.Fatal("older generation is not newest after the newer released")
	}
}
