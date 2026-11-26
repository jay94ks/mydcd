// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestCommittedAddressProjectionRetainsDrainWithoutNewAdmission(t *testing.T) {
	b, _ := NewBook(2)
	p := pool("original", "10.92.0.0/24")
	p.Draining = true
	b, err := b.AddPool(p)
	if err != nil {
		t.Fatal(err)
	}
	before := b.Checkpoint()
	ip := netip.MustParseAddr("10.92.0.10")
	held, err := b.WithCommittedAllocation("workload/task/tenant/app/web/4", p.Owner, p.Network, 77, ip)
	if err != nil || held.Count() != 1 || !reflect.DeepEqual(before, b.Checkpoint()) {
		t.Fatal("committed Drain hold", err)
	}
	if _, _, err = held.Reserve("new", p.Owner, p.Network, "", 78, netip.MustParseAddr("10.92.0.11")); err == nil {
		t.Fatal("projection opened Drain for new admission")
	}
	for _, a := range []netip.Addr{{}, ip, p.Gateway, p.Prefix.Addr(), netip.MustParseAddr("10.93.0.10")} {
		if _, err = held.WithCommittedAllocation("other", p.Owner, p.Network, 78, a); err == nil {
			t.Fatal("invalid/duplicate hold", a)
		}
	}
	if _, err = held.WithCommittedAllocation("foreign", "other", p.Network, 78, netip.MustParseAddr("10.92.0.11")); err == nil {
		t.Fatal("foreign hold")
	}
	if duplicate, err := held.WithCommittedAllocation("workload/task/tenant/app/web/4", p.Owner, p.Network, 77, ip); err != nil || duplicate.Count() != 1 {
		t.Fatal("exact original projection", err)
	}
}
