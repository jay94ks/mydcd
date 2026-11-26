// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"net/netip"
	"testing"
)

func TestResolverRejectsAmbiguousOrUnsafeNativeInputs(t *testing.T) {
	for _, r := range []Resolver{
		{Servers: []netip.Addr{netip.Addr{}}},
		{Servers: []netip.Addr{netip.MustParseAddr("0.0.0.0")}},
		{Servers: []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")}},
		{Servers: []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}},
		{Servers: []netip.Addr{netip.MustParseAddr("224.0.0.1")}},
		{Search: []string{"bad\nsearch"}},
		{Search: []string{"bad search"}},
		{Search: []string{""}},
		{Search: []string{"a", "b", "c", "d", "e", "f", "g"}},
	} {
		if r.Validate() == nil {
			t.Fatal("unsafe resolver accepted", r)
		}
	}
	for _, r := range []Resolver{{}, {Servers: []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53")}, Search: []string{"app.mydc.test", "."}}} {
		if err := r.Validate(); err != nil {
			t.Fatal("valid resolver refused", r, err)
		}
	}
}
