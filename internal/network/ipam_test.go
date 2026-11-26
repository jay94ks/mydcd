// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestIPAMZeroPolicyPreservesSchemaOneEncoding(t *testing.T) {
	p := pool("pool", "10.8.0.0/24")
	raw, err := json.Marshal(p)
	if err != nil || strings.Contains(string(raw), "IPAM") {
		t.Fatal("absent optional policy changed old schema1 input", string(raw), err)
	}
	p.IPAM = PoolIPAM{Dynamic: netip.MustParsePrefix("10.8.0.0/25")}
	raw, err = json.Marshal(p)
	var decoded Pool
	if err != nil || json.Unmarshal(raw, &decoded) != nil || decoded != p {
		t.Fatal("typed policy did not round trip", err)
	}
}
func TestIPAMDockerRangeStaysInsideOwnedCIDR(t *testing.T) {
	for _, raw := range []string{"10.8.0.3/24", "10.9.0.0/24", "2001:db8::/64", "10.0.0.0/8"} {
		p := pool("pool", "10.8.0.0/24")
		p.IPAM.Dynamic = netip.MustParsePrefix(raw)
		b, _ := NewBook(1)
		if _, err := b.AddPool(p); err == nil {
			t.Fatal("invalid Docker range", raw)
		}
	}
}
