// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/json"
	"maps"
	"net/netip"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	dockernet "github.com/moby/moby/api/types/network"
)

// The real SDK request and read-back matcher, without claiming Engine behavior.
func TestBridgeIPAMDockerRangeIsExactSDKInputAndReadback(t *testing.T) {
	p := pool("pool", "10.8.0.0/24")
	p.IPAM = PoolIPAM{Dynamic: netip.MustParsePrefix("10.8.0.0/25")}
	s := BridgeSpec{Schema: 1, Network: p.Network, Owner: p.Owner, MTU: p.MTU, Pools: []Pool{p}}
	raw, _ := json.Marshal(s)
	if _, err := DecodeBridge(string(raw)); err != nil {
		t.Fatal(err)
	}
	id := engine.Identity{Name: "mydc-bridge-0123456789ab", Labels: map[string]string{"owner": "test"}}
	o := bridgeOptions(s, id)
	c := o.IPAM.Config[0]
	if c.IPRange != p.IPAM.Dynamic || len(c.AuxAddress) != 0 {
		t.Fatal("SDK request lost/renamed reservations", c)
	}
	n := dockernet.Inspect{Network: dockernet.Network{ID: "original", Name: id.Name, Labels: maps.Clone(id.Labels), Driver: "bridge", Scope: "local", EnableIPv4: true, Options: maps.Clone(o.Options), IPAM: *o.IPAM}}
	if !matchBridge(n, s, id) {
		t.Fatal("original reservation readback rejected")
	}
	for _, mutate := range []func(*dockernet.Inspect){
		func(n *dockernet.Inspect) { n.IPAM.Config[0].AuxAddress = map[string]netip.Addr{"foreign": p.Gateway} },
		func(n *dockernet.Inspect) { n.IPAM.Config[0].IPRange = p.Prefix },
		func(n *dockernet.Inspect) { n.IPAM.Options = map[string]string{"foreign": "true"} },
	} {
		changed := n
		changed.IPAM.Config = append([]dockernet.IPAMConfig(nil), n.IPAM.Config...)
		changed.IPAM.Config[0].AuxAddress = maps.Clone(c.AuxAddress)
		mutate(&changed)
		if matchBridge(changed, s, id) {
			t.Fatal("changed native IPAM accepted", changed.IPAM)
		}
	}
}
