// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"testing"
)

func TestEmbeddedNetworkDecodeRetainsCanonicalAndOwnerGuards(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil || apps.network == nil {
		t.Fatal(err)
	}
	raw, err := apps.network.encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAppNetwork(raw, f.p.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	after, err := decoded.encode()
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("canonical bytes changed", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*appNetworkDisk)
	}{
		{"zero-revision", func(d *appNetworkDisk) { d.Revision = 0 }},
		{"group-source", func(d *appNetworkDisk) { d.Groups[0].Source = d.Revision + 1 }},
		{"foreign-owner-with-valid-digest", func(d *appNetworkDisk) {
			d.Groups[0].Owners[0].Managed.Node = "foreign"
			d.Groups[0].Digest = appDNSDigest(d.Groups[0].Owners)
		}},
		{"serial-with-valid-digest", func(d *appNetworkDisk) {
			d.Groups[0].Owners[0].Config.Serial++
			d.Groups[0].Digest = appDNSDigest(d.Groups[0].Owners)
		}},
		{"invalid-nested-authority", func(d *appNetworkDisk) { d.Authority = json.RawMessage(`{}`) }},
		{"foreign-cluster", func(d *appNetworkDisk) { d.Cluster[0] ^= 1 }},
		{"too-many-groups", func(d *appNetworkDisk) {
			g := d.Groups[0]
			d.Groups = make([]appDNSGroup, 1025)
			for i := range d.Groups {
				d.Groups[i] = g
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var d appNetworkDisk
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatal(err)
			}
			test.mutate(&d)
			changed, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decodeAppNetwork(changed, f.p.Cluster); err == nil {
				t.Fatal("invalid committed network accepted")
			}
		})
	}
	for _, changed := range [][]byte{append(bytes.Clone(raw), ' '), append([]byte(`{"unexpected":1,`), raw[1:]...)} {
		if _, err := decodeAppNetwork(changed, f.p.Cluster); err == nil {
			t.Fatal("noncanonical/unknown field accepted")
		}
	}
}
