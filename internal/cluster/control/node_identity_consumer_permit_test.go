// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestRotatedBindingPermitChargesOriginalNetworkConsumers(t *testing.T) {
	f, original, request := permitDecodeFixture(t)
	want, err := f.p.AppBindingPermit(f.s, original, request)
	if err != nil {
		t.Fatal("original permit", err)
	}
	next := rotateRQ9CoreOwner(t, f)
	current := [32]byte(next.Public().(ed25519.PublicKey))
	got, err := f.p.AppBindingPermit(f.s, current, request)
	if err != nil || !bytes.Equal(want.Binding, got.Binding) || want.ReadSet != got.ReadSet || want.Task != got.Task || want.Inputs != got.Inputs || want.MaxConsumers != got.MaxConsumers {
		t.Fatal("current key cannot borrow original unchanged inputs/network", err)
	}
	for _, key := range [][32]byte{original, {99}} {
		if _, err := f.p.AppBindingPermit(f.s, key, request); err == nil {
			t.Fatal("historical or foreign current caller admitted")
		}
	}
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	used, err := networkConsumerUsageProjection(projection)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, row := range used {
		if row.node == "node-a" {
			total += row.base + len(row.consumers)
		}
	}
	if total < 2 {
		t.Fatal("fixture lacks distinct original consumers", total)
	}
	catalog, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	limit, _ := projection.Resources.Quotas.Limit("", "node-a")
	originalQuotas := projection.Resources.Quotas
	expected := limit.Revision
	limit.Revision, limit.MaxConsumers = 0, total-1
	projection.Resources.Quotas, err = projection.Resources.Quotas.Set(catalog, "admin", expected, limit, projection.Resources.Networks)
	if err != nil {
		t.Fatal(err)
	}
	if err := admitIngressConsumers(projection, projection.Goals[request.Task.Key]); err == nil {
		t.Fatal("rotation discarded original consumers from shared quota")
	}
	// A forged source is not made same-node by sharing the node name.
	projection.Resources.Quotas = originalQuotas
	for source, row := range used {
		if row.node == "node-a" {
			row.owner = [32]byte{99}
			used[source] = row
			break
		}
	}
	if err := admitConsumerUsage(projection, used, "tenant", "node-a", current); err == nil {
		t.Fatal("foreign source owner accepted")
	}
}
