// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestAppsReadProjectionReturnsOwnedResults(t *testing.T) {
	f, owner, _ := permitDecodeFixture(t)
	// Binding the Task changes the managed DNS projection. Publish that exact
	// current view too; an older empty projection must remain insufficient.
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	permitAppsDecoded.Store(nil)
	first, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	cached := permitAppsDecoded.Load()
	if cached == nil {
		t.Fatal("projection did not reuse the checked Apps interpretation")
	}
	wantProjection, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	_, rows, ok := cached.apps.NetworkDNS(owner)
	if !ok || len(rows) == 0 || rows[0].Managed == nil {
		t.Fatal("managed DNS fixture")
	}
	selection := rows[0].Config
	material, row, err := f.p.AppDNSMaterial(f.s, owner, selection.Tenant, selection.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantMaterial, _ := json.Marshal(material)
	wantRow, _ := json.Marshal(row)
	for key, goal := range first.Goals {
		if len(goal.Goal.Config) > 0 {
			goal.Goal.Config[0] ^= 1
			delete(first.Goals, key)
			break
		}
	}
	first.ManagedDNSConsumers["caller"] = 123
	row.Managed.Node = "caller"
	material.ProtectedZones = append(material.ProtectedZones, "caller.invalid")
	material.Config.Zone = "caller.invalid"
	// A new owned Apps/reducer view must still be independent of the borrowed
	// interpretation used by both projection consumers.
	owned, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for key := range owned.entries {
		delete(owned.entries, key)
	}
	check := func() {
		projection, err := f.p.ProjectResources(f.s)
		if err != nil {
			t.Error(err)
			return
		}
		gotProjection, _ := json.Marshal(projection)
		got, row, err := f.p.AppDNSMaterial(f.s, owner, selection.Tenant, selection.ID)
		gotMaterial, _ := json.Marshal(got)
		gotRow, _ := json.Marshal(row)
		if err != nil || !bytes.Equal(gotProjection, wantProjection) || !bytes.Equal(gotMaterial, wantMaterial) || !bytes.Equal(gotRow, wantRow) {
			t.Error("caller mutation changed cached projection/DNS output", err)
		}
	}
	check()
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() { check() })
	}
	group.Wait()
	if permitAppsDecoded.Load() != cached {
		t.Fatal("unchanged reads replaced the interpretation")
	}
}

func TestAppsReadProjectionRechecksCurrentSourceAndCatalog(t *testing.T) {
	f, owner, _ := permitDecodeFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, err := f.p.readOnlyApps(f.s)
	_, rows, ok := apps.NetworkDNS(owner)
	if err != nil || !ok || len(rows) == 0 {
		t.Fatal("DNS fixture", err)
	}
	row := rows[0]
	if _, _, err := f.p.AppDNSMaterial(f.s, owner, row.Config.Tenant, row.Config.ID); err != nil {
		t.Fatal(err)
	}
	// Apps bytes stay identical while the actual managed DNS source changes.
	changed := permitDecodeWrites(t, f.s, row.Source.Key, map[string][]byte{row.Source.Key: []byte("{}")})
	if _, _, err := f.p.AppDNSMaterial(changed, owner, row.Config.Tenant, row.Config.ID); err == nil {
		t.Fatal("old DNS source accepted from the interpretation")
	}
	// Keep a valid catalog checkpoint and the same user, but remove the tenant.
	catalog, _ := f.p.Catalog(f.s)
	user, _ := catalog.User("admin")
	user.Revision = 0
	empty, _ := access.New(f.p.BootstrapKey)
	empty, err = empty.Enroll(f.p.BootstrapKey, user)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := empty.Encode()
	writes, code := writeCheckpoint(f.s, CatalogKey, f.p.Cluster, f.p.TrustRoot, empty.Revision(), raw)
	if code != state.Applied {
		t.Fatal(code)
	}
	changed = permitDecodeWrites(t, f.s, CatalogKey, writes)
	if _, err := f.p.ProjectResources(changed); err == nil {
		t.Fatal("removed tenant accepted by the resource projection")
	}
	if _, _, err := f.p.AppDNSMaterial(changed, owner, row.Config.Tenant, row.Config.ID); err == nil {
		t.Fatal("removed tenant accepted by DNS material")
	}
}
