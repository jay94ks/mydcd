// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
)

func TestResourceCheckpointLargeTypedRestoreAndTenantAuthority(t *testing.T) {
	owner, anchor := [32]byte{81}, [32]byte{82}
	p := Policy{Cluster: [32]byte{71}, BootstrapKey: anchor, TrustRoot: owner, Genesis: config.Peer{ID: "node-a", Key: hex.EncodeToString(owner[:]), Endpoint: "127.0.0.1:8001", Voter: true}}
	catalog, _ := access.New(anchor)
	catalog, err := catalog.Enroll(anchor, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: anchor, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	enrolledCatalog := catalog
	catalog, err = catalog.CreateTenant("admin", "first", 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("first")
	catalog, err = catalog.SetNodes("admin", "first", tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := state.New("admin")
	apply := func(s state.State, key, id string, writes map[string][]byte) (state.State, state.Result) {
		t.Helper()
		c := state.Command{Kind: state.Module, Actor: "admin", Epoch: 1, RequestID: id, Key: key, Expected: s.Object(key).Revision, Value: "fixed-test-checkpoint"}
		next, result, err := state.ApplyReduced(s, s.Index()+1, c, p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
		if err != nil {
			t.Fatal(err)
		}
		return next, result
	}
	writes, code := p.checkpoint(s, catalog)
	if code != state.Applied {
		t.Fatal(code)
	}
	s, result := apply(s, CatalogKey, "catalog", writes)
	if result.Code != state.Applied {
		t.Fatal(result)
	}
	r, err := p.Resources(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"", "first"} {
		r.Quotas, err = r.Quotas.Set(catalog, "admin", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-a", Owner: owner, Capacity: workload.Resources{CPU: 1000, Memory: 1000}}, r.Networks)
		if err != nil {
			t.Fatal(err)
		}
	}
	reserveCount := 0
	for {
		encoded, err := r.Quotas.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) > 64<<10 {
			break
		}
		if reserveCount >= 1000 {
			t.Fatal("cannot reach bounded checkpoint fixture size")
		}
		r.Quotas, err = r.Quotas.Reserve(catalog, "admin", r.Quotas.Revision(), tenancy.Reservation{Key: fmt.Sprintf("workload/task/first/app/budget-%03d", reserveCount), Tenant: "first", Node: "node-a", Owner: owner, Need: workload.Resources{CPU: 1, Memory: 1}})
		if err != nil {
			t.Fatal(err)
		}
		reserveCount++
	}
	r.Revision = r.Quotas.Revision()
	writes, code = p.resourceCheckpoint(s, r)
	if code != state.Applied || len(writes) < 4 {
		t.Fatal("large quota fixture did not span >64KiB", code, len(writes))
	}
	for key, value := range writes {
		if len(value) > 32<<10 {
			t.Fatal("resource row exceeds chunk budget", key, len(value))
		}
	}
	before := s
	s, result = apply(s, ResourcesKey, "resources", writes)
	if result.Code != state.Applied {
		t.Fatal("typed checkpoint rejected", result)
	}
	decoded, err := p.Resources(s)
	if err != nil || len(decoded.Quotas.Reservations()) != reserveCount {
		t.Fatal("large typed resource restore", err)
	}
	raw, err := state.Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	round, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := p.Resources(round)
	if err != nil || !reflect.DeepEqual(decoded, restored) {
		t.Fatal("Snapshot lost typed quota registry", err)
	}
	// Even a checksum-valid resource checkpoint cannot invent its tenant catalog.
	broken := before
	wrong, _ := p.checkpoint(broken, enrolledCatalog)
	broken, retained := apply(broken, CatalogKey, "empty", wrong)
	if retained.Code != state.Applied {
		t.Fatal(retained)
	}
	_, rejected := apply(broken, ResourcesKey, "foreign-resources", writes)
	if rejected.Code != state.Invalid {
		t.Fatal("orphaned quota/tenant references accepted", rejected)
	}
	// Complete pages use the same view and contain only the requested tenant.
	count, cursor := 0, ""
	for {
		page, next, err := decoded.Page(catalog, "admin", "first", cursor)
		if err != nil || len(page) > 8 {
			t.Fatal("resource page", err)
		}
		count += len(page)
		if next == "" {
			break
		}
		if next <= cursor {
			t.Fatal("cursor did not advance")
		}
		cursor = next
	}
	// the tenant's rows and the system range row
	if count != reserveCount+2 {
		t.Fatal("tenant-scoped page count", count)
	}
	// Changing one fragment without its root/other fragment revision is rejected.
	partial := map[string][]byte{ResourcesKey: writes[ResourcesKey], partKey(ResourcesKey, 0): writes[partKey(ResourcesKey, 0)]}
	_, rejected = apply(s, ResourcesKey, "partial", partial)
	if rejected.Code != state.Invalid {
		t.Fatal("mixed resource checkpoint revisions accepted", rejected)
	}
}
