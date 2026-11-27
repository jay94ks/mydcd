// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Ordinary callers model catalog, Bridge and boot; no native/RPC runs here.
// The explicit kernel fixture supplies its actual boot and native dependency
// while retaining model catalog/approval input for that adapter-only boundary.
func routeOwnerRecordFixture(t *testing.T) (services.ReferenceConsumer, routeOwnerRecord) {
	ref, record, _, _, _ := routeOwnerCoreFixture(t)
	return ref, record
}

type routeOwnerFixtureNative struct {
	Cluster, Boot [32]byte
	Binding       services.RouteNativeBinding
}

func routeOwnerCoreFixture(t *testing.T, native ...routeOwnerFixtureNative) (services.ReferenceConsumer, routeOwnerRecord, access.Catalog, tenancy.Networks, services.Authority) {
	t.Helper()
	clusterID, boot := [32]byte{163}, [32]byte{165}
	if len(native) > 1 {
		t.Fatal("one explicit native fixture input is allowed")
	}
	if len(native) == 1 {
		clusterID, boot = native[0].Cluster, native[0].Boot
		if clusterID == ([32]byte{}) || boot == ([32]byte{}) {
			t.Fatal("explicit native fixture requires actual cluster and boot input")
		}
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{161}, 32))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{162}, 32))
	owner := [32]byte(key.Public().(ed25519.PublicKey))
	catalog, err := access.New(owner)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err = catalog.Enroll(owner, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: owner, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	networks, err := tenancy.New(clusterID)
	if err != nil {
		t.Fatal(err)
	}
	sources := []tenancy.SourceIdentity{{Kind: "bridge", Tenant: "first", Network: "lan", Node: "node-a"}, {Kind: "bridge", Tenant: "second", Network: "lan", Node: "node-b"}}
	keys := []ed25519.PrivateKey{key, other}
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.61.0.0/24"), netip.MustParsePrefix("10.62.0.0/24")}
	for i, source := range sources {
		catalog, err = catalog.CreateTenant("admin", source.Tenant, 0)
		if err != nil {
			t.Fatal(err)
		}
		tenant, _ := catalog.Tenant(source.Tenant)
		catalog, err = catalog.SetNodes("admin", source.Tenant, tenant.Revision, []string{source.Node})
		if err != nil {
			t.Fatal(err)
		}
		networks, err = networks.Create(catalog, "admin", networks.Revision(), tenancy.Network{Tenant: source.Tenant, ID: source.MemberID(), Node: source.Node, Owner: [32]byte(keys[i].Public().(ed25519.PublicKey)), Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefixes[i], Gateway: prefixes[i].Addr().Next(), MTU: 1280}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	book, err := networks.AddressPlan(16)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := services.NewAuthority(networks.Cluster(), book)
	if err != nil {
		t.Fatal(err)
	}
	src, err := networks.Bind("first", sources[0].MemberID(), prefixes[0])
	if err != nil {
		t.Fatal(err)
	}
	dst, err := networks.Bind("second", sources[1].MemberID(), prefixes[1])
	if err != nil {
		t.Fatal(err)
	}
	networks, err = networks.Propose(catalog, "admin", networks.Revision(), tenancy.Route{ID: "database", Source: src, Destination: dst, Protocol: 6, Ports: []tenancy.Ports{{First: 3306, Last: 3306}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []string{"first", "second"} {
		route, _ := networks.Route("first", "database")
		networks, err = networks.Approve(catalog, "admin", "first", "database", side, route.Revision)
		if err != nil {
			t.Fatal(err)
		}
	}
	binding := services.RouteNativeBinding{Key: sources[0].Key(), Generation: 5, Revision: 7, Spec: [32]byte{164}}
	if len(native) == 1 {
		binding = native[0].Binding
	}
	authority, ref, err := authority.GrantRouteInstance(catalog, networks, "admin", "first", "database", "first", 0, binding)
	if err != nil {
		t.Fatal(err)
	}
	core, err := services.NewRouteRuntime(catalog, networks, authority, ref.ID, boot, 2)
	if err != nil {
		t.Fatal(err)
	}
	core, operation, err := core.Plan()
	if err != nil || operation == nil || operation.ID != 1 {
		t.Fatal(err)
	}
	record := routeOwnerRecord{Schema: 1, Nonce: [32]byte{166}}
	record.Core, err = core.Encode()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := services.RouteTunnelDefinition(ref)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(spec)
	record.Dispatch = services.RouteDispatch{Cluster: networks.Cluster(), Reference: services.ReferenceNeed{Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: owner}, Boot: boot, Journal: services.RouteJournalDigest(ref, record.Nonce), Spec: ref.DesiredHash, NativeSpec: sha256.Sum256(raw), Operation: 1}
	record.Dispatch.Signature = ed25519.Sign(key, services.RouteDispatchBytes(record.Dispatch))
	report := control.RouteDispatchReport{Schema: 1, Kind: "route-dispatch", Cluster: networks.Cluster(), Reporter: owner, Epoch: 1, RootRevision: 10, Dispatch: record.Dispatch}
	report.Signature = ed25519.Sign(key, control.RouteDispatchReportBytes(report))
	record.Report = &report
	return ref, record, catalog, networks, authority
}

func TestRouteOwnerOriginalPreparedRecordSurvivesSameDBAndSharedACKResolution(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{reports: db}
	if _, found, err := runtime.loadRouteOwner(ref); err != nil || found {
		t.Fatal("fresh preparation was not distinguished from missing dispatched work", err)
	}
	if err := runtime.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	runtime = &Runtime{reports: db}
	ref.Dispatch = &record.Dispatch
	restored, found, err := runtime.loadRouteOwner(ref)
	if err != nil || !found || restored.Nonce != record.Nonce || !bytes.Equal(restored.Core, record.Core) || restored.Report == nil || !sameRouteDispatch(restored.Report.Dispatch, record.Dispatch) {
		t.Fatal("ACK loss/restart replaced original nonce, core or submission", err)
	}
	// A latest shared marker resolves the original report; it is not Applied.
	restored.Report = nil
	if err := runtime.saveRouteOwner(restored, ref); err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(restored.Core)
	if err != nil || core.Journal().Applied.Present || core.Journal().Pending == nil || core.Journal().Pending.ID != 1 {
		t.Fatal("shared intention fabricated a native result", err)
	}
	if err := db.Write(map[string][]byte{routeOwnerKey(ref.ID): nil}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runtime.loadRouteOwner(ref); err == nil {
		t.Fatal("lost dispatched record was treated as a fresh initialization")
	}
}

func TestRouteOwnerRejectsChangedNonceDependencySubmissionAndFailedStore(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	original, _ := json.Marshal(record)
	for _, mutate := range []func(*routeOwnerRecord){
		func(r *routeOwnerRecord) { r.Nonce[0]++ },
		func(r *routeOwnerRecord) { r.Dispatch.NativeSpec[0]++ },
		func(r *routeOwnerRecord) { r.Report.RootRevision++ },
		func(r *routeOwnerRecord) { r.Dispatch.Reference.Lifetime.Token++ },
		func(r *routeOwnerRecord) { r.Core = json.RawMessage(`{}`) },
	} {
		var changed routeOwnerRecord
		if err := json.Unmarshal(original, &changed); err != nil {
			t.Fatal(err)
		}
		mutate(&changed)
		raw, _ := json.Marshal(changed)
		if _, err := decodeRouteOwner(raw, ref); err == nil {
			t.Fatal("changed original record accepted")
		}
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{reports: db}
	gate := runtime.routeGate(ref.ID)
	gate.view.Store(&routePacketView{})
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.saveRouteOwner(record, ref); err == nil || !runtime.routeStoreFailed {
		t.Fatal("write failure left route owner publishable")
	}
	if gate.view.Load() != nil {
		t.Fatal("failed owner store retained an already published packet gate")
	}
	if _, _, err := runtime.loadRouteOwner(ref); err == nil {
		t.Fatal("failed store was reused before reopening")
	}
}
