// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Shared FSM/signature fixtures deliberately simulate NativeReady and closure.
// They do not claim an actual TLS listener, Engine pull or native I/O join.
func registryFixture(t *testing.T) (*nodeStorageFixture, registry.Specification) {
	t.Helper()
	f := newNodeStorageFixture(t)
	for name, session := range f.sessions {
		session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.ManageRegistry)
		session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
		f.sessions[name] = session
	}
	for _, tenant := range []string{"", "tenant"} {
		f.apply("admin", "set-node-quota", 0, tenancy.NodeLimit{Tenant: tenant, Node: "node-a", Owner: [32]byte(f.node.Public().(ed25519.PublicKey)), Capacity: workload.Resources{CPU: 100, Memory: 1 << 30}, MaxConsumers: 8}, state.Applied)
	}
	scope := volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", ID: "data", Generation: 1, Registry: "private"}
	f.apply("manager", "create-volume", 0, volumeFact(t, scope, "node-a", f.node), state.Applied)
	spec := registry.Specification{Schema: 1, Tenant: "tenant", ID: "private", Node: "node-a", Address: "0.0.0.0:5443", Authority: "registry.example.test:5443", Volume: scope, Enabled: true, Metadata: registry.MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}, Blobs: registry.BlobLimits{BlobBytes: 1 << 20, TotalBytes: 8 << 20, Records: 64}, Budget: workload.Resources{CPU: 2, Memory: 16 << 20}, MaxRequests: 4, MaxHeaderBytes: 8192, RequestTimeoutMS: 30000, TokenSeconds: 60}
	return f, spec
}

func registryEntry(t *testing.T, f *nodeStorageFixture, spec registry.Specification) RegistryEntry {
	t.Helper()
	book, err := f.p.Registries(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := book.Entry(spec.Tenant, spec.ID)
	if !ok {
		t.Fatal("missing registry")
	}
	return entry
}

func registryReportFixture(t *testing.T, f *nodeStorageFixture, report RegistryReport, want state.Code) {
	t.Helper()
	report.Schema, report.Cluster, report.Reporter = 1, f.p.Cluster, [32]byte(f.node.Public().(ed25519.PublicKey))
	report.Epoch, report.RootRevision, report.Index, report.At = f.s.ModuleEpoch(), f.s.Object(RegistriesKey).Revision, f.s.Index(), 3
	if report.Observation != nil {
		report.Observation.At = report.At
	}
	report.Signature = ed25519.Sign(f.node, RegistryReportBytes(report))
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(report.Action, result.Code, want, err)
	}
	f.s = next
}

func registryClosureFixture(f *nodeStorageFixture, run RegistryRunRef) (*volumes.Gone, *tenancy.ReservationClosure) {
	gone := &volumes.Gone{Scope: run.Spec.Volume, Consumer: run.Consumer, Stopped: true, MountsGone: true}
	gone.Signature = ed25519.Sign(f.node, volumes.GoneBytes(*gone))
	budget := &tenancy.ReservationClosure{Schema: 1, Cluster: f.p.Cluster, Key: run.Budget.Key, Node: run.Spec.Node, Owner: run.Owner, Generation: run.Budget.Generation, DrainRevision: run.Budget.Revision, NativeGone: true}
	budget.Signature = ed25519.Sign(f.node, tenancy.ReservationClosureBytes(*budget))
	return gone, budget
}

func TestRegistryReserveDrainClosureAreAtomicAndRetainOriginalVolume(t *testing.T) {
	f, spec := registryFixture(t)
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.Applied)
	entry := registryEntry(t, f, spec)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "reserve", SpecRevision: entry.Revision, Generation: 1}, state.Applied)
	entry = registryEntry(t, f, spec)
	if entry.Active == nil || entry.Generation != 1 || entry.Active.Consumer.OwnerRevision != 1 {
		t.Fatal("missing exact writer")
	}
	resources, _ := f.p.Resources(f.s)
	used, _ := resources.Quotas.Usage(spec.Tenant, spec.Node)
	if used != spec.Budget {
		t.Fatal("registry not in shared budget", used)
	}
	if f.p.storageQuiescent(f.s) {
		t.Fatal("active registry allowed ledger rotation")
	}
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "serving", SpecRevision: entry.Revision, Generation: 1, Observation: &RegistryObservation{Boot: [32]byte{1}, Certificate: [32]byte{2}}}, state.Applied)
	f.apply("manager", "stop-registry", entry.Revision, RegistrySelection{spec.Tenant, spec.ID}, state.Applied)
	entry = registryEntry(t, f, spec)
	if entry.Active == nil || entry.Spec.Enabled {
		t.Fatal("stop returned writer before actual closure")
	}
	rows, _, err := f.p.RegistryPage(f.s, f.sessions["manager"], 3, spec.Tenant, "")
	if err != nil || len(rows) != 1 || rows[0].Observation != nil {
		t.Fatal("old readiness survived stop", err)
	}
	f.apply("manager", "delete-registry", entry.Revision, RegistrySelection{spec.Tenant, spec.ID}, state.ConditionFailed)
	run := *entry.Active
	gone, budget := registryClosureFixture(f, run.Reference())
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "closed", SpecRevision: run.SpecRevision, Generation: run.Generation, Gone: gone, Budget: budget}, state.Forbidden)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "drain", SpecRevision: run.SpecRevision, Generation: run.Generation}, state.Applied)
	run = *registryEntry(t, f, spec).Active
	gone, budget = registryClosureFixture(f, run.Reference())
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "closed", SpecRevision: run.SpecRevision, Generation: run.Generation, Gone: gone, Budget: budget}, state.Applied)
	entry = registryEntry(t, f, spec)
	if entry.Active != nil || entry.Closed == nil {
		t.Fatal("closure missing")
	}
	volumesView, _ := f.p.Volumes(f.s)
	volume := volumesView.entries[volumeKey(spec.Volume)]
	if len(volume.State.Consumers()) != 0 || !volume.State.RetainsData() || volume.State.Deleted() {
		t.Fatal("stop/delete removed data")
	}
	resources, _ = f.p.Resources(f.s)
	if _, exists := resources.Quotas.Reservation(spec.BudgetKey()); exists {
		t.Fatal("closed registry still holds budget")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil || f.p.Validate(f.s, f.s, state.Command{}) != nil {
		t.Fatal("original snapshot lost closure", err)
	}
	f.apply("manager", "delete-registry", entry.Revision, RegistrySelection{spec.Tenant, spec.ID}, state.Applied)
	if !registryEntry(t, f, spec).Deleted {
		t.Fatal("definition not retired")
	}
}

func TestRegistryRejectsOverBudgetUntrustedReportsAndOrphanReferenceWrites(t *testing.T) {
	f, spec := registryFixture(t)
	spec.Budget.CPU = 101
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "reserve", SpecRevision: 1, Generation: 1}, state.ConditionFailed)
	entry := registryEntry(t, f, spec)
	if entry.Active != nil || entry.Generation != 0 {
		t.Fatal("partial overbudget reservation")
	}
	v, _ := f.p.Volumes(f.s)
	if len(v.entries[volumeKey(spec.Volume)].State.Consumers()) != 0 {
		t.Fatal("budget failure retained speculative writer")
	}
	spec.Budget.CPU = 2
	f.apply("manager", "put-registry", entry.Revision, RegistryPut{spec}, state.Applied)
	entry = registryEntry(t, f, spec)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "reserve", SpecRevision: entry.Revision, Generation: 1}, state.Applied)
	run := *registryEntry(t, f, spec).Active
	gone, _ := registryClosureFixture(f, run.Reference())
	v, _ = f.p.Volumes(f.s)
	f.apply("manager", "release-volume", v.entries[volumeKey(spec.Volume)].State.Revision(), *gone, state.Invalid)
	// A signed module report from another key cannot borrow the member's owner.
	q := RegistryReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.manager.Public().(ed25519.PublicKey)), Tenant: spec.Tenant, ID: spec.ID, Action: "drain", SpecRevision: run.SpecRevision, Generation: run.Generation, Epoch: 1, RootRevision: f.s.Object(RegistriesKey).Revision, Index: f.s.Index(), At: 3}
	q.Signature = ed25519.Sign(f.manager, RegistryReportBytes(q))
	cmd, _ := q.Command()
	if f.p.AdmitModule(f.s, cmd) {
		t.Fatal("nonmember report accepted")
	}
	if _, err := f.p.RegistryWork(f.s, q.Reporter, RegistryWorkRequest{RegistrySelection: RegistrySelection{spec.Tenant, spec.ID}, At: 3}); err == nil {
		t.Fatal("other caller read registry work")
	}
}

func TestRegistryCurrentRevocationBlocksStartButNotOriginalOwnerCleanup(t *testing.T) {
	f, spec := registryFixture(t)
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	users, _ := f.p.Catalog(f.s)
	membership, _ := users.Membership(spec.Tenant, "manager")
	// This fixture's deliberately narrow session must explicitly carry the
	// management action being exercised; SystemAdmin doesn't widen a session.
	admin := f.sessions["admin"]
	admin.Scopes[0].Actions = append(admin.Scopes[0].Actions, access.ManageMembers)
	admin.Signature = ed25519.Sign(f.node, access.SessionBytes(admin))
	f.sessions["admin"] = admin
	expected := membership.Revision
	membership.Revision = 0
	membership.Enabled = false
	f.apply("admin", "set-membership", expected, membership, state.Applied)
	work, err := f.p.RegistryWork(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), RegistryWorkRequest{RegistrySelection: RegistrySelection{spec.Tenant, spec.ID}, At: 3})
	if err != nil || work.MayStart || work.Entry.Active == nil {
		t.Fatal("revocation erased original or authorized new I/O", err)
	}
	run := *work.Entry.Active
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "serving", SpecRevision: run.SpecRevision, Generation: run.Generation, Observation: &RegistryObservation{Boot: [32]byte{1}, Certificate: [32]byte{2}}}, state.Forbidden)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "drain", SpecRevision: run.SpecRevision, Generation: run.Generation}, state.Applied)
	run = registryEntry(t, f, spec).Active.Reference()
	gone, budget := registryClosureFixture(f, run)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "closed", SpecRevision: run.SpecRevision, Generation: run.Generation, Gone: gone, Budget: budget}, state.Applied)
	if registryEntry(t, f, spec).Active != nil {
		t.Fatal("revoked manager prevented native cleanup")
	}
}

func TestRegistryEndpointCASAndSpecificationOwnershipCannotBeReplaced(t *testing.T) {
	f, spec := registryFixture(t)
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.Applied)
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.ConditionFailed)
	changed := spec
	changed.Volume.Generation++
	f.apply("manager", "put-registry", 1, RegistryPut{changed}, state.Invalid)
	other := spec
	other.ID = "second"
	other.Volume.Registry = "second"
	f.apply("manager", "create-volume", 0, volumeFact(t, other.Volume, "node-a", f.node), state.Applied)
	f.apply("manager", "put-registry", 0, RegistryPut{other}, state.ConditionFailed)
	other.Address = "0.0.0.0:5444"
	other.Authority = "registry.example.test:5444"
	f.apply("manager", "put-registry", 0, RegistryPut{other}, state.Applied)
	book, _ := f.p.Registries(f.s)
	copy, _ := book.Entry(spec.Tenant, spec.ID)
	copy.Initial.Signature[0] ^= 1
	fresh, _ := book.Entry(spec.Tenant, spec.ID)
	if bytes.Equal(fresh.Initial.Signature, copy.Initial.Signature) {
		t.Fatal("registry query aliases frozen original")
	}
	// A different authorized manager's start is the new authority ceiling.
	f.apply("manager", "stop-registry", 1, RegistrySelection{spec.Tenant, spec.ID}, state.Applied)
	f.apply("admin", "start-registry", 2, RegistrySelection{spec.Tenant, spec.ID}, state.Applied)
	entry := registryEntry(t, f, spec)
	if entry.Origin.Session.User != "admin" || entry.Origin.Change.Action != "start-registry" {
		t.Fatal("restart inherited old submitter")
	}
	if entry.Definition.Change.Action != "put-registry" || entry.Definition.Session.User != "manager" {
		t.Fatal("restart discarded original definition")
	}
	forged := entry.Spec
	forged.Authority = "another.example.test:5443"
	if f.p.registryDefinition(forged, entry.Revision, entry.Definition, entry.Origin) {
		t.Fatal("snapshot definition detached from signed put")
	}
}

func TestRegistryInputRequiresExplicitEnable(t *testing.T) {
	_, spec := registryFixture(t)
	payload, _ := json.Marshal(RegistryPut{spec})
	if _, err := InputChange(changeInput("put-registry", 0, []byte(payload)), "manager"); err != nil {
		t.Fatal(err)
	}
	var fields map[string]map[string]json.RawMessage
	_ = json.Unmarshal(payload, &fields)
	delete(fields["Spec"], "Enabled")
	missing, _ := json.Marshal(fields)
	if _, err := InputChange(changeInput("put-registry", 0, missing), "manager"); err == nil {
		t.Fatal("omitted enabled became implicit stop")
	}
	for _, name := range []string{"start-registry", "stop-registry", "delete-registry"} {
		if CommandKey(name) != RegistriesKey {
			t.Fatal("wrong root", name)
		}
	}
}

func TestRegistrySpecChangeDoesNotRewriteAcceptedRunOrItsOriginalGrant(t *testing.T) {
	f, spec := registryFixture(t)
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	before := registryEntry(t, f, spec)
	changed := spec
	changed.Budget.CPU++
	f.apply("admin", "put-registry", 1, RegistryPut{changed}, state.Applied)
	after := registryEntry(t, f, spec)
	old, _ := json.Marshal(before.Active)
	still, _ := json.Marshal(after.Active)
	if !bytes.Equal(old, still) || after.Definition.Session.User != "admin" || after.Active.Origin.Session.User != "manager" {
		t.Fatal("update rewrote accepted run or original grant")
	}
	work, err := f.p.RegistryWork(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), RegistryWorkRequest{RegistrySelection: RegistrySelection{spec.Tenant, spec.ID}, At: 3})
	if err != nil || work.MayStart || work.Entry.Active == nil {
		t.Fatal("updated desired bypassed original draining run", err)
	}
}

func TestRegistryWorkCarriesCompactAcceptedReferencesWithoutOriginalUserSessions(t *testing.T) {
	f, spec := registryFixture(t)
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	work, err := f.p.RegistryWork(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), RegistryWorkRequest{RegistrySelection: RegistrySelection{spec.Tenant, spec.ID}, At: 3})
	if err != nil || work.Entry.Active == nil || work.Native == nil {
		t.Fatal("missing native/run reference", err)
	}
	entry := registryEntry(t, f, spec)
	definition, _ := entry.Active.Definition.Command()
	origin, _ := entry.Active.Origin.Command()
	if work.Entry.Active.DefinitionDigest != state.Digest(definition) || work.Entry.Active.OriginDigest != state.Digest(origin) {
		t.Fatal("work changed original accepted reference")
	}
	raw, err := json.Marshal(work)
	if err != nil || bytes.Contains(raw, []byte("session-manager")) || bytes.Contains(raw, []byte("AccountRevision")) || len(raw) > 16<<10 {
		t.Fatal("work copied user sessions instead of bounded references", err, len(raw))
	}
}

func TestRegistryRunOwnerReadsOnlyItsAuthorityCertificate(t *testing.T) {
	f, spec := registryFixture(t)
	spec.Authority = "shop.example:5443"
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	f.apply("admin", "add-domain", 0, DomainChange{"shop.example"}, state.Applied)
	v := controlCertificate(t, f, 1, fmt.Sprintf("user-%d", f.next+1))
	f.apply("admin", "put-certificate", 0, CertificatePut{v}, state.Applied)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	q := CertificateMaterialRead{Schema: 2, Cluster: f.p.Cluster, Consumer: owner, Certificate: v.Digest(), ID: v.Metadata.ID, Host: "shop.example", Registry: &RegistryCertificateSource{Tenant: spec.Tenant, ID: spec.ID, Generation: 1}, At: 3}
	if got, err := f.p.CertificateMaterial(f.s, owner, q, 3); err != nil || got.Digest() != v.Digest() {
		t.Fatal("registry run owner denied its authority certificate", err)
	}
	for name, change := range map[string]func(*CertificateMaterialRead){
		"generation": func(q *CertificateMaterialRead) { q.Registry.Generation = 2 },
		"registry":   func(q *CertificateMaterialRead) { q.Registry.ID = "other" },
		"host":       func(q *CertificateMaterialRead) { q.Host = "www.shop.example" },
		"consumer":   func(q *CertificateMaterialRead) { q.Consumer = [32]byte{9} },
		"both":       func(q *CertificateMaterialRead) { q.Source.Key = RegistriesKey },
	} {
		bad := q
		source := *q.Registry
		bad.Registry = &source
		change(&bad)
		if _, err := f.p.CertificateMaterial(f.s, owner, bad, 3); err == nil {
			t.Fatal("registry certificate read accepted", name)
		}
	}
}

func TestRegistryHostIsCanonical(t *testing.T) {
	if RegistryHost("[2001:DB8:0:0::5]:5443") != "2001:db8::5" || RegistryHost("Registry.Example:5443") != "registry.example" || RegistryHost("10.0.0.5") != "10.0.0.5" {
		t.Fatal("registry host not canonical")
	}
}
