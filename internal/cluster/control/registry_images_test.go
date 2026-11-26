// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestCurrentAppTrustDiagnosticPreservesOriginalTaskAndBinding(t *testing.T) {
	f, request, owner := registryImageTaskFixture(t)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	originalSource, found := apps.BindingSource(request.Digest)
	if !found {
		t.Fatal("original accepted binding missing")
	}
	before, _ := json.Marshal(originalSource)
	originalObject, originalApps := f.s.Object(request.Task.Key), f.s.Object(AppsKey)
	assertDiagnostic := func(untrusted bool) {
		t.Helper()
		catalog, err := f.p.Catalog(f.s)
		apps, appErr := f.p.Apps(f.s)
		rows, _, pageErr := apps.Page(catalog, "admin", "tenant", "")
		if err != nil || appErr != nil || pageErr != nil || len(rows) != 1 || rows[0].ImageSourceNoLongerTrusted != untrusted {
			t.Fatal("current trust diagnostic", rows, err, appErr, pageErr)
		}
		source, found := apps.BindingSource(request.Digest)
		after, _ := json.Marshal(source)
		if !found || !bytes.Equal(before, after) || f.s.Object(request.Task.Key) != originalObject || f.s.Object(AppsKey) != originalApps {
			t.Fatal("trust diagnostic/management replaced original execution or binding")
		}
	}
	assertDiagnostic(false)
	catalog, _ := f.p.Catalog(f.s)
	tenant, _ := catalog.Tenant("tenant")
	managedDNSChange(t, f, "withdraw-app-image-trust", "set-trust", tenant.Revision, TrustAssignment{Tenant: "tenant", Rules: []access.TrustRule{}}, state.Applied)
	assertDiagnostic(true)
	if _, err := f.p.RegistryImagePermit(f.s, owner, request); err == nil {
		t.Fatal("diagnostic substituted for current pull/create admission")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	assertDiagnostic(true)
	catalog, _ = f.p.Catalog(f.s)
	tenant, _ = catalog.Tenant("tenant")
	managedDNSChange(t, f, "explicit-app-image-trust-restore", "set-trust", tenant.Revision, TrustAssignment{Tenant: "tenant", Rules: []access.TrustRule{{Registry: "docker.io", Repository: "**"}}}, state.Applied)
	assertDiagnostic(false)
}

// Real product FSM/binding/trust; native/DNS facts are injected. Actual Engine
// auth/TLS/daemon recovery is an E5 native fixture, not claimed by these cases.
func registryImageTaskFixture(t *testing.T) (*backupCoreFixture, RegistryImageRequest, [32]byte) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	// Current trust removal is an explicit management operation, outside the
	// original fixture's deliberately minimal Deploy/Volumes scope.
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageTrust)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	task := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first")
	managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	managedDNSTaskCoreSubmit(t, f, "first", task, true, state.Applied)
	managedDNSTaskCoreProgress(t, f, "first", "bind-inputs", task, nil)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	obj := f.s.Object(task)
	ref := deployment.ObjectRef{Key: task, Revision: obj.Revision, Generation: obj.Generation}
	binding, ok := apps.Binding(ref)
	if !ok {
		t.Fatal("original binding missing")
	}
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	return f, RegistryImageRequest{AppBindingRequest: AppBindingRequest{Task: ref, Digest: binding.Digest(), At: 10}, Image: "docker.io/library/php@sha256:" + strings.Repeat("a", 64)}, owner
}

func TestRegistryImagePermitBindsOriginalTaskAndAcceptedGrant(t *testing.T) {
	f, q, owner := registryImageTaskFixture(t)
	permit, err := f.p.RegistryImagePermit(f.s, owner, q)
	if err != nil || permit.Registry != nil || permit.Subject.Task != q.Task || permit.Subject.Binding != q.Digest || permit.Subject.Node != owner || permit.Subject.Image != q.Image || permit.Index != f.s.Index() {
		t.Fatal("trusted external Task denied or changed", permit, err)
	}
	// Current accepted app authority is distinct from expiration of the login
	// session used to submit it. Never substitute a fresh session or new Task ID.
	expired := q
	expired.At = f.session.ExpiresAt + 1
	if _, err = f.p.RegistryImagePermit(f.s, owner, expired); err != nil {
		t.Fatal("accepted Task was replaced by expired login checks", err)
	}
	for name, mutate := range map[string]func(*RegistryImageRequest){
		"generation": func(q *RegistryImageRequest) { q.Task.Generation++ },
		"revision":   func(q *RegistryImageRequest) { q.Task.Revision++ },
		"binding":    func(q *RegistryImageRequest) { q.Digest[0]++ },
		"image":      func(q *RegistryImageRequest) { q.Image = "docker.io/library/php@sha256:" + strings.Repeat("b", 64) },
		"repo":       func(q *RegistryImageRequest) { q.Image = "docker.io/library/mysql@sha256:" + strings.Repeat("a", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			other := q
			mutate(&other)
			if _, err := f.p.RegistryImagePermit(f.s, owner, other); err == nil {
				t.Fatal("foreign Task/image accepted")
			}
		})
	}
	foreign := owner
	foreign[0]++
	if _, err = f.p.RegistryImagePermit(f.s, foreign, q); err == nil {
		t.Fatal("foreign member became Task owner")
	}
	catalog, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	managedDNSChange(t, f, "remove-image-trust", "set-trust", tenant.Revision, TrustAssignment{Tenant: "tenant", Rules: []access.TrustRule{}}, state.Applied)
	if _, err = f.p.RegistryImagePermit(f.s, owner, q); err == nil {
		t.Fatal("cached image bypassed current trust removal")
	}
}

func TestRegistryImagePermitCannotActivateRetiringTask(t *testing.T) {
	f, q, owner := registryImageTaskFixture(t)
	apps, _ := f.p.Apps(f.s)
	inventory, _ := apps.Inventory("tenant", "first")
	managedDNSChange(t, f, "registry-stop-original", "down-app", inventory.Revision(), AppDown{Tenant: "tenant", App: "first", Operation: "stop-first"}, state.Applied)
	if _, err := f.p.RegistryImagePermit(f.s, owner, q); err == nil {
		t.Fatal("retirement opened new pull credentials")
	}
	// The original operation remains represented; rejecting new work isn't a
	// command to clear the binding, native lease or original retirement receipts.
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	source, ok := apps.BindingSource(q.Digest)
	if !ok || source.Task != q.Task {
		raw, _ := json.Marshal(source)
		t.Fatal("original references were erased", string(raw))
	}
}

func TestRegistryImagePermitManagedAuthorityNeverFallsBackToAnonymous(t *testing.T) {
	f, q, owner := registryImageTaskFixture(t)
	// This pure-core fixture assigns a managed server to the already trusted
	// source name. It does not contact Docker Hub or claim TLS hostname ownership.
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageRegistry)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	scope := volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", ID: "registry-data", Generation: 1, Registry: "private"}
	f.apply("create-registry-data", "create-volume", 0, volumeFact(t, scope, "node-a", f.node), state.Applied)
	spec := registry.Specification{Schema: 1, Tenant: "tenant", ID: "private", Node: "node-a", Address: "0.0.0.0:443", Authority: "docker.io", Volume: scope, Enabled: true, Metadata: registry.MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}, Blobs: registry.BlobLimits{BlobBytes: 1 << 20, TotalBytes: 8 << 20, Records: 64}, Budget: workload.Resources{CPU: 1, Memory: 16 << 20}, MaxRequests: 1, MaxHeaderBytes: 8192, RequestTimeoutMS: 30000, TokenSeconds: 60}
	f.apply("put-registry", "put-registry", 0, RegistryPut{Spec: spec}, state.Applied)
	if _, err := f.p.RegistryImagePermit(f.s, owner, q); err == nil {
		t.Fatal("desired-only registry became anonymous public source")
	}
	report := func(action string, rev uint64, observation *RegistryObservation) {
		t.Helper()
		request := RegistryReport{Schema: 1, Cluster: f.p.Cluster, Reporter: owner, Tenant: "tenant", ID: "private", Action: action, Generation: 1, SpecRevision: rev, Observation: observation, At: 3, Index: f.s.Index(), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(RegistriesKey).Revision}
		request.Signature = ed25519.Sign(f.node, RegistryReportBytes(request))
		cmd, err := request.Command()
		if err != nil {
			t.Fatal(err)
		}
		next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal(action, result.Code, err)
		}
		f.s = next
	}
	book, _ := f.p.Registries(f.s)
	entry, _ := book.Entry("tenant", "private")
	report("reserve", entry.Revision, nil)
	if _, err := f.p.RegistryImagePermit(f.s, owner, q); err == nil {
		t.Fatal("reserved writer invented serving")
	}
	report("serving", entry.Revision, &RegistryObservation{Boot: [32]byte{1}, Certificate: [32]byte{2}, At: 3})
	permit, err := f.p.RegistryImagePermit(f.s, owner, q)
	if err != nil || permit.Registry == nil || *permit.Registry != spec {
		t.Fatal("current managed run not selected", permit, err)
	}
	book, _ = f.p.Registries(f.s)
	entry, _ = book.Entry("tenant", "private")
	f.apply("stop-registry", "stop-registry", entry.Revision, RegistrySelection{Tenant: "tenant", ID: "private"}, state.Applied)
	if _, err = f.p.RegistryImagePermit(f.s, owner, q); err == nil {
		t.Fatal("stopped managed authority fell back to anonymous")
	}
	book, _ = f.p.Registries(f.s)
	entry, _ = book.Entry("tenant", "private")
	if entry.Active == nil || entry.Active.Consumer.Owner.Key != owner {
		t.Fatal("denial lost original writer ref")
	}
}
