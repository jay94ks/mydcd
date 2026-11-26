// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// This extends the existing accepted-app/FSM fixture. Source staging and the
// never-dispatched closure are signed model inputs, not compiler/native proof.
// The product Binding, Catalog, reports and public read path are reused.
func TestPublicLifecycleUsesJoinOriginalBuildParentAndReturnOnlyClosedJob(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	policy := checkerPolicy()
	policy.Build = checker.BuildPolicy{Nodes: []string{"node-a"}, Targets: []string{"linux/amd64"}, Image: "docker.io/library/golang@sha256:" + strings.Repeat("a", 64), Toolchain: "go1.27.3", MaxJobs: 1, NanoCPU: 100000000, MemoryBytes: 64 << 20, WorkspaceBytes: 64 << 20, ArtifactBytes: 32 << 20, TimeoutMS: 10000}
	policy.CompiledCacheBytes = 64 << 20
	f.apply("public-checker-policy", "set-lifecycle-policy", 0, policy, state.Applied)
	source := []byte("package checker\n")
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	fact := checker.SourceFact{Schema: 1, Cluster: f.p.Cluster, Owner: owner, Tenant: "tenant", SDK: 1, Digest: sha256.Sum256(source), Length: uint64(len(source))}
	fact.Signature = ed25519.Sign(f.node, checker.SourceFactBytes(fact))
	f.apply("public-checker-source", "put-lifecycle-script", 0, LifecycleScriptPut{Tenant: "tenant", Name: "ready", Source: fact}, state.Applied)
	compiled := true
	ref := checker.NamedReference{Name: "ready", Revision: 1}
	task := managedDNSTaskCoreBegin(t, f, "checker-app", "10.80.1.41", "checker-app", func(input *deployment.Compose, _ *deployment.PlanningContext) {
		input.MyDC.Lifecycle = &deployment.LifecycleDeclaration{Scripts: map[string]checker.Script{"ready": {Ref: &ref, Compile: &compiled}}}
		service := input.Services["web"]
		service.MyDC.Lifecycle = &deployment.ServiceLifecycle{Checks: []deployment.LifecycleCheck{{ID: "ready", Phase: contract.Readiness, Interval: "1s", Timeout: "3s", LifecycleTemplate: deployment.LifecycleTemplate{Script: "ready"}}}}
		input.Services["web"] = service
	})
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	execution, _ := apps.Execution("tenant", "checker-app")
	for _, step := range execution.Steps() {
		managedDNSTaskCoreSubmit(t, f, "checker-app", step.Key, step.Kind != "task", state.Applied)
		if step.Kind == "task" {
			managedDNSTaskCoreProgress(t, f, "checker-app", "collect", step.Key, nil)
		}
	}
	managedDNSTaskCoreProgress(t, f, "checker-app", "bind-inputs", task, nil)
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	object := f.s.Object(task)
	binding, ok := apps.Binding(deployment.ObjectRef{Key: task, Generation: object.Generation, Revision: object.Revision})
	parent, bound := CheckerBindingUse(binding)
	book, err := f.p.Lifecycles(f.s)
	if !ok || !bound || err != nil {
		t.Fatal("missing original accepted checker Binding", ok, bound, err)
	}
	accepted, ok := book.Use("tenant", parent.ID)
	if !ok || accepted.Digest() != parent.Digest() || parent.Parent != binding.Digest() {
		t.Fatal("catalog pin is not the actual accepted app parent")
	}
	id := sha256.Sum256([]byte("public-original-build"))
	intent := checker.BuildIntent{Schema: 1, Cluster: f.p.Cluster, Tenant: "tenant", ID: hex.EncodeToString(id[:]), AppUseID: parent.ID, AppUse: parent.Digest(), Node: "node-a", Owner: owner, Selection: parent.Selection(), Inputs: []checker.BuildInput{{Content: fact.ContentDigest(), Recipe: [32]byte{2}}}, Manifest: [32]byte{3}, Target: "linux/amd64", DeadlineUnixMilli: 19000}
	report := func(action string, expected uint64, closure *checker.BuildClosure) {
		t.Helper()
		r := CheckerBuildReport{Schema: 1, Cluster: f.p.Cluster, Reporter: owner, Tenant: "tenant", ID: intent.ID, Action: action, Expected: expected, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(LifecycleKey).Revision, Index: f.s.Index(), At: 10, Closure: closure}
		if action == "reserve" {
			r.Intent = &intent
		}
		r.Signature = ed25519.Sign(f.node, CheckerBuildReportBytes(r))
		raw, _ := json.Marshal(r)
		cmd, err := f.p.ResolveCheckerBuildReport(f.s, owner, raw)
		if err != nil {
			t.Fatal(err)
		}
		var result state.Result
		f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal("original member build report", action, result, err)
		}
	}
	readUses := func(wantBuild bool) PublicReadPage {
		t.Helper()
		before, _ := state.Encode(f.s)
		page, err := f.p.PublicRead(f.s, f.session, 10, "lifecycle-uses", "tenant", PublicReadQuery{Name: ref.Name}, "")
		want := 1
		if wantBuild {
			want++
		}
		if err != nil || page.Total != want || len(page.Rows) != want || page.Next != "" {
			t.Fatal("public original script users", page, err)
		}
		current, err := f.p.Lifecycles(f.s)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, row := range page.Rows {
			use := row.Lifecycle
			if use == nil || use.Revision != ref.Revision || use.App != "checker-app" || use.Service != "web" || use.Node != "node-a" || use.Standalone != "" {
				t.Fatal("public use lost actual original app/Task join", row)
			}
			original, ok := current.Use("tenant", use.ID)
			if !ok || original.Kind != use.Kind || original.Node != use.Node || !original.Selection().Equal(parent.Selection()) {
				t.Fatal("public row is not the deletion fence's exact Catalog.Uses entry", row)
			}
			if use.Kind == "app-binding" && use.ID != parent.ID || use.Kind == "build-job" && use.ID != intent.ID {
				t.Fatal("public row replaced original parent/job ID", row)
			}
			seen[use.Kind] = true
		}
		if !seen["app-binding"] || seen["build-job"] != wantBuild {
			t.Fatal("closed historical build was treated as active", seen)
		}
		after, _ := state.Encode(f.s)
		if !bytes.Equal(before, after) {
			t.Fatal("public use read mutated original Catalog/operation")
		}
		return page
	}
	readUses(false)
	report("reserve", 0, nil)
	active := readUses(true)
	active.Rows[0].Lifecycle.ID = "mutated-public-copy"
	readUses(true)
	book, _ = f.p.Lifecycles(f.s)
	job, ok := book.BuildJob("tenant", intent.ID)
	if !ok || job.Phase != "reserved" || job.Intent.AppUseID != parent.ID || job.Intent.AppUse != parent.Digest() {
		t.Fatal("public build is not an active registered original job", job)
	}
	if _, err = book.Release(parent); !errors.Is(err, checker.ErrPending) {
		t.Fatal("active original build did not fence app parent release", err)
	}
	selection := LifecycleScriptSelection{Tenant: "tenant", Name: ref.Name, Revision: ref.Revision}
	f.apply("public-ready-retire", "retire-lifecycle-script", 1, selection, state.Applied)
	f.apply("public-ready-delete-live", "delete-lifecycle-script", 2, selection, state.ConditionFailed)
	readUses(true)
	closure := checker.BuildClosure{Schema: 1, Cluster: f.p.Cluster, Job: intent.Digest(), Owner: owner, Journal: [32]byte{4}, Disposition: "never-dispatched"}
	closure.Signature = ed25519.Sign(f.node, checker.BuildClosureBytes(closure))
	report("close", 1, &closure)
	readUses(false)
	book, _ = f.p.Lifecycles(f.s)
	job, ok = book.BuildJob("tenant", intent.ID)
	if !ok || job.Phase != "closed" || job.Closure == nil || job.Intent.Digest() != intent.Digest() || !bytes.Equal(job.Closure.Signature, closure.Signature) {
		t.Fatal("closing public build erased retained original evidence", job)
	}
	// The still-live app parent continues to fence deletion after the build
	// row is returned. Actual app down/empty/delete is covered by the reused
	// interpreted/compiled native fixture rather than a forged app closure.
	f.apply("public-ready-delete-parent-live", "delete-lifecycle-script", 2, selection, state.ConditionFailed)
	readOnly := f.session
	readOnly.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	readOnly.Signature = ed25519.Sign(f.node, access.SessionBytes(readOnly))
	if _, err = f.p.PublicRead(f.s, readOnly, 10, "lifecycle-uses", "tenant", PublicReadQuery{Name: ref.Name}, ""); !errors.Is(err, access.ErrDenied) {
		t.Fatal("read-only session received script-use management metadata", err)
	}
}
