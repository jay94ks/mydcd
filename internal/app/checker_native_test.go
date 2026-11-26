// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/schema"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
	"github.com/jay94ks/mydcd/tests/registryfixture"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

func TestL1ManagedAppInterpretedCheckersCLIAndRestart(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppChecker, true, false, false)
}

func TestL1ManagedAppCompiledAndInterpretedCheckersCLIAndRestart(t *testing.T) {
	// Image preparation is explicit at L1's final validation, never hidden
	// downloads/builds in a native test or ordinary daemon startup.
	if os.Getenv("MYDC_LIFECYCLE_COMPILER_IMAGE") == "" && os.Getenv("MYDC_LIFECYCLE_COMPILER_CACHE") == "" {
		t.Skip("requires explicitly prepared pinned local compiler image")
	}
	runManagedAppOwner(t, true, true, true, true, managedAppCompiledChecker, true, false, false)
}

const managedCheckerEndpointSource = `package checker
import (
 "context"
 lifecycle "github.com/jay94ks/mydcd/lifecycle/v1"
)
func Check(ctx context.Context,in lifecycle.Request,probe lifecycle.Probe)(lifecycle.Result,error){
 r,err:=probe.Healthz(ctx,lifecycle.HTTPProbe{Service:"web",Port:8080,Path:"/readyz",Method:"GET",ExpectedStatus:[]int{200},MaxBytes:4096})
 if err!=nil{return lifecycle.Result{Schema:1,Status:"unknown",Reason:"probe-error"},err}
 if !r.Match{return lifecycle.Result{Schema:1,Status:"fail",Reason:"endpoint-not-ready"},nil}
 return lifecycle.Result{Schema:1,Status:"pass",Reason:"endpoint-ready"},nil
}
`

func prepareManagedCompilerImage(t *testing.T, ctx context.Context, builder *Runtime, public map[string]any, save func()) string {
	t.Helper()
	if ref := os.Getenv("MYDC_LIFECYCLE_COMPILER_IMAGE"); ref != "" {
		return ref // explicitly pre-provisioned image remains outside fixture cleanup
	}
	cache := os.Getenv("MYDC_LIFECYCLE_COMPILER_CACHE")
	prepared := registryfixture.OpenCompilerCached(t, "127.0.0.1:0", cache)
	ref := prepared.References["lifecycle-compiler"]
	if _, err := builder.docker.Image(ctx, ref, false); !cerrdefs.IsNotFound(err) {
		t.Fatal("new fixture compiler reference required", err)
	}
	public["CompilerImage"] = ref
	public["CompilerCache"] = cache
	public["TemporaryCompilerConfig"] = prepared.Configs[ref]
	public["TemporaryCompilerManifest"] = strings.Split(ref, "@")[1]
	save() // original exact reference/config recorded BEFORE the explicit pull
	got, err := builder.docker.Image(ctx, ref, true)
	// Classic image storage reports config ID; containerd image storage may
	// report manifest ID. Both must still resolve the exact prepared RepoDigest.
	if err != nil || !slices.Contains(got.RepoDigests, ref) || (got.ID != prepared.Configs[ref] && got.ID != public["TemporaryCompilerManifest"]) {
		t.Fatal("explicit fixture compiler import", err)
	}
	return ref
}

func cleanupManagedCompilerImage(t *testing.T, ctx context.Context, c *engine.Client, public map[string]any) {
	t.Helper()
	want, _ := public["TemporaryCompilerConfig"].(string)
	if want == "" {
		return
	}
	ref, _ := public["CompilerImage"].(string)
	got, err := c.API.ImageInspect(ctx, ref)
	if cerrdefs.IsNotFound(err) {
		return
	}
	if err != nil || !slices.Contains(got.RepoDigests, ref) || (got.ID != want && got.ID != public["TemporaryCompilerManifest"]) {
		t.Error("original compiler image cleanup ownership", err)
		return
	}
	// Remove only the imported named reference, with Engine conflict checks;
	// never force removal underneath an unresolved compiler or other consumer.
	if _, err = c.API.ImageRemove(ctx, ref, client.ImageRemoveOptions{}); err != nil {
		t.Error("original compiler image cleanup", err)
	}
}

func prepareManagedCheckerApp(t *testing.T, ctx context.Context, r *Runtime, root string, document []byte, compiled bool, compilerImage string, change func(string, string, uint64, any), builders ...*Runtime) []byte {
	t.Helper()
	input, err := deployment.ParseApp(document)
	if err != nil {
		t.Fatal(err)
	}
	policy := checker.TenantPolicy{Tenant: "tenant", Enabled: true, Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 64 << 20, MaxPIDs: 32, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"connect", "dependency", "exec", "file", "healthz"}}, Resolver: checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/mydcd/lifecycle/v1"}, SourceCacheBytes: 1 << 20}}
	if compiled {
		image, err := access.PinImage(compilerImage)
		if err != nil {
			t.Fatal("pinned compiler image required", err)
		}
		// Native compiler deliberately uses local-only Image(...,false).
		// Inspect without pulling BEFORE accepting any compiler policy/job.
		builder := r
		if len(builders) > 0 {
			builder = builders[0]
		}
		if _, err = builder.docker.Image(ctx, image.Reference, false); err != nil {
			t.Fatal("explicit compiler image not present", err)
		}
		users, err := r.controlPolicy.Catalog(mustCheckerView(t, ctx, r).State)
		if err != nil {
			t.Fatal(err)
		}
		tenant, _ := users.Tenant("tenant")
		rules := slices.Clone(tenant.ImageSources)
		if !slices.ContainsFunc(rules, func(rule access.TrustRule) bool {
			return rule.Registry == image.Registry && rule.Repository == image.Repository
		}) {
			rules = append(rules, access.TrustRule{Registry: image.Registry, Repository: image.Repository})
			change("checker-compiler-trust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant", Rules: rules})
		}
		policy.Build = checker.BuildPolicy{Nodes: []string{builder.installation.record.Root.Self.ID}, Image: image.Reference, Toolchain: runtime.Version(), Targets: []string{runtime.GOOS + "/" + runtime.GOARCH}, MaxJobs: 1, NanoCPU: 1000000000, MemoryBytes: 512 << 20, WorkspaceBytes: 512 << 20, ArtifactBytes: 64 << 20, TimeoutMS: 180000}
		policy.CompiledCacheBytes = 128 << 20
	}
	change("checker-native-policy", "set-lifecycle-policy", 0, policy)
	want := sha256.Sum256([]byte("volume-original"))
	fileSource := fmt.Sprintf(`package checker
import (
 "context"
 lifecycle "github.com/jay94ks/mydcd/lifecycle/v1"
)
func Check(ctx context.Context,in lifecycle.Request,probe lifecycle.Probe)(lifecycle.Result,error){
 r,err:=probe.File(ctx,lifecycle.FileProbe{Service:"web",Path:"/data/marker",Kind:"regular",ContentDigest:"%x",MaxBytes:4096})
 if err!=nil{return lifecycle.Result{Schema:1,Status:"unknown",Reason:"file-error"},err}
 if !r.Exists||!r.Match{return lifecycle.Result{Schema:1,Status:"fail",Reason:"file-not-ready"},nil}
 return lifecycle.Result{Schema:1,Status:"pass",Reason:"file-ready"},nil
}
`, want)
	if err = os.WriteFile(filepath.Join(root, "checker-native-file.go"), []byte(fileSource), 0600); err != nil {
		t.Fatal(err)
	}
	interpreted := false
	input.MyDC.Lifecycle = &deployment.LifecycleDeclaration{Scripts: map[string]checker.Script{
		"endpoint": {Source: managedCheckerEndpointSource, Compile: &compiled, Modules: []checker.ModulePin{}},
		"marker":   {Ref: &checker.NamedReference{Name: "native-file", Revision: 1}, Compile: &interpreted},
	}, Checks: []deployment.LifecycleCheck{{ID: "app-ready", Phase: contract.Readiness, Interval: "1s", Timeout: "3s", LifecycleTemplate: deployment.LifecycleTemplate{Builtin: "depends_on", Parameters: deployment.LifecycleParameters(`{"services":["web"],"condition":"service_healthy"}`)}}}}
	retries := uint32(1)
	service := input.Services["web"]
	service.MyDC.Lifecycle = &deployment.ServiceLifecycle{Checks: []deployment.LifecycleCheck{
		{ID: "marker", Phase: contract.Readiness, Interval: "1s", Timeout: "3s", LifecycleTemplate: deployment.LifecycleTemplate{Script: "marker"}},
		{ID: "alive", Phase: contract.Liveness, Interval: "1s", Timeout: "3s", Retries: &retries, LifecycleTemplate: deployment.LifecycleTemplate{Script: "endpoint"}, Actions: &checker.ActionPolicy{OnDead: checker.RestartContainer}},
		{ID: "shutdown", Phase: contract.Shutdown, Interval: "1s", Timeout: "3s", LifecycleTemplate: deployment.LifecycleTemplate{Script: "marker"}},
	}}
	input.Services["web"] = service
	encoded, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustCheckerView(t *testing.T, ctx context.Context, r *Runtime) cluster.View {
	t.Helper()
	v, err := r.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Called after the SAME real CLI's login and before its compose up. Sources
// are real CLI staging/registration; fixtures do not invent signed SourceFacts.
func prepareManagedCheckerCLI(t *testing.T, root string, document []byte, call func(int, ...string) []byte) {
	t.Helper()
	input, err := deployment.ParseApp(document)
	if err != nil {
		t.Fatal(err)
	}
	program, _, err := input.LifecycleProgram()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]uint64{}
	for _, script := range program.Scripts {
		if script.Ref != nil {
			names[script.Ref.Name] = script.Ref.Revision
		}
	}
	ordered := make([]string, 0, len(names))
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	for _, name := range ordered {
		call(0, "lifecycle", "script", "put", name, "--tenant", input.MyDC.Tenant, "--file", filepath.Join(root, "checker-"+name+".go"), "--expected-revision", "0", "--request-id", "native-"+name)
		call(0, "lifecycle", "script", "show", name, "--tenant", input.MyDC.Tenant, "--revision", fmt.Sprint(names[name]))
	}
}

func verifyManagedCheckerApp(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View, wait func(string, func() bool), compiled, exerciseRestart bool, builders ...*Runtime) {
	t.Helper()
	task := deployment.ResourceKey("task", "tenant", "app", "web")
	var first deployment.Observation
	wait("actual app/checker healthy", func() bool {
		apps, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		execution, _ := apps.Execution("tenant", "app")
		stage, _ := execution.Stage(task)
		if stage.Observation == nil || !stage.Observation.Healthy || stage.Observation.AppChecks == nil || stage.Observation.AppChecks.Status != contract.Pass {
			return false
		}
		first = *stage.Observation
		return true
	})
	if first.StartedAt <= 0 {
		t.Fatal("checker has no actual native start witness")
	}
	book, err := p.Lifecycles(read().State)
	if err != nil {
		t.Fatal(err)
	}
	if compiled && len(book.BuildJobs()) != 1 || !compiled && len(book.BuildJobs()) != 0 {
		t.Fatal("cache-miss job count", len(book.BuildJobs()))
	}
	for _, job := range book.BuildJobs() {
		if job.Phase != "closed" {
			t.Fatal("healthy app before compiler closure", job.Phase)
		}
		builder := r
		if len(builders) > 0 {
			builder = builders[0]
		}
		preparation, err := builder.checkerCompiler.Preparation(job.Intent.Tenant, job.Intent.ID)
		if err != nil || !preparation.Closed {
			t.Fatal("compiler did not return to idle", err)
		}
	}
	if !exerciseRestart {
		// The single-owner Yaegi/compiled runs already exercise this exact
		// local policy restart. Keep the two-owner budget for remote probes,
		// original closure, DB recovery and both owners' cache reclamation.
		return
	}
	// The backend exposes a fixture-only readiness toggle. Docker is still
	// Running while the script returns fail, so the app policy must Stop/Start.
	target, err := r.workload.ProbeTarget(ctx, task, first.Generation, first.Revision)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target.IPv4.String()+":8080/readiness-state?ready=0", nil)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	defer httpClient.CloseIdleConnections()
	response, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, drainErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusNoContent || drainErr != nil || closeErr != nil {
		t.Fatal("fixture toggle failed", drainErr, closeErr)
	}
	wait("same Task/native policy restart and app recovery", func() bool {
		apps, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		execution, _ := apps.Execution("tenant", "app")
		stage, _ := execution.Stage(task)
		o := stage.Observation
		if o == nil || o.Restart == nil || o.StartedAt <= first.StartedAt || !o.Healthy || o.AppChecks == nil || o.AppChecks.Status != contract.Pass {
			return false
		}
		if o.Native != first.Native || o.Generation != first.Generation || o.Revision != first.Revision || o.Restart.Control.Phase != checker.ControlCompleted {
			t.Fatal("restart replaced original Task/native")
		}
		return true
	})
	if after, err := p.Lifecycles(read().State); err != nil || len(after.BuildJobs()) != len(book.BuildJobs()) {
		t.Fatal("ordinary probes/restart created compiler job", err)
	}
}

func verifyManagedCheckerRetirement(t *testing.T, r *Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), publicReads func(bool, bool), peers ...*Runtime) {
	t.Helper()
	rows, err := r.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 4 {
		t.Fatal("missing service/app checker observations")
	}
	for _, raw := range rows {
		point, err := schema.Decode[checkerObservation](raw)
		if err != nil || point.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil || point.Checkpoint.Active != nil || !point.Checkpoint.Retire || !point.remoteCallsClosed() {
			t.Fatal("retired Task lost checker closure", err)
		}
	}
	book, err := p.Lifecycles(read().State)
	if err != nil {
		t.Fatal(err)
	}
	if !book.Quiescent() {
		t.Fatal("retirement retained script/build consumers")
	}
	// The source/cache remain tenant-owned; app down does not delete them.
	if script, ok := book.Script("tenant", "native-file"); !ok || len(script.Versions) != 1 || script.Versions[0].Revision != 1 || script.Versions[0].Deleted {
		t.Fatal("app down deleted tenant named script")
	}
	// Deleting the tenant registration is a separate explicit management action.
	// The periodic owner collector must then delete actual blob values while
	// keeping original build/collection/observation metadata for recovery.
	selection := control.LifecycleScriptSelection{Tenant: "tenant", Name: "native-file", Revision: 1}
	if publicReads != nil {
		publicReads(false, false) // original down returned all actual app uses
	}
	change("native-file-retire", "retire-lifecycle-script", 1, selection)
	if publicReads != nil {
		publicReads(true, false)
	}
	change("native-file-delete", "delete-lifecycle-script", 2, selection)
	if publicReads != nil {
		publicReads(true, true)
	}
	wait("automatic source and compiled byte reclamation", func() bool {
		for _, node := range append([]*Runtime{r}, peers...) {
			for _, prefix := range []string{"checker/source/data/", "checker/source/modules/data/", "checker/source/compiled/data/"} {
				sizes, err := node.reports.SizesBounded(prefix, 4096, 4096*256)
				if err != nil {
					t.Fatal(err)
				}
				if len(sizes) != 0 {
					return false
				}
			}
		}
		return true
	})
	closed, err := p.Lifecycles(read().State)
	if err != nil || len(closed.BuildJobs()) != len(book.BuildJobs()) {
		t.Fatal("GC erased original build metadata", err)
	}
	for _, job := range closed.BuildJobs() {
		if job.Phase != "closed" {
			t.Fatal("GC before original compiler closure")
		}
		var builder *Runtime
		for _, node := range append([]*Runtime{r}, peers...) {
			if node.Identity.Public == job.Intent.Owner {
				builder = node
			}
		}
		if builder == nil {
			t.Fatal("original builder missing")
		}
		if _, err := builder.checkerSources.CompiledCollection(context.Background(), job.Intent.Tenant, job.Intent.Digest()); err != nil {
			t.Fatal("GC invalidated signed build evidence", err)
		}
	}

}
