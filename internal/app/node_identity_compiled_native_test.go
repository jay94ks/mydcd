// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
	"github.com/moby/moby/client"
)

// Uses the existing private Engine/Vault/CLI/rollback fixture and its finite
// compiler job. The explicit prepared cache is served by the existing owned
// local registry; this root does not fetch or build a compiler image itself.
// This covers a CLOSED job across rotation, not an unknown Create/Wait during
// rotation. Original unknown-job recovery remains separate SDK/core evidence.
func TestRealBoundaryInstalledIdentityReusesClosedCompilerJobAndArtifact(t *testing.T) {
	if os.Getenv("MYDC_LIFECYCLE_COMPILER_CACHE") == "" {
		t.Skip("requires explicitly prepared MYDC_LIFECYCLE_COMPILER_CACHE")
	}
	if os.Getenv("MYDC_LIFECYCLE_COMPILER_IMAGE") != "" {
		t.Fatal("select the prepared compiler cache without an image override")
	}
	runManagedAppOwner(t, true, true, true, true, managedAppIdentityCompiled, true, true, true)
}

type identityCompiledProof struct {
	originalCheckKey string
	originalCheck    checkerObservation
	job              checker.BuildJob
	preparation      checker.CompilerPreparation
	collection       checker.CompiledCollection
	fact             checker.CompiledFact
}

func captureIdentityCompiledProof(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View) *identityCompiledProof {
	t.Helper()
	book, err := p.Lifecycles(read().State)
	if err != nil || len(book.BuildJobs()) != 1 {
		t.Fatal("identity compiled fixture requires one original compiler job", err)
	}
	job := book.BuildJobs()[0]
	if job.Phase != "closed" || job.Intent.Owner != r.Identity.Public || job.Closure == nil || job.Closure.Verify(job.Intent, "dispatched") != nil || job.Closure.Disposition != "removed" || len(job.Intent.Inputs) != 1 {
		t.Fatal("original compiler job has no exact removed native closure")
	}
	preparation, err := r.checkerCompiler.Preparation(job.Intent.Tenant, job.Intent.ID)
	if err != nil || !preparation.Closed || !preparation.NativeDispatched || preparation.Intent.Digest() != job.Intent.Digest() {
		t.Fatal("original compiler job was not durably closed", err)
	}
	collection, err := r.checkerSources.CompiledCollection(ctx, job.Intent.Tenant, job.Intent.Digest())
	if err != nil || collection.Verify() != nil || collection.Outcome != "complete" || collection.Owner != r.Identity.Public || collection.Job != job.Intent.Digest() || len(collection.Items) != 1 {
		t.Fatal("original signed compiler collection", err)
	}
	fact, data, err := r.checkerSources.CompiledArtifact(ctx, job.Intent.Tenant, job.Intent.Inputs[0].Recipe)
	defer clear(data)
	if err != nil || fact.Verify() != nil || fact.Owner != r.Identity.Public || fact.Build.Job != job.Intent.Digest() || fact.Build.Recipe.Source != job.Intent.Inputs[0].Content || fact.Build.Recipe.Key() != job.Intent.Inputs[0].Recipe || book.CompiledOrigin(fact.Build) != nil || sha256.Sum256(data) != fact.Build.Digest || uint64(len(data)) != fact.Build.Length || collection.Items[0].Cached != fact.Digest() {
		t.Fatal("original exact compiled bytes and signed provenance", err)
	}
	proof := &identityCompiledProof{job: job.Clone(), preparation: preparation, collection: collection.Clone(), fact: fact.Clone()}
	proof.originalCheckKey = checkerObservationPrefix + "tenant/app/service/web/alive/liveness"
	pointRaw, err := r.reports.GetBounded(proof.originalCheckKey, maxCheckerObservationBytes)
	point, decodeErr := schema.Decode[checkerObservation](pointRaw)
	if err != nil || decodeErr != nil || point.validate(p.Cluster, r.Identity.Public) != nil || point.Checkpoint.Last == nil || point.Checkpoint.Last.Result.Status != contract.Pass || point.Diagnostic == nil || point.Diagnostic.Phase != "compiled-run" {
		t.Fatal("original compiled checker has no exact successful native run", err, decodeErr)
	}
	proof.originalCheck = point
	proof.assertCompilerAbsent(t, ctx, r)
	return proof
}

func (proof *identityCompiledProof) assertCompilerAbsent(t *testing.T, ctx context.Context, r *Runtime) {
	t.Helper()
	if _, err := r.docker.API.ContainerInspect(ctx, proof.job.Closure.Native, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("original finite compiler native container remains or is unknown", err)
	}
}

func (proof *identityCompiledProof) verifyRetained(t *testing.T, ctx context.Context, current, original *Runtime, p control.Policy, read func() cluster.View) {
	t.Helper()
	book, err := p.Lifecycles(read().State)
	if err != nil || !reflect.DeepEqual(book.BuildJobs(), []checker.BuildJob{proof.job}) {
		t.Fatal("identity switch replaced or reran original shared compiler job", err)
	}
	preparation, err := original.checkerCompiler.Preparation(proof.job.Intent.Tenant, proof.job.Intent.ID)
	if err != nil || !reflect.DeepEqual(preparation, proof.preparation) {
		t.Fatal("same-DB original compiler journal changed", err)
	}
	collection, err := original.checkerSources.CompiledCollection(ctx, proof.job.Intent.Tenant, proof.job.Intent.Digest())
	if err != nil || collection.Digest() != proof.collection.Digest() {
		t.Fatal("original compiler collection receipt changed", err)
	}
	fact, data, err := original.checkerSources.CompiledArtifact(ctx, proof.job.Intent.Tenant, proof.fact.Build.Recipe.Key())
	defer clear(data)
	if err != nil || fact.Digest() != proof.fact.Digest() || sha256.Sum256(data) != proof.fact.Build.Digest || uint64(len(data)) != proof.fact.Build.Length {
		t.Fatal("historical namespace lost exact original compiled cache", err)
	}
	if _, err := current.checkerCompiler.Preparation(proof.job.Intent.Tenant, proof.job.Intent.ID); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("current owner recreated or adopted original compiler journal", err)
	}
	for _, owner := range []*Runtime{original, current} {
		pending, err := owner.checkerCompiler.Pending()
		if err != nil || len(pending) != 0 {
			t.Fatal("compiler did not remain idle across installed identity switch", err)
		}
	}
	proof.assertCompilerAbsent(t, ctx, current)
}

func (proof *identityCompiledProof) verifyCurrentTask(t *testing.T, ctx context.Context, current, original *Runtime, binding deployment.Binding, p control.Policy, read func() cluster.View, wait func(string, func() bool)) {
	t.Helper()
	use, ok := control.CheckerBindingUse(binding)
	if !ok || use.Owner != current.Identity.Public {
		t.Fatal("current compiled Task has no exact lifecycle use")
	}
	taskKey := deployment.ResourceKey("task", "tenant", "app", "web")
	apps, err := p.Apps(read().State)
	execution, _ := apps.Execution("tenant", "app")
	stage, stageOK := execution.Stage(taskKey)
	if err != nil || !stageOK {
		t.Fatal("current compiled Task stage", err)
	}
	task := deployment.ObjectRef{Key: taskKey, Revision: stage.Result.Revision, Generation: stage.Result.Generation}
	program, err := current.checkerTaskProgram(read(), binding, task)
	if err != nil || program == nil || !program.Scripts["identity-original"].Compile || program.Sources["identity-original"].ContentDigest() != proof.fact.Build.Recipe.Source {
		t.Fatal("current Task changed original compiled source or execution mode", err)
	}
	preparation, err := current.checkerSources.TaskPreparation(ctx, use.Tenant, checker.TaskCompileID(p.Cluster, use.Digest()), false)
	if err != nil || preparation.Validate() != nil || preparation.Owner != current.Identity.Public || preparation.Use != use.Digest() || preparation.Program != checkerProgramHash(*program) || preparation.Plan == nil || preparation.Plan.Build != nil || len(preparation.Plan.Recipes) != 1 || preparation.Plan.Recipes[0].Key() != proof.fact.Build.Recipe.Key() || preparation.Plan.ValidateProgram(*program) != nil {
		t.Fatal("new current Task did not seal cache-only original compiled recipe", err)
	}
	fact, data, err := current.checkerSources.CompiledArtifact(ctx, use.Tenant, proof.fact.Build.Recipe.Key())
	defer clear(data)
	if err != nil || fact.Verify() != nil || fact.Owner != current.Identity.Public || !reflect.DeepEqual(fact.Build, proof.fact.Build) || sha256.Sum256(data) != proof.fact.Build.Digest || uint64(len(data)) != proof.fact.Build.Length {
		t.Fatal("current cache rewrote original builder/job/signature or bytes", err)
	}
	wait("current Task actually executes the retained compiled artifact", func() bool {
		rows, err := current.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range rows {
			point, err := schema.Decode[checkerObservation](raw)
			if err != nil || point.validate(p.Cluster, current.Identity.Public) != nil {
				t.Fatal("current checker observation invalid", err)
			}
			if point.Task == task && point.Program == program.Program && point.Checkpoint.Definition.Request.Checker == "identity-retained-source" && point.Checkpoint.Last != nil && point.Checkpoint.Last.Result.Status == contract.Pass && point.Diagnostic != nil && point.Diagnostic.Phase == "compiled-run" {
				return true
			}
		}
		return false
	})
	proof.verifyRetained(t, ctx, current, original, p, read)
}

// A retained Task must still obtain current authority for its original cached
// artifact before the test replaces that Task with the successor deployment.
func (proof *identityCompiledProof) verifyOriginalRunAfterRotation(t *testing.T, original *Runtime, p control.Policy, wait func(string, func() bool)) {
	t.Helper()
	installedAt := time.Now().UnixMilli()
	wait("fresh retained original compiled run under current installed authority", func() bool {
		raw, err := original.reports.GetBounded(proof.originalCheckKey, maxCheckerObservationBytes)
		if err != nil {
			t.Fatal(err)
		}
		point, err := schema.Decode[checkerObservation](raw)
		if err != nil || point.validate(p.Cluster, original.Identity.Public) != nil {
			t.Fatal("invalid retained compiled observation", err)
		}
		if point.Task != proof.originalCheck.Task || point.Program != proof.originalCheck.Program || point.Checkpoint.Definition.Request.Checker != proof.originalCheck.Checkpoint.Definition.Request.Checker {
			t.Fatal("retained compiled run changed original task/program")
		}
		return point.Checkpoint.Last != nil && point.Checkpoint.Last.At >= installedAt && point.Checkpoint.Last.Result.Status == contract.Pass && point.Diagnostic != nil && point.Diagnostic.Phase == "compiled-run" && point.Diagnostic.AuthorityCause == ""
	})
}
