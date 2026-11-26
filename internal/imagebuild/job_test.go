// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
)

func testJobSpec(t *testing.T) (JobSpec, ed25519.PrivateKey) {
	t.Helper()
	scope, key := testScope(10, sha256.Sum256([]byte("original")))
	context := ContextSpec{Tenant: scope.Tenant, ID: scope.Context, Kind: "upload", Root: scope.Root, Dockerfile: scope.Dockerfile, Arguments: map[string]string{"PUBLIC": "value"}, Repository: "team/app", Tags: []string{"version-{version}"}, Platforms: []string{"linux/amd64"}}
	policy := Policy{Schema: 1, Tenant: scope.Tenant, Nodes: []NodeRoot{{Node: scope.Root.Node, Root: scope.Root}}, Concurrency: 1, Seconds: 600, CPUMillis: 1000, MemoryBytes: 128 << 20, WorkspaceBytes: 1 << 30, CacheBytes: 1 << 30, Registry: "registry", Platforms: []string{"linux/amd64"}, BuilderImage: "docker.io/moby/buildkit@sha256:" + strings.Repeat("a", 64), Cleanup: CleanupPolicy{HighWaterPercent: 80, UnusedDays: 7}}
	seal := SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: sha256.Sum256([]byte("injected tree")), Entries: 1, ExpandedBytes: 1}
	seal.Signature = ed25519.Sign(key, SealReceiptBytes(seal))
	s := JobSpec{Schema: 1, Cluster: scope.Cluster, Tenant: scope.Tenant, ID: "build-one", Version: VersionID(seal), Number: 1, Scope: scope, Seal: seal, Context: context, Policy: policy, ContextRevision: 1, PolicyRevision: 1, RegistryAuthority: "registry.example", RegistryGeneration: 1, RegistrySpec: [32]byte{3}, CreatedAt: 100}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s, key
}
func jobTestClosure(s JobSpec, key ed25519.PrivateKey, code string) JobClosure {
	result := JobResult{Code: code}
	if code == "OK" {
		result.Image = s.OutputRepository() + "@sha256:" + strings.Repeat("b", 64)
		result.Bytes = 123
	}
	c := JobClosure{Schema: 1, Job: s.Digest(), Native: sha256.Sum256([]byte("injected native closure")), Result: result, At: 103}
	c.Signature = ed25519.Sign(key, JobClosureBytes(c))
	return c
}

func TestJobCoreOriginalInputsCancellationAndUnknownNeedOwnerClosure(t *testing.T) {
	s, key := testJobSpec(t)
	run, err := NewJob(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Context.Arguments["PUBLIC"] = "changed"
	if run.Spec.Context.Arguments["PUBLIC"] != "value" {
		t.Fatal("mutable original inputs")
	}
	if _, err := run.Complete(1, jobTestClosure(run.Spec, key, "OK")); err == nil {
		t.Fatal("queued job fabricated success")
	}
	run, err = run.Begin(1, 101, nil)
	if err != nil {
		t.Fatal(err)
	}
	run, err = run.Uncertain(run.Revision)
	if err != nil || run.Terminal() {
		t.Fatal("unknown released inputs", err)
	}
	if _, err := run.Begin(run.Revision, 102, nil); err == nil {
		t.Fatal("unknown starts replacement")
	}
	run, err = run.RequestCancel(run.Revision)
	if err != nil || run.Terminal() || run.Closure != nil {
		t.Fatal("cancel fabricated native closure", err)
	}
	bad := jobTestClosure(run.Spec, key, "CANCELLED")
	bad.Native = [32]byte{}
	if _, err := run.Complete(run.Revision, bad); err == nil {
		t.Fatal("unsigned/missing closure accepted")
	}
	run, err = run.Complete(run.Revision, jobTestClosure(run.Spec, key, "CANCELLED"))
	if err != nil || !run.Terminal() || run.Phase != "cancelled" || run.Shape() != nil {
		t.Fatal(run.Phase, err)
	}
	if _, err := run.RequestCancel(run.Revision); err == nil {
		t.Fatal("terminal job reopened")
	}
}

func TestJobInputPinsAndOutputTagsCannotBroadenAcceptedScope(t *testing.T) {
	s, _ := testJobSpec(t)
	input := FrozenSource{Source: Source{Reference: "docker.io/library/alpine:latest", Platform: "linux/amd64", Stage: 0, Kind: "from", Line: 1}, Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)}
	if err := ValidateJobInputs(s, []FrozenSource{input}); err != nil {
		t.Fatal(err)
	}
	other := input
	other.Image = "docker.io/other/image@sha256:" + strings.Repeat("a", 64)
	if ValidateJobInputs(s, []FrozenSource{other}) == nil {
		t.Fatal("pin changed repository")
	}
	other = input
	other.Source.Platform = "linux/arm64"
	if ValidateJobInputs(s, []FrozenSource{other}) == nil {
		t.Fatal("undeclared platform accepted")
	}
	s.Context.Tags = []string{"git-{commit}"}
	if s.Shape() == nil {
		t.Fatal("missing Git commit silently substituted")
	}
	s.Commit = strings.Repeat("a", 40)
	tags, err := s.OutputTags()
	if err != nil || len(tags) != 1 || tags[0] != "registry.example/team/app:git-"+s.Commit {
		t.Fatal(tags, err)
	}
}

func TestJobRejectsPreservedSourceLargerThanCurrentWorkspacePolicy(t *testing.T) {
	s, key := testJobSpec(t)
	s.Seal.ExpandedBytes = 2
	s.Seal.Signature = ed25519.Sign(key, SealReceiptBytes(s.Seal))
	s.Version = VersionID(s.Seal)
	s.Policy.WorkspaceBytes = 1
	if s.Seal.Valid(s.Scope) == false || s.Validate() == nil {
		t.Fatal("historical valid seal bypassed lowered workspace admission")
	}
	s.Policy.WorkspaceBytes = 2
	if s.Validate() != nil {
		t.Fatal("source at current workspace boundary rejected")
	}
}

func TestJobInputPlatformUsesAllowedPolicyForCrossBuildStages(t *testing.T) {
	s, _ := testJobSpec(t)
	s.Context.Platforms = []string{"linux/arm64"}
	s.Policy.Platforms = []string{"linux/amd64", "linux/arm64"}
	if s.Validate() != nil {
		t.Fatal("cross-build fixture invalid")
	}
	input := FrozenSource{Source: Source{Reference: "docker.io/library/golang:latest", Platform: "linux/amd64", Stage: 0, Kind: "from", Line: 1}, Image: "docker.io/library/golang@sha256:" + strings.Repeat("a", 64)}
	if err := ValidateJobInputs(s, []FrozenSource{input}); err != nil {
		t.Fatal("allowed build stage rejected because output differs", err)
	}
	input.Source.Platform = "linux/riscv64"
	if ValidateJobInputs(s, []FrozenSource{input}) == nil {
		t.Fatal("policy-external platform accepted")
	}
}
