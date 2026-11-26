// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// SIMULATED signed source/build/cache facts. Real metadata validation only;
// executable bytes, quorum/Task grants and native readiness are not proved.
func checkerArtifactMetadataFixture(t *testing.T) (checker.SourceFact, checker.CompiledFact, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	builder := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{41}, 32))
	cache := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	source := checker.SourceFact{Schema: 1, Cluster: [32]byte{91}, Owner: [32]byte(builder.Public().(ed25519.PublicKey)), Tenant: "tenant", Digest: sha256.Sum256([]byte("package checker\n")), Length: 16, SDK: 1}
	source.Signature = ed25519.Sign(builder, checker.SourceFactBytes(source))
	recipe := checker.CompileRecipe{Schema: 1, Tenant: "tenant", Source: source.ContentDigest(), Image: "docker.io/library/golang@sha256:" + strings.Repeat("a", 64), Toolchain: "go1.27.3", GOOS: "linux", GOARCH: "amd64", Flags: []string{"build", "-p=2", "-trimpath", "-buildvcs=false", "-ldflags=-buildid="}, SDK: [32]byte{1}, Wrapper: [32]byte{2}, Tree: [32]byte{3}}
	job := sha256.Sum256([]byte("original-build-id"))
	build := checker.CompiledBuild{Schema: 1, Cluster: source.Cluster, Builder: source.Owner, Job: job, ID: hex.EncodeToString(job[:]), Recipe: recipe, Digest: [32]byte{99}, Length: 4097}
	build.Signature = ed25519.Sign(builder, checker.CompiledBuildBytes(build))
	fact := checker.CompiledFact{Schema: 1, Owner: [32]byte(cache.Public().(ed25519.PublicKey)), Build: build}
	fact.Signature = ed25519.Sign(cache, checker.CompiledFactBytes(fact))
	if source.Verify() != nil || fact.Verify() != nil {
		t.Fatal("invalid signed fixture")
	}
	return source, fact, builder, cache
}

func TestCheckerCompiledTransferMetadataPreservesBothIdentitiesAndExactRecipe(t *testing.T) {
	source, fact, builder, cache := checkerArtifactMetadataFixture(t)
	build := fact.Build
	q := control.CheckerArtifactRequest{Schema: 1, Tenant: "tenant", Content: source.ContentDigest(), Compiled: &fact}
	p := control.CheckerArtifactPermit{Schema: 1, Tenant: "tenant", Source: source, Compiled: &fact}
	meta := checkerArtifactMetadata{Schema: 1, Compiled: &fact}
	raw, _ := json.Marshal(meta)
	if checkerArtifactMetadataAllowed(raw, q, p) != nil {
		t.Fatal("exact compiled cache metadata")
	}
	if digest, length := checkerArtifactBytes(q, p); digest != build.Digest || length != build.Length {
		t.Fatal("wire selected root bytes")
	}
	for label, mutate := range map[string]func(*checkerArtifactMetadata){
		"mixed-source": func(m *checkerArtifactMetadata) { m.Source = &source },
		"mixed-module": func(m *checkerArtifactMetadata) { m.Module = &checker.ModuleFact{} },
		"missing":      func(m *checkerArtifactMetadata) { m.Compiled = nil },
		"different-provider": func(m *checkerArtifactMetadata) {
			m.Compiled.Owner = build.Builder
			m.Compiled.Signature = ed25519.Sign(builder, checker.CompiledFactBytes(*m.Compiled))
		},
		"different-origin": func(m *checkerArtifactMetadata) {
			m.Compiled.Build.Job[0]++
			m.Compiled.Build.Signature = ed25519.Sign(builder, checker.CompiledBuildBytes(m.Compiled.Build))
			m.Compiled.Signature = ed25519.Sign(cache, checker.CompiledFactBytes(*m.Compiled))
		},
	} {
		t.Run(label, func(t *testing.T) {
			f := fact.Clone()
			m := checkerArtifactMetadata{Schema: 1, Compiled: &f}
			mutate(&m)
			raw, _ := json.Marshal(m)
			if checkerArtifactMetadataAllowed(raw, q, p) == nil {
				t.Fatal("changed transfer metadata")
			}
		})
	}
	q.Module = &checker.ModulePin{}
	if checkerArtifactMetadataAllowed(raw, q, p) == nil {
		t.Fatal("mixed request selectors")
	}
	q.Module = nil
	q.Lookup = &control.CheckerCacheLookup{Provider: fact.Owner, Recipe: fact.Build.Recipe}
	if checkerArtifactMetadataAllowed(raw, q, p) == nil {
		t.Fatal("metadata-only lookup selected body transport")
	}
	q.Lookup = nil
	q.Module, q.Compiled, p.Compiled = nil, nil, nil
	plain, _ := json.Marshal(checkerArtifactMetadata{Schema: 1, Source: &source})
	if checkerArtifactMetadataAllowed(plain, q, p) != nil {
		t.Fatal("source transfer changed")
	}
	if checkerArtifactMetadataAllowed(raw, q, p) == nil {
		t.Fatal("compiled metadata used for source transfer")
	}
	if digest, length := checkerArtifactBytes(q, p); digest != source.Digest || length != source.Length {
		t.Fatal("source wire selection changed")
	}
}
