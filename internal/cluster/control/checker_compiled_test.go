// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// Product catalog and authority projection, SIMULATED signed native closure.
// This does not establish live Task/quorum, Docker or executable cache bytes.
func checkerCompiledFixture(t *testing.T) (checker.Catalog, checker.TaskProgram, checker.CompiledFact, ed25519.PrivateKey) {
	t.Helper()
	f := newCheckerFixture(t)
	p := checkerPolicy()
	p.Build = checker.BuildPolicy{Nodes: []string{"node-a"}, Targets: []string{"linux/amd64"}, Image: "docker.io/library/golang@sha256:" + strings.Repeat("a", 64), Toolchain: "go1.27.3", MaxJobs: 1, NanoCPU: 100000000, MemoryBytes: 64 << 20, WorkspaceBytes: 64 << 20, ArtifactBytes: 32 << 20, TimeoutMS: 10000}
	p.CompiledCacheBytes = 64 << 20
	book, err := checker.NewCatalog(f.p.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.SetPolicy(f.users, "manager", 0, p)
	if err != nil {
		t.Fatal(err)
	}
	p, _ = book.Policy("tenant", 0)
	source := checkerFact(f, f.node, "package checker\n")
	parent := checker.Use{Tenant: "tenant", ID: "original-app", Kind: "app-binding", Principal: "manager", Node: "node-a", Owner: source.Owner, Parent: [32]byte{4}, PolicyRevision: p.Revision, Sources: []checker.SourceFact{source}}
	book, err = book.Reserve(parent)
	if err != nil {
		t.Fatal(err)
	}
	recipe := checker.CompileRecipe{Schema: 1, Tenant: "tenant", Source: source.ContentDigest(), Image: p.Build.Image, Toolchain: p.Build.Toolchain, GOOS: "linux", GOARCH: "amd64", Flags: []string{"build", "-p=2", "-trimpath", "-buildvcs=false", "-ldflags=-buildid="}, SDK: [32]byte{1}, Wrapper: [32]byte{2}, Tree: [32]byte{3}}
	id := sha256.Sum256([]byte("original-build-job"))
	intent := checker.BuildIntent{Schema: 1, Cluster: book.Cluster(), Tenant: "tenant", ID: hex.EncodeToString(id[:]), AppUseID: parent.ID, AppUse: parent.Digest(), Node: "node-a", Owner: source.Owner, Selection: checker.Selection{PolicyRevision: p.Revision, Sources: []checker.SourceFact{source}}, Inputs: []checker.BuildInput{{Content: source.ContentDigest(), Recipe: recipe.Key()}}, Manifest: [32]byte{9}, Target: "linux/amd64", DeadlineUnixMilli: 100000}
	book, err = book.ReserveBuild(intent)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.DispatchBuild("tenant", intent.ID, 1, source.Owner)
	if err != nil {
		t.Fatal(err)
	}
	build := checker.CompiledBuild{Schema: 1, Cluster: book.Cluster(), Builder: source.Owner, Job: intent.Digest(), ID: intent.ID, Recipe: recipe, Digest: [32]byte{13}, Length: 1234}
	build.Signature = ed25519.Sign(f.node, checker.CompiledBuildBytes(build))
	native := sha256.Sum256([]byte("simulated-native-id"))
	closure := checker.BuildClosure{Schema: 1, Cluster: book.Cluster(), Job: intent.Digest(), Owner: source.Owner, Journal: [32]byte{17}, Output: [32]byte{18}, Disposition: "removed", Native: hex.EncodeToString(native[:]), Artifacts: []checker.BuildArtifact{{Key: recipe.Key(), Digest: build.Digest, Length: build.Length}}}
	closure.Signature = ed25519.Sign(f.node, checker.BuildClosureBytes(closure))
	book, err = book.CloseBuild("tenant", intent.ID, 2, closure)
	if err != nil {
		t.Fatal(err)
	}
	// Serving cache identity differs from the original builder identity.
	cache := f.manager
	fact := checker.CompiledFact{Schema: 1, Owner: [32]byte(cache.Public().(ed25519.PublicKey)), Build: build}
	fact.Signature = ed25519.Sign(cache, checker.CompiledFactBytes(fact))
	program := checker.TaskProgram{Tenant: "tenant", Policy: p, Scripts: map[string]checker.ScriptSelection{"alias": {Compile: true}}, Sources: map[string]checker.SourceFact{"alias": source}}
	return book, program, fact, cache
}

func TestCheckerCompiledConsumerRequiresOriginalCompiledTaskAndCurrentPolicy(t *testing.T) {
	book, program, fact, cache := checkerCompiledFixture(t)
	content := fact.Build.Recipe.Source
	if ValidateCheckerCompiledMetadata(book, &program, program.Policy, content, fact) != nil {
		t.Fatal("exact original compiled Task")
	}
	alias := program.Policy.Clone()
	alias.Build.Image = strings.TrimPrefix(alias.Build.Image, "docker.io/library/")
	if ValidateCheckerCompiledMetadata(book, &program, alias, content, fact) != nil {
		t.Fatal("equivalent pinned image alias rejected")
	}
	for label, change := range map[string]func(*checker.TaskProgram, *checker.TenantPolicy, *checker.CompiledFact){
		"interpreted": func(p *checker.TaskProgram, _ *checker.TenantPolicy, _ *checker.CompiledFact) {
			s := p.Scripts["alias"]
			s.Compile = false
			p.Scripts["alias"] = s
		},
		"other-source": func(p *checker.TaskProgram, _ *checker.TenantPolicy, _ *checker.CompiledFact) {
			s := p.Sources["alias"]
			s.Digest[0]++
			p.Sources["alias"] = s
		},
		"other-tenant": func(p *checker.TaskProgram, _ *checker.TenantPolicy, _ *checker.CompiledFact) { p.Tenant = "foreign" },
		"disabled":     func(_ *checker.TaskProgram, p *checker.TenantPolicy, _ *checker.CompiledFact) { p.Enabled = false },
		"new-toolchain": func(_ *checker.TaskProgram, p *checker.TenantPolicy, _ *checker.CompiledFact) {
			p.Build.Toolchain = "go1.27.4"
		},
		"new-image": func(_ *checker.TaskProgram, p *checker.TenantPolicy, _ *checker.CompiledFact) {
			p.Build.Image = "docker.io/library/golang@sha256:" + strings.Repeat("b", 64)
		},
		"no-target": func(_ *checker.TaskProgram, p *checker.TenantPolicy, _ *checker.CompiledFact) { p.Build.Targets = nil },
		"wrong-original-policy": func(p *checker.TaskProgram, _ *checker.TenantPolicy, _ *checker.CompiledFact) {
			p.Policy.Build.Toolchain = "go1.27.4"
		},
		"cache-forged-builder": func(_ *checker.TaskProgram, _ *checker.TenantPolicy, f *checker.CompiledFact) {
			f.Build.Digest[0]++
			f.Signature = ed25519.Sign(cache, checker.CompiledFactBytes(*f))
		},
	} {
		t.Run(label, func(t *testing.T) {
			p, current, f := program.Clone(), program.Policy.Clone(), fact.Clone()
			change(&p, &current, &f)
			if ValidateCheckerCompiledMetadata(book, &p, current, content, f) == nil {
				t.Fatal("unauthorized compiled consumption")
			}
		})
	}
	if ValidateCheckerCompiledMetadata(book, nil, program.Policy, content, fact) == nil {
		t.Fatal("no Task")
	}
	permit := CheckerArtifactPermit{Schema: 1, Source: program.Sources["alias"], Compiled: &fact}
	if permit.Provider() != fact.Owner || permit.Provider() == fact.Build.Builder {
		t.Fatal("cache provider replaced by historical builder")
	}
	copy := permit
	copy.Index = 100
	if !copy.Equal(permit) {
		t.Fatal("unrelated index changed grant")
	}
	changed := fact.Clone()
	changed.Build.Digest[0]++
	copy.Compiled = &changed
	if copy.Equal(permit) {
		t.Fatal("different artifact unchanged grant")
	}
}

func TestCheckerCacheLookupIsRecipeScopedAndCannotChangeTransportGrant(t *testing.T) {
	_, program, fact, _ := checkerCompiledFixture(t)
	r := fact.Build.Recipe
	if checkerRecipeProgramAllowed(&program, program.Policy, r.Source, r) != nil {
		t.Fatal("exact compiled recipe lookup")
	}
	changed := program.Clone()
	script := changed.Scripts["alias"]
	script.Compile = false
	changed.Scripts["alias"] = script
	if checkerRecipeProgramAllowed(&changed, program.Policy, r.Source, r) == nil {
		t.Fatal("interpreted source cache lookup")
	}
	if checkerRecipeProgramAllowed(&program, program.Policy, [32]byte{99}, r) == nil {
		t.Fatal("other source cache lookup")
	}
	lookup := CheckerCacheLookup{Provider: fact.Owner, Recipe: r}
	permit := CheckerArtifactPermit{Schema: 1, Source: program.Sources["alias"], Lookup: &lookup}
	if permit.Provider() != fact.Owner {
		t.Fatal("lookup routed to historical source owner")
	}
	clone := lookup.Clone()
	clone.Recipe.Flags[0] = "changed"
	if lookup.Recipe.Validate() != nil {
		t.Fatal("lookup clone aliases recipe flags")
	}
	other := permit
	copy := lookup.Clone()
	copy.Provider[0]++
	other.Lookup = &copy
	if other.Equal(permit) {
		t.Fatal("provider changed without grant change")
	}
	other = permit
	other.Lookup = nil
	if other.Equal(permit) {
		t.Fatal("lookup used as body grant")
	}
}
