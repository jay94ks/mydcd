// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Reuses the existing signed artifact fixture and actual immutable catalog,
// program freeze, closed-job and membership cores. Native/compiler/cache bytes
// and current Binding admission are deliberately outside this metadata test.
func retainedCompiledAuthorityFixture(t *testing.T) (checker.Catalog, checker.Use, checker.TaskProgram, checker.CompiledFact, ed25519.PrivateKey, access.Catalog) {
	t.Helper()
	source, fact, original, _ := checkerArtifactMetadataFixture(t)
	users, err := access.New(source.Owner)
	if err != nil {
		t.Fatal(err)
	}
	users, err = users.Enroll(source.Owner, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: source.Owner, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	users, err = users.CreateTenant("admin", source.Tenant, 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant(source.Tenant)
	users, err = users.SetNodes("admin", source.Tenant, tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ = users.Tenant(source.Tenant)
	users, err = users.ChangeTrust("admin", source.Tenant, tenant.Revision, []access.TrustRule{{Registry: "docker.io", Repository: "library/golang"}}, tenant.ImageSources)
	if err != nil {
		t.Fatal(err)
	}
	policy := checker.TenantPolicy{Tenant: source.Tenant, Enabled: true,
		Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 64 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}},
		Resolver:  checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/seafield/lifecycle/v1"}, SourceCacheBytes: 1 << 20},
		Build:     checker.BuildPolicy{Nodes: []string{"node-a"}, Targets: []string{"linux/amd64"}, Image: fact.Build.Recipe.Image, Toolchain: fact.Build.Recipe.Toolchain, MaxJobs: 1, NanoCPU: 100000000, MemoryBytes: 64 << 20, WorkspaceBytes: 64 << 20, ArtifactBytes: 32 << 20, TimeoutMS: 10000}, CompiledCacheBytes: 64 << 20}
	book, err := checker.NewCatalog(source.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.SetPolicy(users, "admin", 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	on := true
	frozen, err := checker.FreezeProgram(source.Tenant, checker.Program{Scripts: map[string]checker.Script{"alive": {Source: "package checker\n", Compile: &on}}, Services: map[string][]checker.Check{"web": {{ID: "alive", Phase: contract.Liveness, Template: checker.Template{Script: "alive"}}}}}, book, map[string]checker.SourceFact{"alive": source}, checker.Timing{IntervalMS: 5000, TimeoutMS: 2000, FreshForMS: 7000, Retries: 3})
	if err != nil {
		t.Fatal(err)
	}
	program, err := frozen.Task("web")
	if err != nil || program.Validate(book.Cluster()) != nil {
		t.Fatal("original frozen compiled Task program", err)
	}
	use := checker.Use{Tenant: source.Tenant, ID: "retained-task", Kind: "app-binding", Principal: "admin", Node: "node-a", Owner: source.Owner, Parent: [32]byte{4}, PolicyRevision: 1, Sources: []checker.SourceFact{source}}
	book, err = book.Reserve(use)
	if err != nil {
		t.Fatal(err)
	}
	intent := checker.BuildIntent{Schema: 1, Cluster: source.Cluster, Tenant: source.Tenant, ID: fact.Build.ID, AppUseID: use.ID, AppUse: use.Digest(), Node: use.Node, Owner: source.Owner, Selection: checker.Selection{PolicyRevision: 1, Sources: []checker.SourceFact{source}}, Inputs: []checker.BuildInput{{Content: source.ContentDigest(), Recipe: fact.Build.Recipe.Key()}}, Manifest: [32]byte{5}, Target: "linux/amd64", DeadlineUnixMilli: 100000}
	book, err = book.ReserveBuild(intent)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.DispatchBuild(intent.Tenant, intent.ID, 1, source.Owner)
	if err != nil {
		t.Fatal(err)
	}
	fact.Build.Job = intent.Digest()
	fact.Build.Signature = ed25519.Sign(original, checker.CompiledBuildBytes(fact.Build))
	fact.Owner = source.Owner // This is an original LOCAL compiled cache.
	fact.Signature = ed25519.Sign(original, checker.CompiledFactBytes(fact))
	closure := checker.BuildClosure{Schema: 1, Cluster: source.Cluster, Job: intent.Digest(), Owner: source.Owner, Journal: [32]byte{6}, Output: [32]byte{7}, Disposition: "removed", Native: hex.EncodeToString(bytes.Repeat([]byte{8}, 32)), Artifacts: []checker.BuildArtifact{{Key: fact.Build.Recipe.Key(), Digest: fact.Build.Digest, Length: fact.Build.Length}}}
	closure.Signature = ed25519.Sign(original, checker.BuildClosureBytes(closure))
	book, err = book.CloseBuild(intent.Tenant, intent.ID, 2, closure)
	if err != nil || control.ValidateCheckerCompiledMetadata(book, &program, program.Policy, fact.Build.Recipe.Source, fact) != nil {
		t.Fatal("original closed build/cache provenance", err)
	}
	return book, use, program, fact, original, users
}

func TestCheckerRetainedLocalCompiledAuthorityFollowsTwoCurrentRotations(t *testing.T) {
	book, use, program, fact, original, users := retainedCompiledAuthorityFixture(t)
	peer := config.Peer{ID: use.Node, Key: hex.EncodeToString(use.Owner[:]), Endpoint: "127.0.0.1:9001", Voter: true}
	members, err := membership.New(book.Cluster(), peer)
	if err != nil {
		t.Fatal(err)
	}
	members, err = members.InstallConfiguration(lifecycle.Configuration{Index: 10, Members: []lifecycle.Member{{ID: peer.ID, Key: use.Owner, Voter: true}}})
	if err != nil {
		t.Fatal(err)
	}
	beforeBook, _ := book.Encode()
	beforeFact, _ := json.Marshal(fact)
	beforeUse := use.Digest()
	current := original
	if err := checkerLocalCompiledAuthority(book, members, use.Owner, use.Owner, use, program, fact); err != nil {
		t.Fatal("unrotated local authority", err)
	}
	for i, seed := range []byte{51, 52} {
		next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
		operation := []string{"replace-one", "replace-two"}[i]
		entry, _ := members.Entry(use.Node)
		members, err = members.BeginIdentityRotation(use.Node, operation, entry.Revision, uint64(20+i*10), json.RawMessage(`{"original":"identity-rotation"}`))
		if err != nil {
			t.Fatal(err)
		}
		proof := lifecycle.IdentityProof{Schema: 1, Cluster: book.Cluster(), Node: use.Node, Operation: operation, Old: [32]byte(current.Public().(ed25519.PublicKey)), New: [32]byte(next.Public().(ed25519.PublicKey)), Prepared: [32]byte{9}}
		proof.OldSignature = ed25519.Sign(current, lifecycle.IdentityProofBytes(proof))
		proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
		members, err = members.PrepareIdentityRotation(use.Node, operation, proof)
		if err != nil {
			t.Fatal(err)
		}
		members, err = members.ActivateIdentityRotation(use.Node, operation, uint64(22+i*10))
		if err != nil {
			t.Fatal(err)
		}
		members, err = members.InstalledIdentityRotation(use.Node, operation, uint64(23+i*10))
		if err != nil {
			t.Fatal(err)
		}
		if members.WorkKey(proof.Old) || !members.WorkKey(proof.New) || checkerLocalCompiledAuthority(book, members, proof.New, use.Owner, use, program, fact) != nil {
			t.Fatal("installed successor cannot consume original local compiled metadata", i)
		}
		if checkerLocalCompiledAuthority(book, members, proof.Old, use.Owner, use, program, fact) == nil {
			t.Fatal("retired signer revived local compiled permission", i)
		}
		current = next
	}
	caller := [32]byte(current.Public().(ed25519.PublicKey))
	t.Run("current-isolation", func(t *testing.T) {
		topology, _ := members.Topology()
		node, _ := topology.Node(use.Node)
		isolated, err := members.BeginNode(use.Node, "isolate-current", lifecycle.Isolate, node.Revision, topology.Epoch(), json.RawMessage(`{"original":"isolate-current"}`))
		if err != nil || isolated.WorkKey(caller) || checkerLocalCompiledAuthority(book, isolated, caller, use.Owner, use, program, fact) == nil {
			t.Fatal("current isolation did not revoke retained compiled local run", err)
		}
	})
	t.Run("current-policy-revocation", func(t *testing.T) {
		policy := program.Policy.Clone()
		policy.Revision, policy.Enabled = 0, false
		revoked, err := book.SetPolicy(users, "admin", program.Policy.Revision, policy)
		if err != nil || checkerLocalCompiledAuthority(revoked, members, caller, use.Owner, use, program, fact) == nil {
			t.Fatal("current policy revocation bypassed by retained provenance", err)
		}
	})
	t.Run("original-use-released", func(t *testing.T) {
		released, err := book.Release(use)
		if err != nil || checkerLocalCompiledAuthority(released, members, caller, use.Owner, use, program, fact) == nil {
			t.Fatal("closed build history replaced live original use", err)
		}
	})
	t.Run("foreign-current-owner", func(t *testing.T) {
		foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{53}, ed25519.SeedSize))
		key := [32]byte(foreign.Public().(ed25519.PublicKey))
		other, err := membership.New(book.Cluster(), config.Peer{ID: "foreign", Key: hex.EncodeToString(key[:]), Endpoint: "127.0.0.1:9002", Voter: true})
		if err != nil || !other.WorkKey(key) || checkerLocalCompiledAuthority(book, other, key, use.Owner, use, program, fact) == nil {
			t.Fatal("foreign active signer adopted original local Task/cache", err)
		}
	})
	t.Run("foreign-cache-owner", func(t *testing.T) {
		_, foreignFact, _, _ := checkerArtifactMetadataFixture(t)
		foreign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))
		foreignFact.Build = fact.Build.Clone()
		foreignFact.Signature = ed25519.Sign(foreign, checker.CompiledFactBytes(foreignFact))
		if foreignFact.Verify() != nil || control.ValidateCheckerCompiledMetadata(book, &program, program.Policy, fact.Build.Recipe.Source, foreignFact) != nil || checkerLocalCompiledAuthority(book, members, caller, use.Owner, use, program, foreignFact) == nil {
			t.Fatal("valid remote cache provenance became local run ownership")
		}
	})
	t.Run("exact-use-program-and-output", func(t *testing.T) {
		changedUse := use
		changedUse.Parent[0]++
		changedProgram := program.Clone()
		changedProgram.Scripts["alive"] = checker.ScriptSelection{}
		changedFact := fact.Clone()
		changedFact.Build.Digest[0]++
		changedFact.Build.Signature = ed25519.Sign(original, checker.CompiledBuildBytes(changedFact.Build))
		changedFact.Signature = ed25519.Sign(original, checker.CompiledFactBytes(changedFact))
		if checkerLocalCompiledAuthority(book, members, caller, use.Owner, changedUse, program, fact) == nil || checkerLocalCompiledAuthority(book, members, caller, use.Owner, use, changedProgram, fact) == nil || checkerLocalCompiledAuthority(book, members, caller, use.Owner, use, program, changedFact) == nil || checkerLocalCompiledAuthority(book, members, caller, caller, use, program, fact) == nil {
			t.Fatal("lineage relaxed exact use/program/job/local native owner checks")
		}
	})
	afterBook, _ := book.Encode()
	afterFact, _ := json.Marshal(fact)
	if !bytes.Equal(beforeBook, afterBook) || !bytes.Equal(beforeFact, afterFact) || use.Digest() != beforeUse || fact.Verify() != nil || book.CompiledOrigin(fact.Build) != nil {
		t.Fatal("local metadata permission rewrote original use/job/closure/cache proof")
	}
}
