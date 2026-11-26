// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func newCheckerFixture(t *testing.T) *nodeStorageFixture {
	f := newNodeStorageFixture(t)
	for user, session := range f.sessions {
		session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.ManageServices}}}
		session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
		f.sessions[user] = session
	}
	return f
}

func checkerPolicy() checker.TenantPolicy {
	return checker.TenantPolicy{Tenant: "tenant", Enabled: true,
		Execution: checker.ExecutionPolicy{MaxConcurrent: 2, TimeoutMS: 5000, NanoCPU: 100_000_000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}},
		Resolver:  checker.ResolverPolicy{AllowPackages: []string{"context", "github.com/jay94ks/mydcd/lifecycle/v1"}, SourceCacheBytes: 1 << 20}}
}

func checkerFact(f *nodeStorageFixture, private ed25519.PrivateKey, source string) checker.SourceFact {
	fact := checker.SourceFact{Schema: 1, Cluster: f.p.Cluster, Owner: [32]byte(private.Public().(ed25519.PublicKey)), Tenant: "tenant", SDK: 1, Digest: sha256.Sum256([]byte(source)), Length: uint64(len(source))}
	fact.Signature = ed25519.Sign(private, checker.SourceFactBytes(fact))
	return fact
}

// Facts here are simulated signed staging metadata. This tests the actual FSM,
// admission and checkpoint path, not source transfer/Yaegi/compile readiness.
func TestCheckerLifecycleSharedCASAndCatalogPinsRetainOriginalReceipts(t *testing.T) {
	f := newCheckerFixture(t)
	policy := checkerPolicy()
	f.apply("manager", "set-lifecycle-policy", 0, policy, state.Applied)
	fact := checkerFact(f, f.node, "package checker\n")
	put := LifecycleScriptPut{Tenant: "tenant", Name: "ready", Source: fact}
	original := f.apply("manager", "put-lifecycle-script", 0, put, state.Applied)
	f.apply("manager", "put-lifecycle-script", 0, put, state.ConditionFailed)
	book, err := f.p.Lifecycles(f.s)
	if err != nil {
		t.Fatal(err)
	}
	pin := checker.Use{Tenant: "tenant", ID: "app-original", Kind: "app-binding", Principal: "manager", Node: "node-a", Owner: fact.Owner, Parent: [32]byte{1}, PolicyRevision: 1, Scripts: []checker.NamedReference{{Name: "ready", Revision: 1}}}
	book, err = book.Reserve(pin)
	if err != nil {
		t.Fatal(err)
	}
	// This catalog-only pin is deliberately NOT an accepted app parent. The
	// full candidate validator must reject injecting it into shared state.
	writes, code := f.p.lifecycleCheckpoint(f.s, book)
	if code != state.Applied {
		t.Fatal(code)
	}
	cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "orphan-candidate", Key: LifecycleKey, Expected: f.s.Object(LifecycleKey).Revision, Value: "fixed-fixture"}
	candidate, result, err := state.ApplyReduced(f.s, f.s.Index()+1, cmd, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal("construct original candidate", err)
	}
	if f.p.Validate(f.s, candidate, cmd) == nil {
		t.Fatal("orphan app lifecycle pin passed shared validation")
	}
	users, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	ref := checker.NamedReference{Name: "ready", Revision: 1}
	book, err = book.RetireScript(users, "manager", 1, "tenant", ref, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := book.RetireScript(users, "manager", 2, "tenant", ref, true); err == nil {
		t.Fatal("pure catalog erased live original use")
	}
	policy.Enabled = false
	book, err = book.SetPolicy(users, "manager", 1, policy)
	if err != nil {
		t.Fatal(err)
	}
	if book.Quiescent() {
		t.Fatal("original pin vanished on policy revocation")
	}
	raw, err := book.Encode()
	if err != nil {
		t.Fatal(err)
	}
	book, err = checker.DecodeCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	if old, ok := book.Policy("tenant", 1); !ok || !old.Enabled {
		t.Fatal("accepted policy erased")
	}
	book, err = book.Release(pin)
	if err != nil || !book.Quiescent() {
		t.Fatal("revocation blocked original release", err)
	}
	selection := LifecycleScriptSelection{Tenant: "tenant", Name: "ready", Revision: 1}
	f.apply("manager", "retire-lifecycle-script", 1, selection, state.Applied)
	f.apply("manager", "set-lifecycle-policy", 1, policy, state.Applied)
	snapshot, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(snapshot)
	if err != nil || f.p.Validate(f.s, f.s, state.Command{}) != nil {
		t.Fatal("actual shared metadata snapshot lost original history", err)
	}
	f.apply("manager", "delete-lifecycle-script", 2, selection, state.Applied)
	if !f.p.storageQuiescent(f.s) {
		t.Fatal("static history prevented shared settlement")
	}
	if receipt, found := f.s.LookupResult(original); !found || receipt.Code != state.Applied {
		t.Fatal("original put receipt lost")
	}
	book, _ = f.p.Lifecycles(f.s)
	record, _ := book.Script("tenant", "ready")
	if record.Revision != 3 || !record.Versions[0].Deleted || record.Versions[0].Source.ContentDigest() != fact.ContentDigest() {
		t.Fatal("source/CAS floor lost")
	}
}

func TestCheckerLifecycleCurrentAuthorityProviderAndBuilderAdmission(t *testing.T) {
	f := newCheckerFixture(t)
	policy := checkerPolicy()
	f.apply("manager", "set-lifecycle-policy", 0, policy, state.Applied)
	unknown := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{111}, 32))
	put := LifecycleScriptPut{Tenant: "tenant", Name: "ready", Source: checkerFact(f, unknown, "package checker\n")}
	f.apply("manager", "put-lifecycle-script", 0, put, state.Forbidden)
	put.Source = checkerFact(f, f.node, "package checker\n")
	put.Source.Length++
	f.apply("manager", "put-lifecycle-script", 0, put, state.Invalid)
	put.Source = checkerFact(f, f.node, "package checker\n")
	limited := f.sessions["manager"]
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	limited.Signature = ed25519.Sign(f.node, access.SessionBytes(limited))
	original := f.sessions["manager"]
	f.sessions["manager"] = limited
	f.apply("manager", "put-lifecycle-script", 0, put, state.Forbidden)
	f.sessions["manager"] = original
	put.Tenant = "other"
	put.Source.Tenant = "other"
	put.Source.Signature = ed25519.Sign(f.node, checker.SourceFactBytes(put.Source))
	f.apply("manager", "put-lifecycle-script", 0, put, state.Forbidden)
	policy.Build = checker.BuildPolicy{Nodes: []string{"missing"}, Targets: []string{"linux/amd64"}, Image: "docker.io/library/golang@sha256:" + strings.Repeat("a", 64), Toolchain: "go1.27.3", MaxJobs: 1, NanoCPU: 100_000_000, MemoryBytes: 128 << 20, WorkspaceBytes: 1 << 20, ArtifactBytes: 1 << 20, TimeoutMS: 10000}
	policy.CompiledCacheBytes = 1 << 20
	f.apply("manager", "set-lifecycle-policy", 1, policy, state.Forbidden)
	policy.Build.Nodes = []string{"node-a"}
	f.apply("manager", "set-lifecycle-policy", 1, policy, state.Applied)
}

func TestCheckerLifecyclePagedMetadataAndTypedInputSeparation(t *testing.T) {
	f := newCheckerFixture(t)
	f.apply("manager", "set-lifecycle-policy", 0, checkerPolicy(), state.Applied)
	f.apply("manager", "put-lifecycle-script", 0, LifecycleScriptPut{Tenant: "tenant", Name: "ready", Source: checkerFact(f, f.node, "package checker\n")}, state.Applied)
	current, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal(err)
	}
	page, next, err := current.LifecyclePage(f.s, f.sessions["manager"], 2, "tenant", "")
	if err != nil || len(page) != 1 || page[0].Policy == nil || next != "policy" {
		t.Fatal("first bounded policy page", page, next, err)
	}
	page, next, err = current.LifecyclePage(f.s, f.sessions["manager"], 2, "tenant", next)
	if err != nil || len(page) != 1 || page[0].Source == nil || page[0].SourceRevision != 1 || next != "" {
		t.Fatal("source metadata page", page, next, err)
	}
	if _, _, err = current.LifecyclePage(f.s, f.sessions["manager"], 2, "other", ""); err == nil {
		t.Fatal("cross-tenant metadata disclosed")
	}
	for _, raw := range []string{
		`{"schema":1,"action":"put-lifecycle-script","payload":{"Tenant":"tenant","Name":"ready","Source":"package checker"}}`,
		`{"schema":1,"action":"delete-lifecycle-script","payload":{"Tenant":"tenant","Name":"ready","Revision":1,"Unused":true}}`,
	} {
		if _, err := InputChange([]byte(raw), "manager"); err == nil {
			t.Fatal("raw source/self-supplied closure admitted", raw)
		}
	}
	policyRaw, _ := json.Marshal(checkerPolicy())
	if _, err := InputChange(changeInput("set-lifecycle-policy", 0, []byte(strings.ReplaceAll(string(policyRaw), ":null", ":[]"))), "manager"); err != nil {
		t.Fatal("tenant metadata policy not accepted", err)
	}
	if _, err := InputChange(changeInput("put-lifecycle-script", 0, []byte(`{"Tenant":"tenant","Name":"ready","Source":{"Ready":true}}`)), "manager"); err == nil {
		t.Fatal("self-supplied readiness treated as content metadata")
	}
}

func TestCheckerSourceQuorumPermitSeparatesNewStagingAndOriginalRecovery(t *testing.T) {
	f := newCheckerFixture(t)
	policy := checkerPolicy()
	f.apply("manager", "set-lifecycle-policy", 0, policy, state.Applied)
	fact := checkerFact(f, f.node, "package checker\n")
	q := LifecycleSourcePermitRequest{Session: f.sessions["manager"], Source: fact.Descriptor(), At: 2}
	permit, err := f.p.LifecycleSourcePermit(f.s, fact.Owner, q)
	if err != nil || permit.Node != "node-a" || permit.Provider != fact.Owner || permit.Index != f.s.Index() || permit.Source.ContentDigest() != fact.ContentDigest() {
		t.Fatal("source permit not bound to quorum candidate/provider/content", err)
	}
	if _, err := f.p.LifecycleSourcePermit(f.s, [32]byte{1}, q); err == nil {
		t.Fatal("nonmember source provider")
	}
	policy.Enabled = false
	f.apply("manager", "set-lifecycle-policy", 1, policy, state.Applied)
	if _, err := f.p.LifecycleSourcePermit(f.s, fact.Owner, q); err == nil {
		t.Fatal("disabled policy admitted new cache allocation")
	}
	q.Recover = true
	if _, err := f.p.LifecycleSourcePermit(f.s, fact.Owner, q); err != nil {
		t.Fatal("policy revocation erased original recovery access", err)
	}
	q.Source.Tenant = "other"
	if _, err := f.p.LifecycleSourcePermit(f.s, fact.Owner, q); err == nil {
		t.Fatal("cross-tenant source recovery")
	}
}

func TestCheckerAppPlanningPublishesImplementedLifecycleContract(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	planning, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil || !planning.Features["lifecycle"] || planning.Checkers.Cluster() != f.p.Cluster {
		t.Fatal("actual planning entrypoint does not expose implemented contract", err)
	}
	// Capability is a parser/adapter contract, never a claim of native readiness.
	if len(planning.Checkers.BuildJobs()) != 0 {
		t.Fatal("advertisement started a compiler job")
	}
}
