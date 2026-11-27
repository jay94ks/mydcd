// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// Isolated recovery projection: the original catalog job is retained while
// its live app parent is absent. It deliberately cannot authorize Start and
// does not assert full managed-state admission, TLS or native compiler closure.
func TestCheckerOriginalRecoveryUsesReplacementSignerWithoutRewritingJob(t *testing.T) {
	f := newBackupCore(t)
	original := f.p.TrustRoot
	next := rotateRQ9CoreOwner(t, f)
	current := [32]byte(next.Public().(ed25519.PublicKey))
	users, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	policy := checkerPolicy()
	policy.Build = checker.BuildPolicy{Nodes: []string{"node-a"}, Targets: []string{"linux/amd64"}, Image: "docker.io/library/golang@sha256:" + strings.Repeat("a", 64), Toolchain: "go1.27.3", MaxJobs: 1, NanoCPU: 100000000, MemoryBytes: 64 << 20, WorkspaceBytes: 64 << 20, ArtifactBytes: 32 << 20, TimeoutMS: 10000}
	policy.CompiledCacheBytes = 64 << 20
	book, err := checker.NewCatalog(f.p.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.SetPolicy(users, "admin", 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	source := checker.SourceFact{Schema: 1, Cluster: f.p.Cluster, Tenant: "tenant", Owner: original, SDK: 1, Digest: sha256.Sum256([]byte("original")), Length: 8}
	source.Signature = ed25519.Sign(f.node, checker.SourceFactBytes(source))
	parent := checker.Use{Tenant: "tenant", ID: "retired-parent", Kind: "app-binding", Principal: "admin", Node: "node-a", Owner: original, Parent: [32]byte{4}, PolicyRevision: 1, Sources: []checker.SourceFact{source}}
	book, err = book.Reserve(parent)
	if err != nil {
		t.Fatal(err)
	}
	id := sha256.Sum256([]byte("original-retained-job"))
	intent := checker.BuildIntent{Schema: 1, Cluster: f.p.Cluster, Tenant: "tenant", ID: hex.EncodeToString(id[:]), AppUseID: parent.ID, AppUse: parent.Digest(), Node: "node-a", Owner: original, Selection: checker.Selection{PolicyRevision: 1, Sources: []checker.SourceFact{source}}, Inputs: []checker.BuildInput{{Content: source.ContentDigest(), Recipe: [32]byte{2}}}, Manifest: [32]byte{3}, Target: "linux/amd64", DeadlineUnixMilli: 100000}
	book, err = book.ReserveBuild(intent)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.DispatchBuild("tenant", intent.ID, 1, original)
	if err != nil {
		t.Fatal(err)
	}
	install := func(id string, writes map[string][]byte) {
		t.Helper()
		cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: id, Key: LifecycleKey, Expected: f.s.Object(LifecycleKey).Revision, Value: "modeled original recovery projection"}
		next, result, err := state.ApplyReduced(f.s, f.s.Index()+1, cmd, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
		if err != nil || result.Code != state.Applied {
			t.Fatal(result, err)
		}
		f.s = next
	}
	writes, code := f.p.lifecycleCheckpoint(f.s, book)
	if code != state.Applied {
		t.Fatal(code)
	}
	install("original-recovery-projection", writes)
	q := CheckerBuildRequest{Schema: 1, Tenant: "tenant", ID: intent.ID, Job: intent.Digest(), MinimumIndex: f.s.Index(), At: 3, Recover: true}
	work, err := f.p.CheckerBuildPermit(f.s, current, q)
	if err != nil || work.Owner != original || work.Phase != "dispatched" || work.Manifest != intent.Manifest {
		t.Fatal("current key cannot recover exact original", work, err)
	}
	if _, err = f.p.CheckerBuildPermit(f.s, original, q); err == nil {
		t.Fatal("historic key minted recovery permission")
	}
	start := q
	start.Recover = false
	start.Start = true
	if _, err = f.p.CheckerBuildPermit(f.s, current, start); err == nil {
		t.Fatal("recovery bypassed missing live parent")
	}
	wrong := q
	wrong.Job[0] ^= 1
	if _, err = f.p.CheckerBuildPermit(f.s, current, wrong); err == nil {
		t.Fatal("different job reused retained owner")
	}
	activity, err := f.p.NodeActivity(f.s, current)
	if err != nil || activity.CDJobs == 0 {
		t.Fatal("unsettled original job missing from node blockers", activity, err)
	}
	native := sha256.Sum256([]byte("modeled-original-native"))
	closure := checker.BuildClosure{Schema: 1, Cluster: f.p.Cluster, Job: intent.Digest(), Owner: original, Journal: [32]byte{17}, Output: [32]byte{18}, Disposition: "removed", Native: hex.EncodeToString(native[:])}
	closure.Signature = ed25519.Sign(f.node, checker.BuildClosureBytes(closure))
	report := CheckerBuildReport{Schema: 1, Cluster: f.p.Cluster, Reporter: current, Tenant: "tenant", ID: intent.ID, Action: "close", Expected: work.Revision, Epoch: work.Epoch, RootRevision: work.RootRevision, Index: work.Index, At: 3, Closure: &closure}
	report.Signature = ed25519.Sign(next, CheckerBuildReportBytes(report))
	raw, _ := json.Marshal(report)
	if _, err = f.p.ResolveCheckerBuildReport(f.s, original, raw); err == nil {
		t.Fatal("old wrapper accepted as current signer")
	}
	cmd, err := f.p.ResolveCheckerBuildReport(f.s, current, raw)
	if err != nil {
		t.Fatal(err)
	}
	writes, code = f.p.reduceCheckerBuild(f.s, cmd)
	if code != state.Applied {
		t.Fatal("current signer cannot relay original signed closure", code)
	}
	install("closed-recovery-projection", writes)
	after, err := f.p.Lifecycles(f.s)
	if err != nil {
		t.Fatal(err)
	}
	job, ok := after.BuildJob("tenant", intent.ID)
	if !ok || job.Phase != "closed" || job.Intent.Digest() != intent.Digest() || job.Closure == nil || !bytes.Equal(job.Closure.Signature, closure.Signature) {
		t.Fatal("settlement changed original job or closure")
	}
}
