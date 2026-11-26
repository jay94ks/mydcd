// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

func imageBuildFixture(t *testing.T) (*nodeStorageFixture, imagebuild.ContextSpec) {
	t.Helper()
	f, registry := registryFixture(t)
	// Build CPU policy uses actual NanoCPU just like real Task reservations;
	// the registry-only fixture deliberately uses tiny abstract test budgets.
	for _, tenant := range []string{"", "tenant"} {
		resources, err := f.p.Resources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		limit, ok := resources.Quotas.Limit(tenant, "node-a")
		if !ok {
			t.Fatal("missing fixture quota")
		}
		expected := limit.Revision
		limit.Revision, limit.Capacity.CPU = 0, 10_000_000_000
		f.apply("admin", "set-node-quota", expected, limit, state.Applied)
	}
	f.apply("manager", "put-registry", 0, RegistryPut{registry}, state.Applied)
	f.apply("admin", "add-node-storage", 0, nodestorage.Definition{Node: "node-a", ID: "hdd", Path: "/mnt/hdd", MaxVolumes: 2, Tenants: []string{"tenant"}}, state.Applied)
	f.observe()
	root := f.root().Reference(f.p.Cluster)
	policy := imagebuild.Policy{Schema: 1, Tenant: "tenant", Nodes: []imagebuild.NodeRoot{{Node: "node-a", Root: root}}, Concurrency: 1, Seconds: 600, CPUMillis: 1000, MemoryBytes: 128 << 20, WorkspaceBytes: 1 << 30, CacheBytes: 1 << 30, Registry: registry.ID, Platforms: []string{"linux/amd64"}, BuilderImage: "docker.io/moby/buildkit@sha256:" + strings.Repeat("a", 64), Cleanup: imagebuild.CleanupPolicy{HighWaterPercent: 80, UnusedDays: 7}}
	f.apply("manager", "set-image-build-policy", 0, ImageBuildPolicyPut{policy}, state.Applied)
	spec := imagebuild.ContextSpec{Tenant: "tenant", ID: "source", Kind: "upload", Root: root, Dockerfile: "Dockerfile", Repository: "team/app", Tags: []string{"context-{version}"}, Platforms: []string{"linux/amd64"}}
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{spec}, state.Applied)
	return f, spec
}
func buildTestPart(t *testing.T, f *nodeStorageFixture, upload string, index uint32, data []byte) ImageBuildUploadPart {
	t.Helper()
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := b.Upload("tenant", upload)
	if !ok {
		t.Fatal("missing upload")
	}
	r := imagebuild.PartReceipt{Schema: 1, Scope: u.Scope.Hash(), Index: index, Length: uint32(len(data)), Digest: sha256.Sum256(data)}
	r.Signature = ed25519.Sign(f.node, imagebuild.PartReceiptBytes(r))
	return ImageBuildUploadPart{Tenant: "tenant", Upload: upload, Receipt: r}
}
func buildTestSeal(t *testing.T, f *nodeStorageFixture, upload string) imagebuild.SealReceipt {
	t.Helper()
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := b.Upload("tenant", upload)
	if !ok {
		t.Fatal("missing upload")
	}
	r := imagebuild.SealReceipt{Schema: 1, Scope: u.Scope.Hash(), ZIP: u.Scope.Digest, Tree: sha256.Sum256([]byte("injected native tree")), Entries: 1, ExpandedBytes: u.Scope.Length}
	r.Signature = ed25519.Sign(f.node, imagebuild.SealReceiptBytes(r))
	return r
}

// Real signatures/reducer/FSM/restore and the reusable upload core; owner ZIP
// facts are injected. This is not a native filesystem, transport or build pass.
func TestImageBuildUploadCASVersionAtomicityAndCreator(t *testing.T) {
	f, _ := imageBuildFixture(t)
	data := bytes.Repeat([]byte{9}, imagebuild.PartBytes+5)
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "upload-one", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	last := buildTestPart(t, f, "upload-one", 1, data[imagebuild.PartBytes:])
	f.apply("admin", "put-build-zip-part", 1, last, state.ConditionFailed)
	f.apply("manager", "put-build-zip-part", 1, last, state.Applied)
	page, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, "tenant", ImageBuildQuery{Part: "missing", Upload: "upload-one"}, "")
	if err != nil || len(page.Missing) != 1 || page.Missing[0] != 0 || page.UploadRevision != 2 {
		t.Fatal("missing page", page, err)
	}
	if _, err := f.p.ImageBuildPage(f.s, f.sessions["admin"], 2, "tenant", ImageBuildQuery{Part: "missing", Upload: "upload-one"}, ""); err == nil {
		t.Fatal("another account reads creator-only progress")
	}
	seal := buildTestSeal(t, f, "upload-one")
	f.apply("manager", "upload-build-zip", 2, ImageBuildZIPConsume{Tenant: "tenant", ID: "source", Upload: "upload-one", Fact: seal}, state.ConditionFailed)
	first := buildTestPart(t, f, "upload-one", 0, data[:imagebuild.PartBytes])
	f.apply("manager", "put-build-zip-part", 2, first, state.Applied)
	f.apply("manager", "upload-build-zip", 3, ImageBuildZIPConsume{Tenant: "tenant", ID: "other", Upload: "upload-one", Fact: seal}, state.ConditionFailed)
	f.apply("manager", "upload-build-zip", 3, ImageBuildZIPConsume{Tenant: "tenant", ID: "source", Upload: "upload-one", Fact: seal}, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := b.Upload("tenant", "upload-one")
	ctx, _ := b.Context("tenant", "source")
	if !u.Closed || u.Received != 0 || u.Version != imagebuild.VersionID(seal) || ctx.NextVersion != 1 || len(b.Versions) != 1 {
		t.Fatal("consume did not atomically create version and close upload")
	}
	for _, obj := range f.s.Objects(buildPartPrefix("tenant", "upload-one")) {
		if obj.Present {
			t.Fatal("consumed part still live")
		}
	}
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "upload-one", Length: 1, Digest: sha256.Sum256([]byte("x")), ExpiresAt: 1000}, state.ConditionFailed)
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("restore lost ownership/version", err)
	}
	versions, err := f.p.ImageBuildPage(restored, f.sessions["manager"], 2, "tenant", ImageBuildQuery{Part: "versions", ID: "source"}, "")
	if err != nil || len(versions.Versions) != 1 {
		t.Fatal(versions, err)
	}
	public, _ := json.Marshal(versions)
	if bytes.Contains(public, []byte("Signature")) || bytes.Contains(public, []byte("Session")) {
		t.Fatal("public page leaks accepted grant")
	}
}

func TestImageBuildPartCASIgnoresUnrelatedRootChangeOnly(t *testing.T) {
	f, spec := imageBuildFixture(t)
	data := []byte("original")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: spec.ID, Upload: "parallel", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	part := buildTestPart(t, f, "parallel", 0, data)
	payload, _ := json.Marshal(part)
	op := UserOperation{Schema: 1, Session: f.sessions["manager"], At: 2, Epoch: f.s.ModuleEpoch(), RequestID: "parallel-part", RootRevision: f.s.Object(ImageBuildKey).Revision, Change: Change{Schema: 1, Principal: "manager", Action: "put-build-zip-part", Expected: 1, Payload: payload}}
	op.Signature = ed25519.Sign(f.manager, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil || cmd.Kind != state.ModuleUpload {
		t.Fatal(err)
	}
	spec.ID = "unrelated"
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{spec}, state.Applied)
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != state.Applied {
		t.Fatal("unrelated context invalidates exact upload CAS", result, err)
	}
	f.s = next
	if len(cmd.Value) > 8<<10 || strings.Contains(cmd.Value, "Data") {
		t.Fatal("raw context bytes entered replicated command")
	}
	slot := f.s.Object(buildPartKey("tenant", "parallel", 0))
	if !slot.Present || slot.Value != hex.EncodeToString(part.Receipt.Digest[:]) {
		t.Fatal("part slot not independently persisted")
	}
	if f.s.Object(buildRecordKey("context", "tenant", spec.ID)).Revision == f.s.Index() {
		t.Fatal("part rewrote unrelated metadata")
	}
}

func TestImageBuildScopeChangesBlockPartButAllowOriginalAbort(t *testing.T) {
	f, spec := imageBuildFixture(t)
	data := []byte("original")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: spec.ID, Upload: "changed", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	part := buildTestPart(t, f, "changed", 0, data)
	spec.Dockerfile = "other/Dockerfile"
	f.apply("manager", "put-build-context", 1, ImageBuildContextPut{spec}, state.Applied)
	f.apply("manager", "put-build-zip-part", 1, part, state.ConditionFailed)
	f.apply("manager", "abort-build-zip-upload", 1, ImageBuildUploadSelection{"tenant", "changed"}, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := b.Upload("tenant", "changed")
	if !u.Closed || u.Version != ([32]byte{}) || u.Scope.Dockerfile != "Dockerfile" {
		t.Fatal("abort retargeted original scope")
	}
	if b.RootReferences(spec.Root) == 0 {
		t.Fatal("abort fabricated native reclamation")
	}
}

func TestImageBuildPagesAreBoundAndNoForeignTenantOrRawInput(t *testing.T) {
	f, spec := imageBuildFixture(t)
	for i := 0; i < 9; i++ {
		spec.ID = fmt.Sprintf("source-%02d", i)
		f.apply("manager", "put-build-context", 0, ImageBuildContextPut{spec}, state.Applied)
	}
	q := ImageBuildQuery{Part: "contexts"}
	page, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, "tenant", q, "")
	if err != nil || len(page.Contexts) != 8 || page.Next == "" {
		t.Fatal("page", page, err)
	}
	next, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, "tenant", q, page.Next)
	if err != nil || len(next.Contexts) != 2 || next.Next != "" {
		t.Fatal("continuation", next, err)
	}
	if _, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, "foreign", q, page.Next); err == nil {
		t.Fatal("cross-tenant cursor accepted")
	}
	spec.ID = "newer"
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{spec}, state.Applied)
	if _, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, "tenant", q, page.Next); err == nil {
		t.Fatal("changed snapshot accepted")
	}
	if _, err := InputChange([]byte(`{"schema":1,"action":"put-build-zip-part","expected":1,"payload":{"Tenant":"tenant","Upload":"source","Index":0,"Data":"c2VjcmV0"}}`), "manager"); err == nil {
		t.Fatal("raw context bytes accepted as Raft change")
	}
}

func TestImageBuildOwnerPermitRequiresExactCreatorProofAndCurrentUploadCAS(t *testing.T) {
	f, _ := imageBuildFixture(t)
	data := []byte("original native bytes")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "io", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := b.Upload("tenant", "io")
	proof := imagebuild.PartProof{Schema: 1, Scope: u.Scope.Hash(), Index: 0, Length: uint32(len(data)), Digest: sha256.Sum256(data), Expected: 1, At: 2, ExpiresAt: 100, Nonce: [32]byte{1}}
	proof.Signature = ed25519.Sign(f.manager, imagebuild.PartProofBytes(proof))
	call := ImageBuildIOCall{Session: f.sessions["manager"], Tenant: "tenant", At: 2, Request: imagebuild.Transfer{Upload: "io", Kind: "part", Expected: 1, Data: data, Proof: &proof}}
	work, err := f.p.ImageBuildIOPermit(f.s, u.Scope.Root.Key, call)
	if err != nil || work.Scope != u.Scope || work.Root.Reference(f.p.Cluster) != u.Scope.Root {
		t.Fatal("original owner permit", work, err)
	}
	if _, err := f.p.ImageBuildIOPermit(f.s, [32]byte{3}, call); err == nil {
		t.Fatal("other installed key serves original root")
	}
	changed := call
	changed.Request.Data = []byte("different raw content")
	if _, err := f.p.ImageBuildIOPermit(f.s, u.Scope.Root.Key, changed); err == nil {
		t.Fatal("member changed creator data")
	}
	changed = call
	changed.Session = f.sessions["admin"]
	if _, err := f.p.ImageBuildIOPermit(f.s, u.Scope.Root.Key, changed); err == nil {
		t.Fatal("another admin adopts upload")
	}
	part := buildTestPart(t, f, "io", 0, data)
	f.apply("manager", "put-build-zip-part", 1, part, state.Applied)
	if _, err := f.p.ImageBuildIOPermit(f.s, u.Scope.Root.Key, call); err == nil {
		t.Fatal("stale upload revision starts native work")
	}
	seal := ImageBuildIOCall{Session: f.sessions["manager"], Tenant: "tenant", At: 2, Request: imagebuild.Transfer{Upload: "io", Kind: "seal", Expected: 2}}
	if _, err := f.p.ImageBuildIOPermit(f.s, u.Scope.Root.Key, seal); err != nil {
		t.Fatal("complete owner seal denied", err)
	}
	f.apply("manager", "abort-build-zip-upload", 2, ImageBuildUploadSelection{"tenant", "io"}, state.Applied)
	if _, err := f.p.ImageBuildIOPermit(f.s, u.Scope.Root.Key, seal); err == nil {
		t.Fatal("closed upload resumes native seal")
	}
}
