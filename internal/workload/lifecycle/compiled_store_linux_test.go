// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

// Synthetic ELF and simulated signed builder/native metadata only. These
// fixtures exercise the actual parser/DB/cache; they do not compile or exec Go
// and do not establish real Docker, authority or script semantic correctness.
func compiledTestELF(arch string) []byte {
	code := []byte{0xc3}
	machine := uint16(62)
	if arch == "arm64" {
		machine, code = 183, []byte{0xc0, 0x03, 0x5f, 0xd6}
	}
	b := make([]byte, 4096+len(code))
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], machine)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[24:], 0x400000)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	binary.LittleEndian.PutUint32(b[68:], 5)
	binary.LittleEndian.PutUint64(b[72:], 4096)
	binary.LittleEndian.PutUint64(b[80:], 0x400000)
	binary.LittleEndian.PutUint64(b[88:], 0x400000)
	binary.LittleEndian.PutUint64(b[96:], uint64(len(code)))
	binary.LittleEndian.PutUint64(b[104:], uint64(len(code)))
	binary.LittleEndian.PutUint64(b[112:], 4096)
	copy(b[4096:], code)
	return b
}

func compiledTestBuild(t *testing.T) (CompiledBuild, SourceDescriptor, TenantPolicy, []byte, ed25519.PrivateKey) {
	t.Helper()
	_, _, intent, batch, private := buildJobFixture(t)
	_, policy := compilationFixture(t)
	item := batch.Items[0]
	data := compiledTestELF(item.Recipe.GOARCH)
	build := CompiledBuild{Schema: 1, Cluster: intent.Cluster, Builder: intent.Owner, Job: intent.Digest(), ID: intent.ID, Recipe: item.Recipe, Digest: sha256.Sum256(data), Length: uint64(len(data))}
	build.Signature = ed25519.Sign(private, CompiledBuildBytes(build))
	return build, item.Source, policy, data, private
}

func TestCheckerCompiledReceiverPreservesBuilderAndActualBytesAcrossDBRecovery(t *testing.T) {
	ctx := context.Background()
	build, d, policy, data, _ := compiledTestBuild(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{45}, 32))
	db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, build.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := store.StageCompiled(ctx, d, policy, build, data)
	if err != nil || fact.Verify() != nil || fact.Owner == build.Builder || fact.Build.Builder != build.Builder || !bytes.Equal(fact.Build.Signature, build.Signature) {
		t.Fatal("receiver rewrote builder", err)
	}
	original := fact.Digest()
	fact.Signature[0]++
	fact.Build.Recipe.Flags[0] = "changed"
	actual, read, err := store.CompiledArtifact(ctx, d.Tenant, build.Recipe.Key())
	if err != nil || !bytes.Equal(read, data) || actual.Digest() != original {
		t.Fatal("actual cache bytes/owned fact", err)
	}
	read[len(read)-1] ^= 1
	if _, _, err := store.CompiledArtifact(ctx, "other", build.Recipe.Key()); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("tenant namespace", err)
	}
	other := build.Clone()
	other.ID = hashText("another-build")
	other.Job[0]++
	otherPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, 32))
	other.Signature = ed25519.Sign(otherPrivate, CompiledBuildBytes(other))
	reused, err := store.StageCompiled(ctx, d, policy, other, data)
	if err != nil || reused.Digest() != original || reused.Build.Job != build.Job {
		t.Fatal("cache hit rewrote original provenance", err)
	}
	changed := bytes.Clone(data)
	changed[len(changed)-1] ^= 1
	other.Digest = sha256.Sum256(changed)
	other.Signature = ed25519.Sign(otherPrivate, CompiledBuildBytes(other))
	if _, err := store.StageCompiled(ctx, d, policy, other, changed); !errors.Is(err, ErrCompiledConflict) {
		t.Fatal("different binary replaced recipe", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSources(db, build.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	recovered, err := store.RecoverCompiled(ctx, d.Tenant, build.Recipe.Key())
	if err != nil || recovered.Digest() != original {
		t.Fatal("same DB changed facts", err)
	}
	key := compiledDataPrefix + compiledObjectKey(d.Tenant, build.Recipe.Key())
	if err := db.Write(map[string][]byte{key: changed}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompiledArtifact(ctx, d.Tenant, build.Recipe.Key()); !errors.Is(err, ErrSourceStore) {
		t.Fatal("corrupt bytes used", err)
	}
	if _, err := store.StageCompiled(ctx, d, policy, build, data); !errors.Is(err, ErrSourceStore) {
		t.Fatal("corruption automatically overwritten", err)
	}
	id := compiledObjectKey(d.Tenant, build.Recipe.Key())
	if err := db.Write(map[string][]byte{compiledMetaPrefix + id: nil, compiledDataPrefix + id: nil}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CompiledArtifact(ctx, d.Tenant, build.Recipe.Key()); !errors.Is(err, ErrSourceStore) {
		t.Fatal("known lost metadata/data became positive cache miss", err)
	}
	if _, err := store.StageCompiled(ctx, d, policy, build, data); !errors.Is(err, ErrSourceStore) {
		t.Fatal("known lost original was recreated", err)
	}
}

func TestCheckerCompiledELFAndQuotaFailuresNeverPublishFacts(t *testing.T) {
	build, d, policy, data, private := compiledTestBuild(t)
	if verifyCompileELF(bytes.NewReader(data[:64]), build.Recipe.GOARCH) == nil {
		t.Fatal("ELF header without executable code accepted")
	}
	bad := bytes.Clone(data)
	binary.LittleEndian.PutUint32(bad[64:], 3)
	if verifyCompileELF(bytes.NewReader(bad), build.Recipe.GOARCH) == nil {
		t.Fatal("dynamic interpreter ELF accepted")
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, build.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy.Build.ArtifactBytes, policy.CompiledCacheBytes = uint64(len(data)), uint64(len(data))
	if _, err := store.StageCompiled(context.Background(), d, policy, build, data); !errors.Is(err, ErrCompiledCapacity) || len(store.compiled) != 0 {
		t.Fatal("metadata quota not counted", err)
	}
	orphan := compiledDataPrefix + compiledObjectKey(d.Tenant, build.Recipe.Key())
	if err := db.Write(map[string][]byte{orphan: data}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecoverCompiled(context.Background(), d.Tenant, build.Recipe.Key()); !errors.Is(err, ErrSourceUncertain) {
		t.Fatal("orphan interpreted as missing", err)
	}
}

func collectionTestFixture(t *testing.T) (*SourceStore, CompilerOutput, []byte) {
	t.Helper()
	_, _, intent, batch, private := buildJobFixture(t)
	_, policy := compilationFixture(t)
	base := t.TempDir()
	db, err := storage.Open(filepath.Join(base, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := OpenSources(db, intent.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rootPath := filepath.Join(base, "compiler")
	outputPath := filepath.Join(rootPath, filepath.FromSlash(compilerJobPath(intent)), "output")
	if err := os.MkdirAll(outputPath, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	rootID, err := directoryIdentity(info)
	if err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(filepath.Dir(outputPath))
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := directoryIdentity(info)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: compilerSpec(intent, policy)}})
	state, _, _ = reconcile.Plan(state)
	state, _ = reconcile.Dispatch(state, state.Pending.ID)
	r := compilerDisk{Schema: 1, Intent: intent, Policy: policy, State: state, Directory: jobID, Index: 10, SharedRevision: 2, InputReady: true, CreateDispatched: true, NativeID: hashText("simulated-removed-native"), ImageID: "sha256:" + hashText("simulated-image"), StartDispatched: true, Exited: true, Removed: true, CollectionDispatched: true}
	metadata, _ := json.Marshal(r)
	identity, _ := json.Marshal(compilerOwnerIdentity{1, intent.Cluster, intent.Owner, rootPath, rootID})
	if err := db.Write(map[string][]byte{compilerPrefix + "identity": identity, compilerRecordPrefix + compilerJobKey(intent): metadata}); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	data := compiledTestELF(batch.GOARCH)
	key := batch.Items[0].Key
	name := hex.EncodeToString(key[:]) + ".cli"
	if err := os.WriteFile(filepath.Join(outputPath, name), data, 0500); err != nil {
		t.Fatal(err)
	}
	report := CompileReport{Schema: 1, Job: intent.ID, Tenant: intent.Tenant, Items: []CompileArtifact{{Key: key, Digest: sha256.Sum256(data), Length: uint64(len(data)), Status: "built", Reason: "compiled"}}}
	raw, _ := json.Marshal(report)
	if err := os.WriteFile(filepath.Join(outputPath, "report.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	diagnostic := []byte("private checker.go compiler warning\n")
	if err := os.WriteFile(filepath.Join(outputPath, hex.EncodeToString(key[:])+".diagnostic"), diagnostic, 0600); err != nil {
		t.Fatal(err)
	}
	return store, CompilerOutput{Intent: intent, Policy: policy, Batch: batch, ExitKnown: true, ExitCode: 0, Root: root}, diagnostic
}

func TestCheckerCompilerCollectionAtomicallyRetainsOriginalReceiptAndDiagnostics(t *testing.T) {
	store, output, diagnostic := collectionTestFixture(t)
	ctx := context.Background()
	root, err := store.CollectCompiled(ctx, output)
	if err != nil {
		t.Fatal("collection", err)
	}
	c, err := store.CompiledCollection(ctx, output.Intent.Tenant, output.Intent.Digest())
	if err != nil || c.Verify() != nil || c.Digest() != root || c.Outcome != "complete" || len(c.Items) != 1 || c.Items[0].Status != "cached" {
		t.Fatal("actual signed DB receipt", err)
	}
	owner := &CompilerOwner{db: store.db, identity: compilerOwnerIdentity{Cluster: output.Intent.Cluster, Node: output.Intent.Owner}}
	artifacts, err := owner.collectedArtifacts(compilerDisk{Intent: output.Intent}, root)
	if err != nil || len(artifacts) != 1 || artifacts[0].Key != output.Batch.Items[0].Key || artifacts[0].Digest != sha256.Sum256(compiledTestELF(output.Batch.GOARCH)) {
		t.Fatal("closure lost collector's exact artifact commitment", err)
	}
	if _, err := owner.collectedArtifacts(compilerDisk{Intent: output.Intent}, [32]byte{99}); err == nil {
		t.Fatal("different collector receipt adopted")
	}
	text, err := store.CompiledDiagnostic(ctx, c.Tenant, c.Job, c.Items[0].Key)
	if err != nil || !bytes.Equal(text, diagnostic) {
		t.Fatal("private diagnostic lost", err)
	}
	output.Recover = true
	if err := output.Root.Remove("report.json"); err != nil {
		t.Fatal(err)
	}
	again, err := store.CollectCompiled(ctx, output)
	if err != nil || again != root || len(store.compiled) != 1 {
		t.Fatal("lost receipt resumed as a new result", err)
	}
	other, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	output.Root = other
	if _, err := store.CollectCompiled(ctx, output); !errors.Is(err, ErrSourceStore) {
		t.Fatal("different output root adopted", err)
	}
}

func TestCheckerCompilerInvalidArtifactProducesFailureReceiptWithoutCacheReady(t *testing.T) {
	store, output, _ := collectionTestFixture(t)
	name := hex.EncodeToString(output.Batch.Items[0].Key[:]) + ".cli"
	f, err := output.Root.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0500)
	if err != nil { // original 0500 file is intentionally read-only
		if err := output.Root.Chmod(name, 0700); err != nil {
			t.Fatal(err)
		}
		f, err = output.Root.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0500)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("invalid")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	root, err := store.CollectCompiled(context.Background(), output)
	if err != nil {
		t.Fatal(err)
	}
	c, err := store.CompiledCollection(context.Background(), output.Intent.Tenant, output.Intent.Digest())
	if err != nil || c.Digest() != root || c.Outcome != "failed" || c.Items[0].Reason != "artifact-invalid" || len(store.compiled) != 0 {
		t.Fatal("invalid artifact made Ready", err)
	}
}

// Expiration prevents a new compiler job, not consumption of already complete
// bytes. The original ID/deadline is retained by the actual private store.
func TestExpiredPreparationCanSealOnlyCompleteLocalCacheWithoutNewJob(t *testing.T) {
	ctx := context.Background()
	book, _, intent, batch, private := buildJobFixture(t)
	build, descriptor, policy, data, _ := compiledTestBuild(t)
	on := true
	frozen, err := FreezeProgram("tenant", Program{Scripts: map[string]Script{"compiled": {Source: compileTestSource, Compile: &on}}, Services: map[string][]Check{"web": {{ID: "ready", Phase: "readiness", Template: Template{Script: "compiled"}}}}}, book, map[string]SourceFact{"compiled": intent.Selection.Sources[0]}, programDefaults())
	if err != nil {
		t.Fatal(err)
	}
	program, err := frozen.Task("web")
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, intent.Cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.Stage(ctx, descriptor, []byte(compileTestSource), policy); err != nil {
		t.Fatal(err)
	}
	target := ResolverTarget{GOOS: batch.GOOS, GOARCH: batch.GOARCH, Toolchain: batch.Toolchain}
	if _, err = store.CachedTaskCompilePlan(ctx, program, policy, target); err == nil {
		t.Fatal("missing binary became a complete plan")
	}
	if _, err = store.StageCompiled(ctx, descriptor, policy, build, data); err != nil {
		t.Fatal(err)
	}
	plan, err := store.CachedTaskCompilePlan(ctx, program, policy, target)
	if err != nil || plan.Build != nil || len(plan.Recipes) != 1 {
		t.Fatal("cache hit needs a new build", err)
	}
	prep := TaskPreparation{Schema: 1, Cluster: intent.Cluster, Owner: intent.Owner, Use: [32]byte{9}, Program: checkerProgramDigestForTest(program), SDK: CompileSDKDigest(), Tenant: "tenant", UseID: "original", Target: batch.GOOS + "/" + batch.GOARCH, DeadlineUnixMilli: 1}
	prep, err = store.BeginTaskPreparation(ctx, prep)
	if err != nil {
		t.Fatal(err)
	}
	id := prep.ID()
	prep.Plan = &plan
	prep, err = store.SealTaskPreparation(ctx, prep)
	if err != nil || prep.ID() != id || prep.DeadlineUnixMilli != 1 || prep.Plan.Build != nil {
		t.Fatal("expired scope/deadline replaced", err)
	}
}
func checkerProgramDigestForTest(p TaskProgram) [32]byte {
	raw, _ := json.Marshal(p)
	return sha256.Sum256(raw)
}
