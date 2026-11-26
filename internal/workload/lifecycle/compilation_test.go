// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const compileTestSource = `package checker
import (
 "context"
 lifecycle "github.com/jay94ks/mydcd/lifecycle/v1"
)
func Check(ctx context.Context, in lifecycle.Request, probe lifecycle.Probe) (lifecycle.Result,error) {
 r,err := probe.File(ctx,lifecycle.FileProbe{Service:"web",Path:"/ready",Kind:"regular",ContentDigest:"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",MaxBytes:16})
 if err != nil { return lifecycle.Result{Schema:1,Status:lifecycle.Unknown,Reason:"probe-error"},err }
 if !r.Match { return lifecycle.Result{Schema:1,Status:lifecycle.Fail,Reason:"not-ready"},nil }
 return lifecycle.Result{Schema:1,Status:lifecycle.Pass,Reason:"ready"},nil
}
`

func compilationFixture(t *testing.T) (*Compilation, TenantPolicy) {
	t.Helper()
	policy := sourcePolicy()
	policy.Build = BuildPolicy{Nodes: []string{"builder"}, Targets: []string{runtime.GOOS + "/" + runtime.GOARCH}, Image: "docker.io/library/golang@sha256:" + strings.Repeat("a", 64), Toolchain: runtime.Version(), MaxJobs: 1, NanoCPU: 100000000, MemoryBytes: 512 << 20, WorkspaceBytes: 512 << 20, ArtifactBytes: 32 << 20, TimeoutMS: 120000}
	policy.CompiledCacheBytes = 64 << 20
	d := SourceDescriptor{Tenant: "tenant", SDK: 1, Digest: sha256.Sum256([]byte(compileTestSource)), Length: uint64(len(compileTestSource))}
	source, err := ResolveSource(context.Background(), policy, d, []byte(compileTestSource), nil, ResolverTarget{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Toolchain: runtime.Version()})
	if err != nil {
		t.Fatal(err)
	}
	input, err := PrepareCompilation(source)
	if err != nil {
		t.Fatal(err)
	}
	return input, policy
}

func TestCheckerCompilationSharesExactProductSDKAndSealedTree(t *testing.T) {
	input, policy := compilationFixture(t)
	item := input.Item()
	if !validCompileItem(item) || item.Key != item.Recipe.Key() || !bytes.Contains(input.files[compileMainPath], []byte("RunCompiled")) {
		t.Fatal("compiled recipe")
	}
	for path, data := range trustedCompileSources() {
		if !bytes.Equal(input.files[path], data) {
			t.Fatal("a second SDK/validator was emitted", path)
		}
	}
	item.Recipe.Flags[0] = "changed"
	item.Files[0].Path = "../outside.go"
	if !validCompileItem(input.Item()) {
		t.Fatal("manifest aliases original compilation")
	}
	batch, err := NewCompileBatch(hashText("compile-job"), time.Now().Add(time.Minute).UnixMilli(), policy, []*Compilation{input, input})
	if err != nil || len(batch.Items) != 1 {
		t.Fatal("same recipe did not deduplicate", err)
	}
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := WriteCompileBatch(root, batch, []*Compilation{input}); err != nil {
		t.Fatal(err)
	}
	if err := WriteCompileBatch(root, batch, []*Compilation{input}); err == nil {
		t.Fatal("accepted compiler input overwritten")
	}
	if _, err := os.Stat(filepath.Join(rootPath, "manifest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestCheckerCompileManifestRejectsRootSDKFlagsAndPathSubstitution(t *testing.T) {
	input, _ := compilationFixture(t)
	for _, change := range []func(*CompileItem){
		func(i *CompileItem) {
			i.Source.Digest[0]++
			i.Recipe.Source = i.Source.ContentDigest()
			i.Key = i.Recipe.Key()
		},
		func(i *CompileItem) { i.Recipe.SDK[0]++; i.Key = i.Recipe.Key() },
		func(i *CompileItem) { i.Recipe.Flags[0] = "generate"; i.Key = i.Recipe.Key() },
		func(i *CompileItem) { i.Files[0].Path = "../host.go" },
		func(i *CompileItem) { i.Files[0].Length++ },
	} {
		item := input.Item()
		change(&item)
		if validCompileItem(item) {
			t.Fatal("altered compile input accepted")
		}
	}
}
