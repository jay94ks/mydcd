// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/storage"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Real offline Go compiler -> native ELF -> actual inherited Probe/result FDs.
// The Probe adapter is a fake; this is not Docker/native Task or OS isolation
// evidence. Run only in L1 final validation after implementation rows 1-5.
func TestCheckerRealFiniteCompilerAndGeneratedCLIUseSameSDKAndProbeFD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	input, policy := compilationFixture(t)
	batch, err := NewCompileBatch(hashText("real-compile-job"), time.Now().Add(2*time.Minute).UnixMilli(), policy, []*Compilation{input})
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	e := CompileEnvironment{Input: filepath.Join(base, "input"), Work: filepath.Join(base, "work"), Output: filepath.Join(base, "output"), GoRoot: runtime.GOROOT()}
	cache := os.Getenv("GOCACHE")
	if cache == "" {
		root, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		cache = filepath.Join(root, "go-build")
	}
	if !filepath.IsAbs(cache) {
		t.Fatal("an existing absolute build cache is required")
	}
	e.Cache = cache // compiler/module caches are intentionally retained
	for _, dir := range []string{e.Input, e.Work, e.Output, e.Cache} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(e.Input)
	if err != nil {
		t.Fatal(err)
	}
	err = WriteCompileBatch(root, batch, []*Compilation{input})
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	report, err := ExecuteCompileBatch(ctx, e)
	if err != nil || len(report.Items) != 1 || report.Items[0].Status != "built" || report.Items[0].Length == 0 {
		t.Fatal("real compiler", err, report)
	}
	item := input.Item()
	data, err := os.ReadFile(filepath.Join(e.Output, hex.EncodeToString(item.Key[:])+".cli"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	request := probeRequest()
	source := item.Source.ContentDigest()
	request.SourceDigest = hex.EncodeToString(source[:])
	clusterBytes, _ := hex.DecodeString(request.Cluster)
	var cluster [32]byte
	copy(cluster[:], clusterBytes)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{157}, 32))
	defer clear(private)
	db, err := storage.Open(filepath.Join(base, "compiled-cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := OpenSources(db, cluster, private)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err = store.Stage(ctx, item.Source, []byte(compileTestSource), policy); err != nil {
		t.Fatal(err)
	}
	// Actual bytes came from the host compiler above. This signed fixture
	// exercises the cache/runner, not a Docker builder's closed-job permit.
	build := CompiledBuild{Schema: 1, Cluster: cluster, Builder: [32]byte(private.Public().(ed25519.PublicKey)), Job: sha256.Sum256([]byte(batch.Job)), ID: batch.Job, Recipe: item.Recipe, Digest: report.Items[0].Digest, Length: report.Items[0].Length}
	build.Signature = ed25519.Sign(private, CompiledBuildBytes(build))
	if _, err = store.StageCompiled(ctx, item.Source, policy, build, data); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"pass", "fail", "probe-error", "cancel-probe", "denied", "revoked-after-check", "recipe-mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			runContext, cancelRun := context.WithCancel(ctx)
			defer cancelRun()
			request.RunID = hashText("cached-compiled/" + scenario)
			request.DeadlineUnixMilli = time.Now().Add(10 * time.Second).UnixMilli()
			calls, permits := 0, 0
			denied := errors.New("current Task denied")
			authorize := func(context.Context) error {
				permits++
				if scenario == "denied" || scenario == "revoked-after-check" && permits == 3 {
					return denied
				}
				return nil
			}
			native := &probeFixture{file: func(c context.Context, q contract.FileProbe) (contract.FileResult, error) {
				calls++
				if q.ContentDigest != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" || q.MaxBytes != 16 {
					return contract.FileResult{}, errors.New("compiled file content query lost")
				}
				if scenario == "cancel-probe" {
					cancelRun()
					<-c.Done()
					return contract.FileResult{}, c.Err()
				}
				if scenario == "probe-error" {
					return contract.FileResult{}, errors.New("unavailable native observation")
				}
				return contract.FileResult{Exists: true, Match: scenario != "fail", Kind: "regular", Mode: 0444}, nil
			}}
			var diagnostic bytes.Buffer
			recipe := item.Recipe
			if scenario == "recipe-mismatch" {
				recipe.Tree[0]++
			}
			value, err := store.RunCachedCompiled(runContext, item.Source, policy, recipe, request, native, authorize, &diagnostic)
			switch scenario {
			case "pass", "fail":
				want := contract.Pass
				if scenario == "fail" {
					want = contract.Fail
				}
				if err != nil || value.Status != want || calls != 1 || permits != 3 || diagnostic.Len() != 0 {
					t.Fatal(value, err, calls, permits, diagnostic.Len())
				}
			case "denied", "revoked-after-check":
				wantCalls := 0
				if scenario == "revoked-after-check" {
					wantCalls = 1
				}
				if !errors.Is(err, denied) || value.Status != contract.Unknown || calls != wantCalls {
					t.Fatal("authority changed execution facts", value, err, calls, permits)
				}
			case "recipe-mismatch":
				if err == nil || value.Status != contract.Unknown || calls != 0 || permits != 1 {
					t.Fatal("different recipe executed", value, err, calls, permits)
				}
			default:
				if err == nil || value.Status != contract.Unknown || calls != 1 {
					t.Fatal("failed/canceled Probe became pass or replayed", value, err, calls)
				}
			}
		})
	}
	entries, err := os.ReadDir(e.Work)
	if err != nil || len(entries) != 0 {
		t.Fatal("compiler scratch retained", err)
	}
}
