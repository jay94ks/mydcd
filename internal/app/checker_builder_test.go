// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/client"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/storage"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

type checkerBuilderNoHTTP struct{ t *testing.T }

func (f checkerBuilderNoHTTP) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Fatal("metadata preparation issued native HTTP")
	return nil, errors.New("unexpected native request")
}

// Actual local DB/owner and the production Runtime preparation method. Shared
// job/phase are simulated; no Engine, quorum, source transfer or native effect.
func TestCheckerBuilderMissingDispatchedJournalCannotBecomeFreshAcceptance(t *testing.T) {
	ctx := context.Background()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{47}, 32))
	public := [32]byte(key.Public().(ed25519.PublicKey))
	cluster := [32]byte{92}
	base := t.TempDir()
	db, err := storage.Open(filepath.Join(base, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	api, err := client.New(client.WithHost("unix:///nonexistent-sfc-compiler.sock"), client.WithAPIVersion("1.53"), client.WithHTTPClient(&http.Client{Transport: checkerBuilderNoHTTP{t}}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	owner, err := checker.OpenCompilerOwner(db, filepath.Join(base, "compiler"), cluster, key, &engine.Client{API: api, Owner: engine.Owner(cluster, public)}, func(context.Context, checker.BuildIntent, bool) (checker.CompilerGrant, error) {
		t.Fatal("local prepare queried native authority")
		return checker.CompilerGrant{}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	source := checker.SourceFact{Schema: 1, Cluster: cluster, Owner: public, Tenant: "tenant", Digest: sha256.Sum256([]byte("package checker\n")), Length: 16, SDK: 1}
	source.Signature = ed25519.Sign(key, checker.SourceFactBytes(source))
	id := sha256.Sum256([]byte("original-job"))
	p := checker.TenantPolicy{Tenant: "tenant", Revision: 1, Enabled: true, Build: checker.BuildPolicy{Nodes: []string{"builder"}, Targets: []string{"linux/amd64"}, Image: "docker.io/library/golang@sha256:" + strings.Repeat("a", 64), Toolchain: "go1.27.3", MaxJobs: 1, NanoCPU: 100000000, MemoryBytes: 64 << 20, WorkspaceBytes: 64 << 20, ArtifactBytes: 32 << 20, TimeoutMS: 10000}, Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}}, Resolver: checker.ResolverPolicy{SourceCacheBytes: 1 << 20}, CompiledCacheBytes: 64 << 20}
	b := checker.BuildIntent{Schema: 1, Cluster: cluster, Tenant: "tenant", ID: hex.EncodeToString(id[:]), AppUseID: "original-app", AppUse: [32]byte{1}, Node: "builder", Owner: public, Selection: checker.Selection{PolicyRevision: 1, Sources: []checker.SourceFact{source}}, Inputs: []checker.BuildInput{{Content: source.ContentDigest(), Recipe: [32]byte{2}}}, Manifest: [32]byte{3}, Target: "linux/amd64", DeadlineUnixMilli: 100000, Image: p.Build.Image}
	if b.Validate() != nil || p.Validate() != nil {
		t.Fatal("invalid fixture")
	}
	r := &Runtime{checkerCompiler: owner}
	cache, err := checker.OpenSources(db, cluster, key)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	r.checkerSources = cache
	book, err := checker.NewCatalog(cluster)
	if err != nil {
		t.Fatal(err)
	}
	if hit, err := r.compilerInputsCached(ctx, book, b); err != nil || hit {
		t.Fatal("empty cache was not a positive miss", err)
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	if hit, err := r.compilerInputsCached(ctx, book, b); err == nil || hit {
		t.Fatal("unavailable cache treated as miss/hit", err)
	}
	job := checker.BuildJob{Intent: b, Phase: "dispatched", Revision: 2}
	if _, err := r.compilerPreparation(ctx, job, p); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("missing dispatched journal recreated", err)
	}
	if _, err := owner.Preparation(b.Tenant, b.ID); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("failed consume wrote a fresh local record", err)
	}
	if _, err := os.Stat(filepath.Join(base, "compiler", "jobs")); !os.IsNotExist(err) {
		t.Fatal("failed consume created workspace", err)
	}
	job.Phase, job.Revision = "reserved", 1
	local, err := r.compilerPreparation(ctx, job, p)
	if err != nil || local.Intent.Digest() != b.Digest() || local.InputReady || local.Cancelled || local.Closed {
		t.Fatal("reserved metadata acceptance", err)
	}
	job.Phase, job.Revision = "dispatched", 2
	if _, err = r.compilerPreparation(ctx, job, p); !errors.Is(err, checker.ErrCompilerOwner) {
		t.Fatal("pre-Stage journal was resumed as dispatched/new preparation", err)
	}
	job.Intent.Manifest[0]++
	if _, err := r.compilerPreparation(ctx, job, p); !errors.Is(err, checker.ErrCompilerOwner) {
		t.Fatal("same ID replaced original local intent", err)
	}
	if _, err := os.Stat(filepath.Join(base, "compiler", "jobs")); !os.IsNotExist(err) {
		t.Fatal("metadata acceptance started preparation/native", err)
	}
}
