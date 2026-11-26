// SPDX-License-Identifier: Apache-2.0

package app

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/userauth"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func TestLifecycleEditorActualUnixEntryRelaysOriginalSourceToInstalledProvider(t *testing.T) {
	testRealManagedJoin(t, false, "lifecycle-editor")
}

// Same managed join/Raft/MYDCP and actual source DBs, without Docker or a compiler.
func verifyLifecycleEditorRemoteProvider(t *testing.T, ctx context.Context, entry, provider *Runtime, c userauth.Client, peer mydcp.Peer, session access.Session, policy control.Policy, submit func(string, string, uint64, any), root string) {
	t.Helper()
	submit("editor-tenant", "create-tenant", 0, control.TenantID{ID: "editor"})
	view, err := entry.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	users, err := policy.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("editor")
	submit("editor-nodes", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "editor", Nodes: []string{"node-a", "node-b"}})
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	file, err := zw.CreateHeader(&zip.FileHeader{Name: "example.invalid/safe@v1.0.0/safe.go", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("package safe\nconst Ready=true\n")); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	pin := checker.ModulePin{Path: "example.invalid/safe", Version: "v1.0.0", Digest: sha256.Sum256(archive.Bytes()), Length: uint64(archive.Len())}
	p := checker.TenantPolicy{Tenant: "editor", Enabled: true, Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100000000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}}, Resolver: checker.ResolverPolicy{AllowPackages: []string{"context", "example.invalid/safe", "github.com/jay94ks/mydcd/lifecycle/v1"}, SourceCacheBytes: 1 << 20, Modules: []checker.ModulePin{pin}}}
	submit("editor-policy", "set-lifecycle-policy", 0, p)
	data := []byte(`package checker
import("context";lifecycle "github.com/jay94ks/mydcd/lifecycle/v1";"example.invalid/safe")
var noExecution=func()int{panic("source editing must not execute initialization")}()
func Check(ctx context.Context,in lifecycle.Request,probe lifecycle.Probe)(lifecycle.Result,error){
 if !safe.Ready{return lifecycle.Result{Schema:1,Status:lifecycle.Fail},nil}
 return lifecycle.Result{Schema:1,Status:lifecycle.Pass},nil
}
` + strings.Repeat("// original remote UTF-8 원본\n", 2000))
	d := checker.SourceDescriptor{Tenant: "editor", SDK: 1, Digest: sha256.Sum256(data), Length: uint64(len(data)), Modules: []checker.ModulePin{pin}}
	upload := sha256.Sum256([]byte("original remote editor upload"))
	localPeer := peer
	localPeer.Endpoint = "unix://" + filepath.Join(root, "editor-entry.sock")
	if err = entry.Mesh.ListenUnix(strings.TrimPrefix(localPeer.Endpoint, "unix://")); err != nil {
		t.Fatal(err)
	}
	local := c
	local.Mesh, err = mydcp.NewTransport(c.Self, c.Cluster, func(k mydcp.Identity) (mydcp.Peer, bool) { return localPeer, k == localPeer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer local.Mesh.Close()
	local.Peers = []mydcp.Peer{localPeer}
	module, err := local.StageLifecycleModule(ctx, localPeer, session, "node-b", d, upload, checker.ModuleArchive{Pin: pin, ZIP: archive.Bytes()})
	if err != nil || !module.Valid(true) || module.Owner != provider.Identity.Public {
		t.Fatal("Unix entry to original remote module provider", module, err)
	}
	staged, err := local.StageLifecycleSource(ctx, localPeer, session, "node-b", d, upload, data)
	if err != nil || !staged.Valid(false) || staged.Source == nil || staged.Owner != provider.Identity.Public || staged.Node != "node-b" {
		t.Fatal("Unix entry to checked remote source provider", staged, err)
	}
	if _, _, err = entry.checkerSources.SourceArtifact(ctx, d); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("entry duplicated remote provider source", err)
	}
	_, actual, err := provider.checkerSources.SourceArtifact(ctx, d)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatal("provider actual cache bytes", err)
	}
	clear(actual)
	submit("editor-register", "put-lifecycle-script", 0, control.LifecycleScriptPut{Tenant: "editor", Name: "remote", Source: *staged.Source})
	for _, endpoint := range []struct {
		client userauth.Client
		peer   mydcp.Peer
	}{{c, peer}, {local, localPeer}} {
		text, err := endpoint.client.LifecycleSource(ctx, endpoint.peer, session, "editor", "remote", 1)
		if err != nil || text.Source != string(data) || text.Digest != d.Digest {
			t.Fatal("entry reads exact remote registered source", endpoint.peer.Endpoint, err)
		}
	}
	recovered, err := c.RecoverLifecycleSource(ctx, peer, session, "node-b", d, upload)
	if err != nil || recovered.Source == nil || !bytes.Equal(recovered.Source.Signature, staged.Source.Signature) {
		t.Fatal("remote original upload recovery", err)
	}
	recoveredModule, err := local.RecoverLifecycleModule(ctx, localPeer, session, "node-b", d, upload, pin)
	if err != nil || recoveredModule.Module == nil || !bytes.Equal(recoveredModule.Module.Signature, module.Module.Signature) {
		t.Fatal("remote original module recovery", err)
	}
	t.Log("actual Unix User entry -> authenticated installed non-voter provider: locked ZIP/root type checks without init, owner-only source DB, registered original pages via Unix/QUIC member read permits and same upload recovery; no compiler/Docker/health claim")
}
