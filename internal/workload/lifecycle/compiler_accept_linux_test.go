// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/moby/client"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/storage"
)

// Actual owner DB/lock, simulated shared phase/authority and fatal SDK HTTP
// transport. No socket or actual container success is claimed.
func TestCheckerCompilerAcceptanceHasNoContainerOrJobDirectoryAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	_, _, intent, _, private := buildJobFixture(t)
	_, policy := compilationFixture(t)
	base := t.TempDir()
	db, err := storage.Open(filepath.Join(base, "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var grants int
	authority := func(_ context.Context, b BuildIntent, recover bool) (CompilerGrant, error) {
		grants++
		if !recover {
			t.Fatal("metadata acceptance/cleanup requested new execution")
		}
		raw, _ := json.Marshal(policy)
		return CompilerGrant{Schema: 1, Job: b.Digest(), Manifest: b.Manifest, Policy: sha256.Sum256(raw), Owner: b.Owner, Phase: "reserved", Revision: 1, Index: 5, DeadlineUnixMilli: b.DeadlineUnixMilli, Recovery: true}, nil
	}
	api, err := client.New(client.WithHost("unix:///nonexistent-sfc-compiler.sock"), client.WithAPIVersion("1.53"), client.WithHTTPClient(&http.Client{Transport: compilerSDKTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("metadata acceptance/never-dispatched cleanup issued native HTTP")
		return nil, errors.New("unexpected native request")
	})}))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	native := &engine.Client{API: api, Owner: engine.Owner(intent.Cluster, intent.Owner)}
	root := filepath.Join(base, "compiler")
	owner, err := OpenCompilerOwner(db, root, intent.Cluster, private, native, authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if owner != nil {
			owner.Close()
		}
	}()
	if _, err := owner.Preparation(intent.Tenant, intent.ID); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("missing original journal not reported", err)
	}
	if err := owner.Accept(ctx, intent, policy); err != nil {
		t.Fatal(err)
	}
	if err := owner.Accept(ctx, intent, policy); err != nil {
		t.Fatal("same original acceptance", err)
	}
	if _, err := os.Stat(filepath.Join(root, "jobs")); !os.IsNotExist(err) || grants != 0 {
		t.Fatal("acceptance created workspace/native authority", err, grants)
	}
	local, err := owner.Preparation(intent.Tenant, intent.ID)
	if err != nil || local.InputReady || local.Closed || local.Cancelled || local.Intent.Digest() != intent.Digest() {
		t.Fatal("local acceptance metadata", err)
	}
	changed := intent.Clone()
	changed.Manifest[0]++
	if err := owner.Accept(ctx, changed, policy); err == nil {
		t.Fatal("same ID changed manifest")
	}
	local.Intent.Inputs[0].Recipe[0]++
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err = OpenCompilerOwner(db, root, intent.Cluster, private, native, authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	local, err = owner.Preparation(intent.Tenant, intent.ID)
	if err != nil || local.Intent.Digest() != intent.Digest() {
		t.Fatal("local clone/reopen lost original intent", err)
	}
	if err := owner.Cancel(intent.Tenant, intent.ID); err != nil {
		t.Fatal(err)
	}
	if err := owner.Step(ctx, intent.Tenant, intent.ID); err != nil {
		t.Fatal("never prepared cancellation", err)
	}
	closure, err := owner.Closure(intent.Tenant, intent.ID)
	if err != nil || closure.Disposition != "never-dispatched" || closure.Verify(intent, "reserved") != nil {
		t.Fatal("reserved no-request closure", err)
	}
	pending, err := owner.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatal("closed local job still scheduled", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err = OpenCompilerOwner(db, root, intent.Cluster, private, native, authority, nil)
	if err != nil {
		t.Fatal(err)
	}
	pending, err = owner.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatal("closed original job requeued on daemon reopen", err)
	}
	if err := owner.Accept(ctx, intent, policy); err != nil {
		t.Fatal("closed original ID metadata", err)
	}
	local, err = owner.Preparation(intent.Tenant, intent.ID)
	if err != nil || !local.Closed || !local.Cancelled {
		t.Fatal("duplicate acceptance reset closure/cancel", err)
	}
}
