// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
)

func TestRealBoundaryManagedInstalledSecretFiles(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppLocalSecrets, true, true)
}

func installManagedSecretFiles(t *testing.T, cfg *config.Node, root string) {
	t.Helper()
	installed := filepath.Join(root, "installed-files")
	for _, revision := range []uint64{1, 2} {
		dir := filepath.Join(installed, "tenant/data", strconv.FormatUint(revision, 10))
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(map[string]any{"schema": 1, "profile": "values", "object": "tenant/data", "revision": revision, "keys": []string{"DB_PASSWORD"}})
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		value := "private-db-value"
		if revision == 2 {
			value = "must-not-use-latest"
		}
		if err := os.WriteFile(filepath.Join(dir, "key-DB_PASSWORD"), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i, p := range cfg.Vaults {
		if p.Profile == "values" {
			cfg.Vaults[i] = config.VaultBackend{Mode: "local-file", Realm: p.Realm, Profile: p.Profile, Root: installed, Prefix: p.Prefix, Values: true}
		}
	}
}

func verifyManagedSecretFiles(t *testing.T, ctx context.Context, r *Runtime, cfg config.Node, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) map[string]any {
	t.Helper()
	a, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := a.Execution("tenant", "app")
	stage, _ := e.Stage(deployment.ResourceKey("task", "tenant", "app", "web"))
	ref := deployment.ObjectRef{Key: stage.Command.Key, Generation: stage.Result.Generation, Revision: stage.Result.Revision}
	b, _ := a.Binding(ref)
	request := control.AppBindingRequest{Task: ref, Digest: b.Digest(), At: time.Now().Unix()}
	permit, err := r.appInputPermit(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	q := control.AppInputFetch{Schema: 1, Consumer: r.Identity.Public, Binding: request, ReadSet: permit.ReadSet, MinimumIndex: permit.CommandIndex, Realm: "tenant", Secret: "data"}
	value, err := r.readAppInputLeaf(ctx, q)
	if err != nil || string(value.Values["DB_PASSWORD"]) != "private-db-value" {
		t.Fatal("actual approved installed original read", err)
	}
	for _, v := range value.Values {
		clear(v)
	}
	backend := r.vaultBackends["tenant/values"]
	if backend.writer != nil || backend.verifier != nil || backend.config.Mode != "local-file" {
		t.Fatal("read-only file source gained Vault writer")
	}
	file := filepath.Join(backend.config.Root, "tenant/data/1/key-DB_PASSWORD")
	if err := os.Rename(file, file+"-held"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := os.Stat(file + "-held"); err == nil {
			_ = os.Rename(file+"-held", file)
		}
	}()
	if value, err := r.readAppInputLeaf(ctx, q); err == nil || len(value.Values) != 0 {
		t.Fatal("missing original file used latest/Vault/projection fallback")
	}
	status, err := r.workload.Status(ctx, ref.Key)
	if err != nil || !status.Running || status.NativeID != stage.Observation.Native {
		t.Fatal("failed new read removed live original Task", err)
	}
	if err := os.Rename(file+"-held", file); err != nil {
		t.Fatal(err)
	}
	restored, err := r.readAppInputLeaf(ctx, q)
	if err != nil || string(restored.Values["DB_PASSWORD"]) != "private-db-value" {
		t.Fatal("restored original file before independent mode refusal", err)
	}
	for _, v := range restored.Values {
		clear(v)
	}
	current, _ := p.Vault(read().State)
	profile, _ := current.Trees["tenant"].WriteProfile("values")
	previous := profile.Revision
	profile.Mode, profile.Revision = "", 0
	change("file-source-mode-mismatch", "vault-set-profile", current.Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: profile})
	// A newly authorized read-set still cannot reinterpret the installed file
	// profile as a Vault source. Both current profile and installation must agree.
	permit, err = r.appInputPermit(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	q.ReadSet, q.MinimumIndex = permit.ReadSet, permit.CommandIndex
	if _, err := r.readAppInputLeaf(ctx, q); err == nil {
		t.Fatal("provider mode mismatch accepted")
	}
	current, _ = p.Vault(read().State)
	profile.Mode, profile.Revision = "local-file", 0
	change("file-source-mode-restore", "vault-set-profile", current.Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: profile})
	current, _ = p.Vault(read().State)
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := current.Trees["tenant"].PlanWrite(catalog, "admin", "file-write-denied", "data", "values", secrets.ValueWrite, nil); err == nil {
		t.Fatal("installed file profile allowed runtime provider write")
	}
	t.Log("actual CLI approved Group and native Task read fixed installed value1 despite successor2; missing original read refused with no Vault/latest/projection fallback and original running ID retained; current profile mode mismatch denied; same DB and original native termination/whole reference return follow")
	return map[string]any{"provider": "local-file", "fixed_revision": 1, "successor_revision": 2, "native_id": status.NativeID, "profile_before": previous, "missing_original_refused": true, "mode_mismatch_refused": true}
}
