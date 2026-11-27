// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registryclient"
)

// These extensions run only in the existing explicitly enabled native fixture,
// with its real user CLI, SFCP/Raft, retained Volume, registry owner and rollback.
// They do not replace that fixture with a simulated ready fact or fake store.
func (f *managedRegistryNative) maintenanceNativeWait(t *testing.T, ctx context.Context, p control.Policy, read func() cluster.View, id, state, code string) control.RegistryMaintenanceRecord {
	t.Helper()
	var result control.RegistryMaintenanceRecord
	registryNativeWait(t, ctx, "original registry maintenance "+id, func() bool {
		jobs, err := p.RegistryMaintenanceJobs(read().State)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		result, found = jobs.Record(id)
		return found && !result.Pending()
	})
	if result.State != state || result.Result == nil || result.Result.Code != code {
		t.Fatal("original maintenance result", result)
	}
	var public control.RegistryMaintenanceStatus
	if err := json.Unmarshal(f.cli(nil, "registry", "maintenance-status", id, "--tenant", "tenant"), &public); err != nil || public.Operation != id || public.State != state || public.Result == nil || public.Result.Code != code {
		// CLI uses exit 3 for failed terminal jobs, so callers of this helper only
		// query successful jobs. The refused-job test below reads via the FSM.
		t.Fatal("public original status", public, err)
	}
	return result
}

func (f *managedRegistryNative) verifyEmptyRegistryMaintenance(t *testing.T, ctx context.Context, p control.Policy, read func() cluster.View) {
	t.Helper()
	var plan control.RegistryMaintenancePlan
	if err := json.Unmarshal(f.cli(nil, "registry", "gc", "private", "--tenant", "tenant", "--preview"), &plan); err != nil || plan.Change.Operation != "" || plan.Change.Run.Generation != f.original.Generation || plan.Change.Run.Ready != nil {
		t.Fatal("real GC preview changed original run", plan, err)
	}
	const id = "rq6-registry-native-empty-gc"
	args := []string{"registry", "gc", "private", "--tenant", "tenant", "--request-id", id}
	f.cli(nil, args...)
	first := f.maintenanceNativeWait(t, ctx, p, read, id, "done", "OK")
	if first.Result.Native == ([32]byte{}) || first.Result.ReclaimedBytes != 0 {
		t.Fatal("empty GC invented reclaimed bytes or omitted native evidence", first)
	}
	f.cli(nil, args...)
	again := f.maintenanceNativeWait(t, ctx, p, read, id, "done", "OK")
	if again.Revision != first.Revision || *again.Result != *first.Result {
		t.Fatal("same signed CLI operation ran GC again", again, first)
	}
	f.public["RegistryRQ6EmptyGCMaintenance"] = id
	f.verifyEmptyRegistryPrune(t, ctx, p, read)
	f.save()
}

func (f *managedRegistryNative) verifyEmptyRegistryPrune(t *testing.T, ctx context.Context, p control.Policy, read func() cluster.View) {
	t.Helper()
	f.verifyEmptyRegistryPruneOperation(t, ctx, p, read, "rq6-registry-native-empty-prune")
}

func (f *managedRegistryNative) verifyEmptyRegistryPruneOperation(t *testing.T, ctx context.Context, p control.Policy, read func() cluster.View, id string) control.RegistryMaintenanceRecord {
	t.Helper()
	root := t.TempDir()
	conditions := filepath.Join(root, "conditions.json")
	if err := os.WriteFile(conditions, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	body := f.cli(nil, "registry", "prune", "private", "--tenant", "tenant", "--conditions", conditions, "--preview")
	var document struct {
		Schema   uint8
		Tenant   string
		Plan     control.RegistryMaintenancePlan
		Items    []control.RegistryPruneRow
		Retained []registryclient.PruneRetained
	}
	if err := json.Unmarshal(body, &document); err != nil || document.Plan.Change.Prune == nil || document.Plan.Change.Prune.Fact.Items != 0 || document.Plan.Change.Prune.Fact.Public != control.RegistryPrunePublicDigest(document.Items, document.Retained) {
		t.Fatal("real signed bulk preview", document, err)
	}
	path := filepath.Join(root, "preview.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"registry", "prune", "private", "--tenant", "tenant", "--preview-file", path, "--request-id", id}
	f.cli(nil, args...)
	first := f.maintenanceNativeWait(t, ctx, p, read, id, "done", "OK")
	if first.Result.Prune == nil || first.Result.Prune.Processed != 0 || first.Result.Prune.GCCode != "" {
		t.Fatal("empty prune invented item/GC effects", first)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// An original result lookup must not require/rebuild an expired preview.
	f.cli(nil, args...)
	again := f.maintenanceNativeWait(t, ctx, p, read, id, "done", "OK")
	if again.Revision != first.Revision || again.Result.Native != first.Result.Native {
		t.Fatal("empty prune reran original", again)
	}
	var results struct {
		Processed uint32
		Items     []control.RegistryPruneRow
	}
	if err := json.Unmarshal(f.cli(nil, "registry", "prune-items", id, "--tenant", "tenant"), &results); err != nil || results.Processed != 0 || len(results.Items) != 0 {
		t.Fatal("original result page", results, err)
	}
	f.public["RegistryRQ6EmptyPruneMaintenance"] = id
	return first
}

func (f *managedRegistryNative) verifyUsedRegistryMaintenance(t *testing.T, ctx context.Context, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	_, digest, ok := strings.Cut(f.reference, "@")
	if !ok {
		t.Fatal("missing original app image digest")
	}
	var plan control.RegistryMaintenancePlan
	if err := json.Unmarshal(f.cli(nil, "registry", "delete-image", "private", "--tenant", "tenant", "--repository", "fixture", "--reference", digest, "--expected-digest", digest, "--preview"), &plan); err != nil || !plan.InUse {
		t.Fatal("actual Task/accepted app missing from deletion preview", plan, err)
	}
	// Deliberately bypass only the CLI advisory check. The authenticated typed
	// action must still be refused by the real owner before any native effect.
	const id = "rq6-registry-native-used-delete"
	payload := plan.Change
	payload.Operation = id
	change(id, "delete-registry-image", plan.Expected, payload)
	var row control.RegistryMaintenanceRecord
	registryNativeWait(t, ctx, "used native registry image refusal", func() bool {
		jobs, err := p.RegistryMaintenanceJobs(read().State)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		row, found = jobs.Record(id)
		return found && !row.Pending()
	})
	if row.State != "failed" || row.Result == nil || row.Result.Code != "IMAGE_IN_USE" || row.Result.ReclaimedBytes != 0 {
		t.Fatal("real owner did not refuse a used image", row)
	}
	if err := p.RegistryPushAvailable(read().State, f.spec); err != nil {
		t.Fatal("known refusal retained admission fence", err)
	}
	secret := f.credential(t, "pull")
	defer clear(secret)
	token := f.token(t, ctx, secret, "repository:fixture:pull")
	if _, _, status := f.request(t, ctx, "GET", "/v2/fixture/manifests/"+digest, token, nil, nil); status != 200 {
		t.Fatal("refusal removed the running app manifest", status)
	}
	f.public["RegistryRQ6UsedImageRefusal"] = id
	f.verifyRegistryContent(t)
	f.save()
}

func (f *managedRegistryNative) verifyRegistryContent(t *testing.T) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "content-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	read := func(kind, digest string) []byte {
		t.Helper()
		if err := file.Truncate(0); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		args := []string{"registry", "content", f.reference, "--kind", kind, "--output-fd", "3", "--tenant", "tenant"}
		if digest != "" {
			args = append(args, "--blob-digest", digest)
		}
		var reply struct {
			Status  string
			Content registryclient.ContentInfo
		}
		if err := json.Unmarshal(f.cli([]*os.File{file}, args...), &reply); err != nil || reply.Status != "content-read" {
			t.Fatal("real content CLI", reply, err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		count, err := io.Copy(hash, file)
		if err != nil || count != reply.Content.Bytes || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != reply.Content.Digest {
			t.Fatal("real owner body/digest", reply, err)
		}
		if kind == "layer" {
			return nil
		}
		if count > 1<<20 {
			t.Fatal("fixture manifest/config exceeds its bounded parsing input")
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(file)
		if err != nil {
			t.Fatal("fixture manifest/config read", err)
		}
		return raw
	}
	manifest, err := v1.ParseManifest(strings.NewReader(string(read("manifest", ""))))
	if err != nil || len(manifest.Layers) == 0 {
		t.Fatal("native fixture image manifest", err)
	}
	read("config", manifest.Config.Digest.String())
	read("layer", manifest.Layers[0].Digest.String())
	f.public["RegistryRQ6ContentRead"] = []string{"manifest", "config", "layer"}
}
