// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// One actual managed-registry seed push and the existing retained Volume/CLI/
// User/Raft rollback. No app/BuildKit/large payload is replayed. This covers
// managed nonempty prune+selected GC, not external DELETE or a 10 GiB transfer.
func TestRQ6RegistryPruneNonemptyOriginalItemsAndGCNative(t *testing.T) {
	if os.Getenv("SFC_TEST_RQ6_REMAINING") != "prune-nonempty" {
		t.Skip("explicit prune-nonempty remaining scope required")
	}
	if os.Getenv("SFC_TEST_RQ6_IMAGE_BUILD") == "1" || os.Getenv("SFC_TEST_RQ6_LARGE_CONTEXT") == "1" || os.Getenv("SFC_TEST_RQ6_LARGE_REGISTRY") == "1" {
		t.Fatal("prune-nonempty reuses the seed push without build/large opt-ins")
	}
	if os.Getenv("SFC_REGISTRY_TEST_IP") == "" || os.Getenv("SFC_STORAGE_TEST_ROOT") == "" || os.Getenv("SFC_STORAGE_TEST_OWNER") == "" || os.Getenv("SFC_STORAGE_HOST_MOUNT_NS") == "" {
		t.Skip("installed registry IPv4 and owned storage/mount rollback inputs required")
	}
	runManagedAppOwner(t, true, true, true, true, managedAppRegistry, true, false, false)
}

func (f *managedRegistryNative) verifyRegistryPruneNonemptyNative(t *testing.T, ctx context.Context, owner *Runtime, root string, p control.Policy, read func() cluster.View) {
	t.Helper()
	if os.Getenv("SFC_TEST_RQ6_IMAGE_BUILD") == "1" || os.Getenv("SFC_TEST_RQ6_LARGE_CONTEXT") == "1" || os.Getenv("SFC_TEST_RQ6_LARGE_REGISTRY") == "1" {
		t.Fatal("prune-nonempty must finish before unrelated native scopes")
	}
	_, digest, found := strings.Cut(f.reference, "@")
	if !found || owner == nil || f.original.Owner != owner.Identity.Public {
		t.Fatal("original managed owner/seed reference missing")
	}
	checkOriginal := func() {
		t.Helper()
		view := read()
		catalog, err := p.Registries(view.State)
		if err != nil {
			t.Fatal(err)
		}
		entry, ok := catalog.Entry("tenant", "private")
		if !ok || entry.Active == nil || entry.Spec.Node != "node-a" || !sameMaintenanceRun(entry.Active.Reference(), f.original) {
			t.Fatal("prune changed original registry source/run/owner")
		}
		volumes, err := p.Volumes(view.State)
		if err != nil {
			t.Fatal(err)
		}
		creation, ok := volumes.Creation(f.spec.Volume)
		if !ok || creation.Ready == nil || !reflect.DeepEqual(*creation.Ready, f.native) {
			t.Fatal("prune replaced original native Volume")
		}
		if err := p.RegistryPushAvailable(view.State, f.spec); err != nil {
			t.Fatal("settled prune retained registry admission fence", err)
		}
	}
	checkOriginal()
	// This finite scope deliberately has no accepted app/task. Confirm that
	// premise on the actual public usage query, rather than claiming IMAGE_IN_USE
	// coverage. The existing used-image native scope supplies that counterexample.
	var usages struct {
		Schema uint8
		Tenant string
		Root   [32]byte
		Usages []control.ImageUsage
		Next   string
	}
	if err := json.Unmarshal(f.cli(nil, "registry", "usages", f.reference, "--tenant", "tenant"), &usages); err != nil || usages.Schema != 1 || usages.Tenant != "tenant" || usages.Root == ([32]byte{}) || len(usages.Usages) != 0 || usages.Next != "" {
		t.Fatal("seed prune lacks an actual unused-image precondition", err)
	}
	type document struct {
		Schema   uint8
		Tenant   string
		Plan     control.RegistryMaintenancePlan
		Items    []control.RegistryPruneRow
		Retained []registryclient.PruneRetained
	}
	preview := func(name string, conditions registryclient.PruneConditions) (document, []byte) {
		t.Helper()
		path := filepath.Join(root, "prune-nonempty-"+name+"-conditions.json")
		encoded, err := json.Marshal(conditions)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, encoded, 0600); err != nil {
			t.Fatal(err)
		}
		body := f.cli(nil, "registry", "prune", "private", "--tenant", "tenant", "--conditions", path, "--preview")
		var doc document
		if err = json.Unmarshal(body, &doc); err != nil || doc.Schema != 1 || doc.Tenant != "tenant" || doc.Plan.Action != control.RegistryPruneAction || doc.Plan.Cluster != p.Cluster || doc.Plan.InUse || doc.Plan.Change.Operation != "" || doc.Plan.Change.External != nil || doc.Plan.Change.Prune == nil || !doc.Plan.Change.Prune.Valid(p.Cluster, doc.Plan.Change) || doc.Plan.Expected != doc.Plan.Change.ExpectedRevision() || !sameMaintenanceRun(doc.Plan.Change.Run, f.original) {
			t.Fatal("fresh owner-signed managed prune preview lost original scope", err)
		}
		fact := doc.Plan.Change.Prune.Fact
		if fact.Owner != owner.Identity.Public || fact.Public != control.RegistryPrunePublicDigest(doc.Items, doc.Retained) || fact.Conditions != control.PruneConditionsDigest(conditions) || fact.Items != uint32(len(doc.Items)) || fact.Retained != uint32(len(doc.Retained)) || fact.Live || fact.At > uint64(time.Now().Unix()) || uint64(time.Now().Unix())-fact.At > control.RegistryPrunePreviewSeconds {
			t.Fatal("actual preview's fixed public rows/conditions/current owner do not match")
		}
		return doc, body
	}
	// Both fixed conditions protect the ACTUAL seed. Preview is read-only and
	// does not manufacture an accepted zero-item operation or a deletion.
	for _, test := range []struct {
		name, code string
		conditions registryclient.PruneConditions
	}{
		{"protected", "PROTECTED", registryclient.PruneConditions{Repositories: []string{"fixture"}, IncludeUntagged: true, ProtectedDigests: []string{digest}}},
		{"tag", "EXCLUDED_TAG", registryclient.PruneConditions{Repositories: []string{"fixture"}, IncludeUntagged: true, ExcludeTags: []string{"owned"}}},
	} {
		doc, _ := preview(test.name, test.conditions)
		protected := false
		for _, row := range doc.Retained {
			if row.Image.Digest == digest && row.Code == test.code {
				protected = true
			}
		}
		for _, row := range doc.Items {
			if row.Image.Digest == digest {
				t.Fatal("fixed preview condition selected protected seed", test.name)
			}
		}
		if !protected {
			t.Fatal("fixed preview condition did not retain original seed", test.name)
		}
	}
	secret := f.credential(t, "pull")
	defer clear(secret)
	token := f.token(t, ctx, secret, "repository:fixture:pull")
	if _, _, status := f.request(t, ctx, "GET", "/v2/fixture/manifests/"+digest, token, nil, nil); status != 200 {
		t.Fatal("read-only protected previews removed original manifest", status)
	}
	doc, body := preview("selected", registryclient.PruneConditions{Repositories: []string{"fixture"}, IncludeUntagged: true, GC: true})
	if len(doc.Items) == 0 {
		t.Fatal("nonempty prune preview has no actual seed items")
	}
	selected := false
	for _, row := range doc.Items {
		if !row.Valid(false) || row.Image.Repository != "fixture" {
			t.Fatal("preview selected a foreign/invalid image")
		}
		if row.Image.Digest == digest && row.Image.Reference == digest {
			selected = row.Aliases == 1 && row.AliasDigest == registryclient.PruneAliasDigest([]string{"owned"})
		}
	}
	if !selected {
		t.Fatal("nonempty preview omitted original seed digest/complete owned alias")
	}
	const id = "rq6-registry-native-nonempty-prune"
	path := filepath.Join(root, "prune-nonempty-selected-preview.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"registry", "prune", "private", "--tenant", "tenant", "--preview-file", path, "--request-id", id}
	f.public["RegistryRQ6NonemptyPruneOperation"] = id
	f.save()
	f.cli(nil, args...)
	// A completed seed push does not revoke its already issued token. Prove
	// that the original accepted operation waits without deleting, rather than
	// treating the intentionally pending job as an execution timeout. The
	// real token clock and the owner's persisted fence remain authoritative.
	if f.seedPushIssued <= 0 || f.seedPushExpires-f.seedPushIssued != int64(f.spec.TokenSeconds) || f.seedPushExpires <= time.Now().Unix() {
		t.Fatal("actual unexpired seed token required for prune fence premise")
	}
	var pending control.RegistryMaintenanceRecord
	registryNativeWait(t, ctx, "original nonempty prune waiting on push lease", func() bool {
		jobs, err := p.RegistryMaintenanceJobs(read().State)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		pending, found = jobs.Record(id)
		if !found {
			return false
		}
		if !pending.Pending() {
			t.Fatal("nonempty prune terminated before the original push lease expired", pending.State)
		}
		local, err := owner.loadRegistryMaintenance(control.RegistryMaintenanceWork{Operation: id, Change: pending.Change})
		return err == nil && local.Prune != nil && local.Sent && local.Prune.Sent && local.Prune.Next == 0 && local.Result == nil
	})
	store, err := owner.maintenanceStore(pending.Change.Run)
	if err != nil {
		t.Fatal(err)
	}
	owner.registryPruneMu.Lock()
	frozenPending, err := owner.loadRegistryPrunePreview(pending.Change)
	owner.registryPruneMu.Unlock()
	if err != nil || len(frozenPending.Items) == 0 {
		t.Fatal("pending original prune lost frozen items", err)
	}
	deletion, err := registry.PruneImageDelete(id, pending.Change.Authority(), frozenPending.Items[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.DeleteReceipt(ctx, deletion); err != nil || found || time.Now().Unix() >= f.seedPushExpires {
		t.Fatal("native deletion before original push lease expiry or missing live premise", found, err)
	}
	if _, _, status := f.request(t, ctx, "GET", "/v2/fixture/manifests/"+digest, token, nil, nil); status != 200 {
		t.Fatal("pending fenced prune hid original manifest before lease expiry", status)
	}
	f.public["RegistryRQ6NonemptyPrunePendingAt"] = time.Now().Unix()
	f.public["RegistryRQ6NonemptyPrunePendingNoDelete"] = true
	f.save()
	t.Logf("original prune pending without deletion; issued push lease expires at %s", time.Unix(f.seedPushExpires, 0).UTC().Format(time.RFC3339))
	first := f.maintenanceNativeWait(t, ctx, p, read, id, "done", "OK")
	if first.Result == nil || first.Result.At/1000 < uint64(f.seedPushExpires) {
		t.Fatal("original prune settled before issued push lease expiry")
	}
	// Readback has its own current pull credential; the original short-lived
	// pre-wait read token must not be mistaken for a storage failure.
	readSecret := f.credential(t, "pull")
	defer clear(readSecret)
	token = f.token(t, ctx, readSecret, "repository:fixture:pull")
	if first.Origin.VerifyOriginal(p.Cluster) != nil || first.Origin.Change.Action != control.RegistryPruneAction || first.Origin.RequestID != id || first.Change.Prune == nil || !reflect.DeepEqual(*first.Change.Prune, *doc.Plan.Change.Prune) || first.Result.Prune == nil || first.Result.Prune.Processed != uint32(len(doc.Items)) || first.Result.Prune.Deleted != uint32(len(doc.Items)) || first.Result.Prune.Skipped != 0 || first.Result.Prune.Failed != 0 || first.Result.Prune.GCCode != "OK" || first.Result.Prune.GCAt == 0 || !sameMaintenanceRun(first.Change.Run, f.original) {
		t.Fatal("typed nonempty operation lost original preview/selection/terminal result")
	}
	local, err := owner.loadRegistryMaintenance(control.RegistryMaintenanceWork{Operation: id, Change: first.Change})
	if err != nil || local.Prune == nil || local.Prune.Sent || local.Prune.Next != uint32(len(doc.Items)) || local.Owner != owner.Identity.Public || local.Target != first.Change.DigestValue() || !reflect.DeepEqual(local.Result, first.Result) {
		t.Fatal("shared nonempty result differs from original durable owner receipt", err)
	}
	owner.registryPruneMu.Lock()
	frozen, err := owner.loadRegistryPrunePreview(first.Change)
	owner.registryPruneMu.Unlock()
	if err != nil || frozen.Digest() != first.Change.Prune.Fact.Preview || len(frozen.Items) != len(doc.Items) {
		t.Fatal("accepted nonempty prune lost original frozen native selection", err)
	}
	type results struct {
		Schema            uint8
		Tenant, Operation string
		Processed         uint32
		Root              [32]byte
		Items             []control.RegistryPruneRow
	}
	var output results
	if err = json.Unmarshal(f.cli(nil, "registry", "prune-items", id, "--tenant", "tenant"), &output); err != nil || output.Schema != 1 || output.Tenant != "tenant" || output.Operation != id || output.Processed != uint32(len(doc.Items)) || output.Root != control.RegistryPruneResultRoot(local.Target, output.Processed, local.Result) || len(output.Items) != len(doc.Items) {
		t.Fatal("original public nonempty item pages incomplete", err)
	}
	store, err = owner.maintenanceStore(first.Change.Run)
	if err != nil {
		t.Fatal(err)
	}
	nativeItems := make([]registry.ImageDeleteReceipt, 0, len(output.Items))
	for index, row := range output.Items {
		item := frozen.Items[index]
		if !reflect.DeepEqual(control.PrunePublicItem(item), doc.Items[index]) || !row.Valid(true) || row.Code != "OK" || row.Native == ([32]byte{}) {
			t.Fatal("actual nonempty item changed its frozen public selection/result", index)
		}
		selected := row
		selected.Code, selected.At, selected.Native = "", 0, [32]byte{}
		if !reflect.DeepEqual(selected, doc.Items[index]) {
			t.Fatal("result identifies another original item", index)
		}
		raw, err := owner.reports.GetBounded(registryPruneItemKey(id, uint32(index)), 16<<10)
		persisted, decodeErr := schema.Decode[control.RegistryPruneRow](raw)
		if err != nil || decodeErr != nil || !reflect.DeepEqual(persisted, row) {
			t.Fatal("public item differs from original node DB receipt", err, decodeErr)
		}
		deletion, err := registry.PruneImageDelete(id, first.Change.Authority(), item)
		if err != nil {
			t.Fatal(err)
		}
		native, found, err := store.DeleteReceipt(ctx, deletion)
		if err != nil || !found || !native.Valid() || native.State != "deleted" || native.Code != "OK" || native.Request != deletion {
			t.Fatal("original item has no exact managed native DELETE receipt", index, err)
		}
		nativeItems = append(nativeItems, native)
		expected := nativeMaintenanceResult("OK", native.At, native, 0)
		if row.At != expected.At || row.Native != expected.Native {
			t.Fatal("item native witness differs from actual delete transaction", index)
		}
		if _, _, status := f.request(t, ctx, "GET", "/v2/fixture/manifests/"+item.Image.Reference, token, nil, nil); status != 404 {
			t.Fatal("successfully pruned original manifest remains", index, status)
		}
	}
	gc, found, err := store.GCReceipt(ctx, registry.GCRequest{Operation: id, Authority: f.address})
	if err != nil || !found || !gc.Valid() || gc.State != "done" || gc.CompletedAt != first.Result.Prune.GCAt || gc.ReclaimedBytes != first.Result.ReclaimedBytes || gc.ReclaimedBytes <= 0 {
		t.Fatal("selected GC differs from completed actual native receipt", err)
	}
	for _, blob := range gc.Blobs {
		if !blob.Dropped {
			t.Fatal("completed GC retained an unfinished physical deletion")
		}
		if _, _, status := f.request(t, ctx, "HEAD", "/v2/fixture/blobs/"+blob.Digest, token, nil, nil); status != 404 {
			t.Fatal("positively reclaimed GC blob still served", status)
		}
	}
	// The owner adapter must keep the accepted original source/owner, rather
	// than treating a changed native generation as another result location.
	accepted, err := p.RegistryPruneRead(read().State, first.Origin.Session, time.Now().Unix(), "tenant", control.RegistryPruneQuery{Operation: id, Part: "items"}, "", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"owner", "generation", "spec-revision"} {
		bad := accepted
		switch mode {
		case "owner":
			bad.Base.Change.Run.Owner[0] ^= 1
		case "generation":
			bad.Base.Change.Run.Generation++
		case "spec-revision":
			bad.Base.Change.Run.SpecRevision++
		}
		out, err := owner.registryPruneOwner(ctx, bad, true)
		if !errors.Is(err, sfcp.ErrAdmission) || out.Schema != 0 {
			t.Fatal("original result accepted changed source/owner", mode, err)
		}
	}
	checkOriginal()
	// No preview file or fresh preview is needed to recover the original typed
	// operation. Replaying it must leave the native item and GC receipts fixed.
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	f.cli(nil, args...)
	again := f.maintenanceNativeWait(t, ctx, p, read, id, "done", "OK")
	if !reflect.DeepEqual(again, first) {
		t.Fatal("same original nonempty prune changed shared result")
	}
	var replay results
	if err = json.Unmarshal(f.cli(nil, "registry", "prune-items", id, "--tenant", "tenant"), &replay); err != nil || !reflect.DeepEqual(replay, output) {
		t.Fatal("original nonempty item replay changed", err)
	}
	for _, original := range nativeItems {
		again, found, err := store.DeleteReceipt(ctx, original.Request)
		if err != nil || !found || !reflect.DeepEqual(again, original) {
			t.Fatal("original nonempty replay reran an item DELETE", err)
		}
	}
	gcAgain, found, err := store.GCReceipt(ctx, registry.GCRequest{Operation: id, Authority: f.address})
	if err != nil || !found || !reflect.DeepEqual(gcAgain, gc) {
		t.Fatal("original nonempty replay reran selected GC", err)
	}
	checkOriginal()
	f.public["RegistryRQ6NonemptyPruneOperation"], f.public["RegistryRQ6NonemptyPruneResult"] = id, first.Result
	f.public["RegistryRQ6NonemptyPruneItems"], f.public["RegistryRQ6NonemptyPruneGC"] = output.Items, gc
	f.public["RegistryRQ6NonemptyPruneScope"] = "managed seed only; current empty usages and fixed conditions; original item/native receipts and selected GC; no external DELETE, app usage refusal or 10GiB claim"
	f.save()
}
