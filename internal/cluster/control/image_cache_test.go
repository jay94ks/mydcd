// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagecache"
)

func signedCachePlanCore(t *testing.T, f *backupCoreFixture, alias string) imagecache.Plan {
	t.Helper()
	id := "sha256:" + strings.Repeat("b", 64)
	p := imagecache.Plan{Schema: 1, Cluster: f.p.Cluster, Owner: f.p.TrustRoot, Boot: [32]byte{1}, Node: "node-a", At: 2500, Index: f.s.Index(), Selection: []string{id}, Images: []imagecache.Image{{ID: id, Bytes: 128, Aliases: []string{alias}}}}
	p.Signature = ed25519.Sign(f.node, imagecache.PlanBytes(p))
	if !p.DeleteReady() {
		t.Fatal("invalid signed unused fixture plan")
	}
	return p
}
func cacheReportCore(t *testing.T, f *backupCoreFixture, id, action string, part *imagecache.Part, want state.Code) {
	t.Helper()
	jobs, err := f.p.ImageCacheJobs(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := jobs.Record(id)
	if !ok {
		t.Fatal("original absent")
	}
	r := ImageCacheReport{Schema: 1, Cluster: f.p.Cluster, Owner: row.Plan.Owner, Operation: id, Action: action, Expected: row.Revision, RootRevision: f.s.Object(ImageCacheKey).Revision, Epoch: f.s.ModuleEpoch(), At: 3, Part: part}
	r.Signature = ed25519.Sign(f.node, ImageCacheReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, cmd, want)
}
func TestCacheOriginalReservationsBlockNewAliasesAndSettleExactOwnerResults(t *testing.T) {
	f := newBackupCore(t)
	plan := signedCachePlanCore(t, f, "docker.io/library/proof:latest")
	before, err := f.p.NodeActivity(f.s, plan.Owner)
	if err != nil {
		t.Fatal(err)
	}
	cmd, _ := managedDNSChange(t, f, "cache-original", "prune-node-images", 0, imagecache.Change{Operation: "cache-42", Plan: plan}, state.Applied)
	pending, err := f.p.NodeActivity(f.s, plan.Owner)
	if err != nil || pending.Resources != before.Resources+1 {
		t.Fatal("pending cache missing from owner closure", err)
	}
	if f.p.imageCacheAvailable(f.s, "node-a", "proof:latest") == nil {
		t.Fatal("new alias consumer raced pending cache deletion")
	}
	if f.p.imageCacheAvailable(f.s, "node-b", "proof:latest") != nil {
		t.Fatal("node cache fenced another node's independent Engine")
	}
	managedDNSChange(t, f, "cache-overlap", "prune-node-images", 0, imagecache.Change{Operation: "cache-overlap", Plan: plan}, state.ConditionFailed)
	cacheReportCore(t, f, "cache-42", "begin", nil, state.Applied)
	part := imagecache.Part{ID: plan.Images[0].ID, State: "already-absent", At: 3000}
	cacheReportCore(t, f, "cache-42", "item", &part, state.Applied)
	applyRestartCore(t, f, cmd, state.Applied)
	status, err := f.p.ImageCacheStatus(f.s, f.session, 3, imagecache.Query{Operation: "cache-42"})
	if err != nil || status.State != "done" || len(status.Parts) != 1 || status.Parts[0].State != "already-absent" {
		t.Fatal("original outcome not preserved", err)
	}
	if f.p.imageCacheAvailable(f.s, "node-a", "proof:latest") != nil {
		t.Fatal("settled alias fence not released")
	}
	current, err := f.p.NodeActivity(f.s, plan.Owner)
	if err != nil || current.Resources != before.Resources {
		t.Fatal("settled cache still pins owner", err)
	}
	raw, _ := state.Encode(f.s)
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.ImageCacheJobs(restored); err != nil {
		t.Fatal("snapshot lost original cache plan/results", err)
	}
	public, _ := json.Marshal(status)
	var fields map[string]any
	_ = json.Unmarshal(public, &fields)
	if fields["Origin"] != nil || fields["Session"] != nil {
		t.Fatal("status exposed original grant")
	}
}
func TestCacheProtectsAcceptedTaskBeforeContainerExistsAndCurrentCredentialRevocation(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	managedDNSTaskCoreBegin(t, f, "cache-app", "10.80.1.2", "web")
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	execution, found := apps.Execution("tenant", "cache-app")
	if !found || f.p.imageCacheBlueprintAvailable(f.s, execution.Blueprint()) != nil {
		t.Fatal("task blueprint metadata was parsed as a submitted GoalCommand")
	}
	alias := "docker.io/library/php@sha256:" + strings.Repeat("a", 64)
	plan := signedCachePlanCore(t, f, alias)
	managedDNSChange(t, f, "cache-desired", "prune-node-images", 0, imagecache.Change{Operation: "cache-protected", Plan: plan}, state.ConditionFailed)
	permit, err := f.p.ImageCacheReadPermit(f.s, plan.Owner, 2, ImageCacheRead{Owner: plan.Owner, Index: f.s.Index(), Session: f.session, Query: imagecache.Query{Node: "node-a", Images: plan.Selection}, Images: plan.Images})
	if err != nil || len(permit.References) != 1 || permit.References[0] == 0 {
		t.Fatal("unmaterialized accepted Task not counted", err)
	}
	g := newBackupCore(t)
	unused := signedCachePlanCore(t, g, "docker.io/library/unused:latest")
	managedDNSChange(t, g, "cache-revoke-original", "prune-node-images", 0, imagecache.Change{Operation: "cache-revoked", Plan: unused}, state.Applied)
	restricted := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{164}, ed25519.SeedSize))
	g.replaceOwnKey("key", "restricted", [32]byte(restricted.Public().(ed25519.PublicKey)), []string{"cordon-node"})
	work, err := g.p.ImageCacheWork(g.s, unused.Owner, ImageCacheWorkRequest{Operation: "cache-revoked"})
	if err != nil || work.Allowed {
		t.Fatal("revoked credential authorized deletion", err)
	}
	cacheReportCore(t, g, "cache-revoked", "begin", nil, state.Applied)
	part := imagecache.Part{ID: unused.Images[0].ID, State: "failed", Code: "authority-revoked", At: 3000}
	cacheReportCore(t, g, "cache-revoked", "item", &part, state.Applied)
}
