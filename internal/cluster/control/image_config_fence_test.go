// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagecache"
)

func TestResolvedConfigFenceRejectsOriginalUnknownBareImageCacheJob(t *testing.T) {
	f, q, owner := registryImageTaskFixture(t)
	id := "sha256:" + strings.Repeat("b", 64)
	q.ConfigID = id
	if _, err := f.p.RegistryImagePermit(f.s, owner, q); err != nil {
		t.Fatal("original task/config gate", err)
	}
	plan := imagecache.Plan{Schema: 1, Cluster: f.p.Cluster, Owner: owner, Boot: [32]byte{1}, Node: "node-a", At: 2500, Index: f.s.Index(), Selection: []string{id}, Images: []imagecache.Image{{ID: id, Bytes: 128}}}
	plan.Signature = ed25519.Sign(f.node, imagecache.PlanBytes(plan))
	if !plan.DeleteReady() {
		t.Fatal("bare config fixture")
	}
	managedDNSChange(t, f, "bare-cache-original", "prune-node-images", 0, imagecache.Change{Operation: "bare-cache", Plan: plan}, state.Applied)
	if _, err := f.p.RegistryImagePermit(f.s, owner, q); err == nil {
		t.Fatal("resolved config escaped original cache admission fence")
	}
	named := q
	named.ConfigID = ""
	if _, err := f.p.RegistryImagePermit(f.s, owner, named); err != nil {
		t.Fatal("config fence was confused with origin/name authorization", err)
	}
	bad := q
	bad.ConfigID = "not-an-image-id"
	if _, err := f.p.RegistryImagePermit(f.s, owner, bad); err == nil {
		t.Fatal("invalid config identity accepted")
	}
	cacheReportCore(t, f, "bare-cache", "begin", nil, state.Applied)
	if _, err := f.p.RegistryImagePermit(f.s, owner, q); err == nil {
		t.Fatal("running/unknown original deletion released config fence")
	}
	cacheReportCore(t, f, "bare-cache", "item", &imagecache.Part{ID: id, State: "already-absent", At: 3000}, state.Applied)
	if _, err := f.p.RegistryImagePermit(f.s, owner, q); err != nil {
		t.Fatal("positively settled original fence not released", err)
	}
}
