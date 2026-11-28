// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/imagecache"
)

func TestImageCacheQueryCannotMixTenantNodeOrCursorAuthority(t *testing.T) {
	q := imagecache.Query{Node: "node-a", Images: []string{"sha256:" + strings.Repeat("a", 64)}}
	if !(ImageCachePlanQuery{Query: q}).Valid() || !(ImageCacheStatusQuery{Operation: "original-1"}).Valid() {
		t.Fatal("typed cache query rejected")
	}
	if (ImageCachePlanQuery{Query: imagecache.Query{Operation: "original-1"}}).Valid() || (ImageCacheStatusQuery{}).Valid() {
		t.Fatal("cache plan and status selections mixed")
	}
	for _, raw := range []string{`{"Query":{"Node":"node-a"},"Tenant":"team"}`, `{"Operation":"original-1","Node":"node-a"}`} {
		if strict([]byte(raw), &ImageCachePlanQuery{}) == nil && strict([]byte(raw), &ImageCacheStatusQuery{}) == nil {
			t.Fatal("foreign cache field accepted", raw)
		}
	}
	if strict([]byte(`{"Query":{"Node":"node-a"},"Tenant":"team"}`), &ImageCachePlanQuery{}) == nil {
		t.Fatal("tenant scope accepted on a cluster cache plan")
	}
}

// A server listing its images adds the references of its own running
// tasks to the shared count; that is not a conflict. Fewer is.
func TestImageCacheListingKeepsPrivateReferences(t *testing.T) {
	images := []imagecache.Image{{References: 3}, {References: 0}}
	if !sharedReferencesHeld(images, []uint64{1, 0}) {
		t.Fatal("private references of a running task were a conflict")
	}
	if sharedReferencesHeld(images, []uint64{4, 0}) || sharedReferencesHeld(images, []uint64{1}) {
		t.Fatal("a listing below the shared references was accepted")
	}
}
