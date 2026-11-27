// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"github.com/jay94ks/seafield/internal/imagecache"
	"strings"
	"testing"
)

func TestImageCacheQueryCannotMixTenantNodeOrCursorAuthority(t *testing.T) {
	q := imagecache.Query{Node: "node-a", Images: []string{"sha256:" + strings.Repeat("a", 64)}}
	base := Request{Method: "image-cache-plan", ImageCache: &q}
	if !base.validQuerySelectors() {
		t.Fatal("typed cache plan rejected")
	}
	for _, edit := range []func(*Request){func(r *Request) { r.Tenant = "team" }, func(r *Request) { r.Node = "node-a" }, func(r *Request) { r.After = "cursor" }, func(r *Request) { r.Method = "whoami" }, func(r *Request) { r.ImageCache = nil }} {
		bad := base
		edit(&bad)
		if bad.validQuerySelectors() {
			t.Fatal("mixed cache scope accepted")
		}
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
