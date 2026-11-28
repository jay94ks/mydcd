// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestBuildCacheRequestRejectsForeignAndMixedSelectors(t *testing.T) {
	q := ImageBuildCacheQuery{Tenant: "tenant", Query: imagebuild.CacheQuery{Job: "original"}}
	if !q.Valid() {
		t.Fatal("cache read request rejected")
	}
	for _, edit := range []func(*ImageBuildCacheQuery){func(q *ImageBuildCacheQuery) { q.Tenant = "" }, func(q *ImageBuildCacheQuery) { q.Query = imagebuild.CacheQuery{Job: "../other"} }, func(q *ImageBuildCacheQuery) { q.After = "invalid" }} {
		bad := q
		edit(&bad)
		if bad.Valid() {
			t.Fatal("invalid cache request accepted")
		}
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Query":{"Job":"original"},"Node":"other"}`,
		`{"Tenant":"tenant","Query":{"Job":"original"},"Log":{"Job":"original","MaxBytes":1}}`,
	} {
		if strict([]byte(raw), &ImageBuildCacheQuery{}) == nil {
			t.Fatal("foreign cache field accepted", raw)
		}
	}
}

func TestBuildCacheScopeRequestRequiresExactlyOneSelectorAndExplicitNode(t *testing.T) {
	cache := [32]byte{1}
	r := ImageBuildCacheQuery{Tenant: "tenant", Query: imagebuild.CacheQuery{Cache: &cache, Node: "node-a"}}
	if !r.Valid() {
		t.Fatal("valid scope query rejected")
	}
	for _, q := range []imagebuild.CacheQuery{{Job: "original", Cache: &cache, Node: "node-a"}, {Cache: &cache}, {Cache: &[32]byte{}, Node: "node-a"}, {Cache: &cache, Node: "../other"}, {Job: "original", Node: "node-a"}} {
		bad := r
		bad.Query = q
		if bad.Valid() {
			t.Fatal("invalid scope query accepted")
		}
	}
}
