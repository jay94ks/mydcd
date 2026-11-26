// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func TestBuildCacheRequestRejectsForeignAndMixedSelectors(t *testing.T) {
	r := Request{Schema: 1, Method: "image-build-cache", Tenant: "tenant", ImageBuildCache: &imagebuild.CacheQuery{Job: "original"}}
	if !r.validMethodFields() || !r.validQuerySelectors() {
		t.Fatal("cache read request rejected")
	}
	for _, edit := range []func(*Request){func(r *Request) { r.Method = "image-builds" }, func(r *Request) { r.Tenant = "" }, func(r *Request) { r.Node = "other" }, func(r *Request) { r.ImageBuildLog = &imagebuild.LogQuery{Job: "original", MaxBytes: 1} }, func(r *Request) { r.ImageBuildCache = &imagebuild.CacheQuery{Job: "../other"} }, func(r *Request) { r.After = "invalid" }, func(r *Request) { r.ImageBuild = &control.ImageBuildQuery{Part: "jobs"} }} {
		bad := r
		edit(&bad)
		if bad.validMethodFields() && bad.validQuerySelectors() {
			t.Fatal("invalid/mixed cache request accepted")
		}
	}
}

func TestBuildCacheScopeRequestRequiresExactlyOneSelectorAndExplicitNode(t *testing.T) {
	cache := [32]byte{1}
	r := Request{Schema: 1, Method: "image-build-cache", Tenant: "tenant", ImageBuildCache: &imagebuild.CacheQuery{Cache: &cache, Node: "node-a"}}
	if !r.validMethodFields() || !r.validQuerySelectors() {
		t.Fatal("valid scope query rejected")
	}
	for _, q := range []imagebuild.CacheQuery{{Job: "original", Cache: &cache, Node: "node-a"}, {Cache: &cache}, {Cache: &[32]byte{}, Node: "node-a"}, {Cache: &cache, Node: "../other"}, {Job: "original", Node: "node-a"}} {
		bad := r
		bad.ImageBuildCache = &q
		if bad.validMethodFields() && bad.validQuerySelectors() {
			t.Fatal("invalid scope query accepted")
		}
	}
}
