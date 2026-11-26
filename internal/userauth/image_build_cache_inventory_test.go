// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestCacheInventoryRequestKeepsNodeFilterInsideItsTypedRead(t *testing.T) {
	r := Request{Schema: 1, Method: "image-builds", Tenant: "tenant", ImageBuild: &control.ImageBuildQuery{Part: "caches", Node: "node-a", ID: "source"}}
	if !r.validMethodFields() || !r.validQuerySelectors() {
		t.Fatal("valid cache inventory rejected")
	}
	for _, edit := range []func(*Request){func(r *Request) { r.Node = "node-a" }, func(r *Request) { r.ImageBuild = &control.ImageBuildQuery{Part: "jobs", Node: "node-a"} }, func(r *Request) { r.ImageBuild = &control.ImageBuildQuery{Part: "caches", Job: "other"} }, func(r *Request) { r.ImageBuild = &control.ImageBuildQuery{Part: "caches", Upload: "other"} }, func(r *Request) { r.ImageBuild = &control.ImageBuildQuery{Part: "caches", Node: "../other"} }} {
		bad := r
		edit(&bad)
		if bad.validMethodFields() && bad.validQuerySelectors() {
			t.Fatal("mixed/foreign cache selector accepted")
		}
	}
}
