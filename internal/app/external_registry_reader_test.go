// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/imagesource"
)

func TestSourceReaderFenceRetainsActiveCallsAndRejectsOldGeneration(t *testing.T) {
	r := &Runtime{Identity: &identity.Identity{Public: [32]byte{1}}}
	work := control.ExternalRegistryWork{Reader: control.ExternalRegistryReader{Spec: imagesource.Source{Tenant: "tenant", ID: "private", Authority: "ghcr.io", Repository: "**", Enabled: true, Auth: "none"}, Owner: r.Identity.Public, Generation: 2}}
	release, err := r.acquireExternalReader(work)
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.acquireExternalReader(work)
	if err != nil {
		t.Fatal(err)
	}
	draining := work.Reader
	draining.Draining = true
	if r.fenceExternalReader(draining) {
		t.Fatal("active HTTP/Secret call declared closed")
	}
	if _, err = r.acquireExternalReader(work); err == nil {
		t.Fatal("fenced original reacquired")
	}
	newer := work
	newer.Reader.Generation++
	if _, err = r.acquireExternalReader(newer); err == nil {
		t.Fatal("new generation replaced active old call")
	}
	release()
	release()
	if r.fenceExternalReader(draining) {
		t.Fatal("second call omitted from join")
	}
	second()
	if !r.fenceExternalReader(draining) {
		t.Fatal("actual join never closed")
	}
	if _, err = r.acquireExternalReader(work); err == nil {
		t.Fatal("idle old generation reopened")
	}
	next, err := r.acquireExternalReader(newer)
	if err != nil {
		t.Fatal("explicit next shared generation", err)
	}
	defer next()
	if r.fenceExternalReader(draining) {
		t.Fatal("old closure fenced a newer call")
	}
	if _, err = r.acquireExternalReader(work); err == nil {
		t.Fatal("old permit displaced new generation")
	}
}
