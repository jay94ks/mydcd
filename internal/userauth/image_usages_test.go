// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestImageUsageSelectorsKeepTenantCursorAndSourceFieldsSeparate(t *testing.T) {
	base := Request{Method: "image-usages", Tenant: "tenant", ImageUsage: &control.ImageUsageQuery{Refs: []string{"alpine:latest"}}}
	if !base.validQuerySelectors() || !base.validMethodFields() {
		t.Fatal("typed image usages query rejected")
	}
	for _, edit := range []func(*Request){
		func(q *Request) { q.Tenant = "" }, func(q *Request) { q.Node = "node-a" }, func(q *Request) { q.After = "not-a-cursor" },
		func(q *Request) { q.ImageUsage = nil }, func(q *Request) { q.Method = "image-resolve" },
		func(q *Request) { q.ImageUsage = &control.ImageUsageQuery{ExternalSource: "../private"} },
		func(q *Request) {
			q.ImageUsage = &control.ImageUsageQuery{Refs: []string{"alpine", "docker.io/library/alpine:latest"}}
		},
		func(q *Request) { q.ImageUsage = &control.ImageUsageQuery{Refs: []string{strings.Repeat("a", 1025)}} },
	} {
		bad := base
		edit(&bad)
		if bad.validQuerySelectors() {
			t.Fatal("mixed/invalid reference query accepted")
		}
	}
	q := control.ImageUsageQuery{ExternalSource: "source"}
	if !q.Valid() {
		t.Fatal("source-only usage read rejected")
	}
}
