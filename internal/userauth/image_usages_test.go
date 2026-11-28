// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestImageUsageSelectorsKeepTenantCursorAndSourceFieldsSeparate(t *testing.T) {
	base := ImageUsagesQuery{Tenant: "tenant", Query: control.ImageUsageQuery{Refs: []string{"alpine:latest"}}}
	if !base.Valid() {
		t.Fatal("typed image usages query rejected")
	}
	for _, edit := range []func(*ImageUsagesQuery){
		func(q *ImageUsagesQuery) { q.Tenant = "" }, func(q *ImageUsagesQuery) { q.After = "not-a-cursor" },
		func(q *ImageUsagesQuery) { q.Query = control.ImageUsageQuery{ExternalSource: "../private"} },
		func(q *ImageUsagesQuery) {
			q.Query = control.ImageUsageQuery{Refs: []string{"alpine", "docker.io/library/alpine:latest"}}
		},
		func(q *ImageUsagesQuery) {
			q.Query = control.ImageUsageQuery{Refs: []string{strings.Repeat("a", 1025)}}
		},
	} {
		bad := base
		edit(&bad)
		if bad.Valid() {
			t.Fatal("mixed/invalid reference query accepted")
		}
	}
	if strict([]byte(`{"Tenant":"tenant","Query":{"Refs":["alpine:latest"]},"Node":"node-a"}`), &ImageUsagesQuery{}) == nil {
		t.Fatal("foreign usage field accepted")
	}
	q := control.ImageUsageQuery{ExternalSource: "source"}
	if !q.Valid() {
		t.Fatal("source-only usage read rejected")
	}
}
