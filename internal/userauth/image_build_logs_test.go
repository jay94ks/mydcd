// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestBuildLogRequestRejectsMixedSelectorsAndUnboundedPages(t *testing.T) {
	r := ImageBuildLogsQuery{Tenant: "tenant", Query: imagebuild.LogQuery{Job: "build-one", MaxBytes: 4096}}
	if !r.Valid() {
		t.Fatal("valid log query rejected")
	}
	for _, edit := range []func(*ImageBuildLogsQuery){
		func(r *ImageBuildLogsQuery) { r.Tenant = "" },
		func(r *ImageBuildLogsQuery) { r.Query = imagebuild.LogQuery{Job: "build-one", MaxBytes: 0} },
		func(r *ImageBuildLogsQuery) {
			r.Query = imagebuild.LogQuery{Job: "build-one", MaxBytes: 4096, Tail: true}
			r.After = "prior-cursor"
		},
		func(r *ImageBuildLogsQuery) {
			r.Query = imagebuild.LogQuery{Job: "build-one", MaxBytes: imagebuild.MaxLogPageBytes + 1}
		},
	} {
		bad := r
		edit(&bad)
		if bad.Valid() {
			t.Fatal("invalid log query accepted")
		}
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Query":{"Job":"build-one","MaxBytes":4096},"Node":"node-a"}`,
		`{"Tenant":"tenant","Query":{"Job":"build-one","MaxBytes":4096},"ImageBuild":{"Part":"jobs"}}`,
	} {
		if strict([]byte(raw), &ImageBuildLogsQuery{}) == nil {
			t.Fatal("mixed log query accepted", raw)
		}
	}
}

func TestBuildLogTailKeepsOriginalQueryJSONWhenUnselected(t *testing.T) {
	q := imagebuild.LogQuery{Job: "build-one", MaxBytes: 4096}
	raw, err := json.Marshal(q)
	if err != nil || string(raw) != `{"Job":"build-one","MaxBytes":4096}` {
		t.Fatal("old query encoding changed", string(raw), err)
	}
	q.Tail = true
	if !(ImageBuildLogsQuery{Tenant: "tenant", Query: q}).Valid() {
		t.Fatal("tail query refused")
	}
}
