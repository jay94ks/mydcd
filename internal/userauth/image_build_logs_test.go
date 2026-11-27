// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestBuildLogRequestRejectsMixedSelectorsAndUnboundedPages(t *testing.T) {
	r := Request{Schema: 1, Method: "image-build-logs", Tenant: "tenant", ImageBuildLog: &imagebuild.LogQuery{Job: "build-one", MaxBytes: 4096}}
	if !r.validMethodFields() || !r.validQuerySelectors() {
		t.Fatal("valid log query rejected")
	}
	for _, edit := range []func(*Request){
		func(r *Request) { r.Method = "image-builds" }, func(r *Request) { r.ImageBuild = &control.ImageBuildQuery{Part: "jobs"} },
		func(r *Request) { r.ImageBuildLog = nil }, func(r *Request) { r.Node = "node-a" }, func(r *Request) { r.Tenant = "" },
		func(r *Request) { r.ImageBuildLog = &imagebuild.LogQuery{Job: "build-one", MaxBytes: 0} },
		func(r *Request) {
			r.ImageBuildLog = &imagebuild.LogQuery{Job: "build-one", MaxBytes: 4096, Tail: true}
			r.After = "prior-cursor"
		},
		func(r *Request) {
			r.ImageBuildLog = &imagebuild.LogQuery{Job: "build-one", MaxBytes: imagebuild.MaxLogPageBytes + 1}
		},
	} {
		bad := r
		edit(&bad)
		if bad.validMethodFields() && bad.validQuerySelectors() {
			t.Fatal("mixed/invalid log query accepted")
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
	r := Request{Schema: 1, Method: "image-build-logs", Tenant: "tenant", ImageBuildLog: &q}
	if !r.validMethodFields() || !r.validQuerySelectors() {
		t.Fatal("tail query refused")
	}
}
