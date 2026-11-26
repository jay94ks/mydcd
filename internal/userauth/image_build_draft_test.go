// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func TestDraftRequestRejectsMixedSelectorsAndMutationWithoutProof(t *testing.T) {
	q := imagebuild.DraftRequest{Context: "editable", Kind: "plan"}
	r := Request{Schema: 1, Method: "build-draft", Tenant: "tenant", Nonce: [32]byte{1}, ImageBuildDraft: &q}
	if !r.validMethodFields() {
		t.Fatal("draft plan request rejected")
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.Method = "whoami" },
		func(r *Request) { r.After = "foreign-cursor" },
		func(r *Request) { r.Node = "other" },
		func(r *Request) { r.ImageBuildContent = &imagebuild.ContentQuery{Version: [32]byte{1}, Part: "tree"} },
		func(r *Request) { r.ImageBuildDraft = nil },
	} {
		bad := r
		mutate(&bad)
		if bad.validMethodFields() {
			t.Fatal("mixed draft selector accepted")
		}
	}
	bad := q
	bad.Kind = "edit"
	if bad.Valid() {
		t.Fatal("mutation without fixed scope, edit and user proof accepted")
	}
}
