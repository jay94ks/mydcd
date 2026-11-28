// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestDraftRequestRejectsMixedSelectorsAndMutationWithoutProof(t *testing.T) {
	q := imagebuild.DraftRequest{Context: "editable", Kind: "plan"}
	r := BuildDraftQuery{Tenant: "tenant", Request: q}
	if !r.Valid() {
		t.Fatal("draft plan request rejected")
	}
	if (BuildDraftQuery{Request: q}).Valid() {
		t.Fatal("draft without tenant accepted")
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Request":{"Context":"editable","Kind":"plan"},"After":"foreign-cursor"}`,
		`{"Tenant":"tenant","Request":{"Context":"editable","Kind":"plan"},"Node":"other"}`,
		`{"Tenant":"tenant","Request":{"Context":"editable","Kind":"plan"},"Query":{"Part":"tree"}}`,
	} {
		if strict([]byte(raw), &BuildDraftQuery{}) == nil {
			t.Fatal("mixed draft selector accepted", raw)
		}
	}
	bad := q
	bad.Kind = "edit"
	if bad.Valid() {
		t.Fatal("mutation without fixed scope, edit and user proof accepted")
	}
}
