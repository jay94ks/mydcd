// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestImageResolveRequestCannotCarryOtherScopeOrPrivateInput(t *testing.T) {
	base := ImageResolveQuery{Tenant: "tenant", Query: control.ImageResolveQuery{Ref: "alpine:latest"}}
	if !base.Valid() {
		t.Fatal("typed image resolve rejected")
	}
	for _, bad := range []ImageResolveQuery{
		{Query: base.Query}, {Tenant: "tenant"},
		{Tenant: "tenant", Query: control.ImageResolveQuery{Ref: strings.Repeat("a", 1025)}},
	} {
		if bad.Valid() {
			t.Fatal("invalid image lookup accepted", bad)
		}
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Query":{"Ref":"alpine:latest"},"After":"cursor"}`,
		`{"Tenant":"tenant","Query":{"Ref":"alpine:latest"},"Secret":"cHJpdmF0ZQ=="}`,
	} {
		if strict([]byte(raw), &ImageResolveQuery{}) == nil {
			t.Fatal("foreign image lookup field accepted", raw)
		}
	}
}
