// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestRegistryLoginProbeCannotCarryOtherFieldsOrCredentials(t *testing.T) {
	q := control.ExternalRegistryProbeQuery{ID: "private", Image: "ghcr.io/team/app:stable"}
	if !(ExternalRegistryProbeQuery{Tenant: "tenant", Query: q}).Valid() {
		t.Fatal("source login query rejected")
	}
	if (ExternalRegistryProbeQuery{Query: q}).Valid() {
		t.Fatal("login query without a tenant accepted")
	}
	for _, raw := range []string{
		`{"Tenant":"tenant","Query":{"ID":"private"},"Node":"node-a"}`,
		`{"Tenant":"tenant","Query":{"ID":"private"},"Secret":"bm90IGFsbG93ZWQ="}`,
		`{"Tenant":"tenant","Query":{"ID":"private","Node":"node-a"}}`,
	} {
		if strict([]byte(raw), &ExternalRegistryProbeQuery{}) == nil {
			t.Fatal("foreign field accepted", raw)
		}
	}
}

func TestRegistryLoginProbePublicFailureCannotCarryImageOrRawProviderError(t *testing.T) {
	read := control.ExternalRegistryProbeRead{Selection: control.ExternalRegistryReadSelection{Tenant: "tenant", ID: "private", Generation: 2}}
	result := control.ExternalRegistryProbeResult{Selection: read.Selection, Owner: [32]byte{1}, At: 1, Code: "UNAUTHORIZED"}
	if !result.Valid(read) {
		t.Fatal("sanitized 401 observation rejected")
	}
	result.Code = "remote body: private password"
	if result.Valid(read) {
		t.Fatal("raw provider failure accepted")
	}
	result.Code = "OK"
	if !result.Valid(read) {
		t.Fatal("login-only success rejected")
	}
	read.Image = "ghcr.io/team/app:stable"
	if result.Valid(read) {
		t.Fatal("login-only result claimed image pull permission")
	}
	result.Code = "UNAUTHORIZED"
	result.Selection.Generation++
	if result.Valid(read) {
		t.Fatal("other source generation returned")
	}
}
