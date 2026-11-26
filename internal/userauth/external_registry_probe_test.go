// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestRegistryLoginProbeCannotMixOtherSelectorsOrCredentials(t *testing.T) {
	q := control.ExternalRegistryProbeQuery{ID: "private", Image: "ghcr.io/team/app:stable"}
	base := Request{Method: "registry-login-test", Tenant: "tenant", ExternalRegistryProbe: &q}
	if !base.validQuerySelectors() {
		t.Fatal("source login query rejected")
	}
	for _, edit := range []func(*Request){
		func(r *Request) { r.Tenant = "" },
		func(r *Request) { r.Node = "node-a" },
		func(r *Request) { r.After = "cursor" },
		func(r *Request) { r.Method = "external-registries" },
		func(r *Request) { r.ExternalRegistryProbe = nil },
		func(r *Request) {
			r.ExternalRegistryBind = &control.ExternalRegistryBindQuery{ID: "private", Node: "node-a"}
		},
	} {
		bad := base
		edit(&bad)
		if bad.validQuerySelectors() {
			t.Fatal("foreign source/Secret selector accepted")
		}
	}
	bad := base
	bad.Secret = []byte("not allowed")
	if bad.validCredentialFields(Envelope{}, 1) {
		t.Fatal("registry query accepted raw login Secret")
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
