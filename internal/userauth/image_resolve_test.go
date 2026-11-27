// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestImageResolveRequestCannotCarryOtherScopeOrPrivateInput(t *testing.T) {
	base := Request{Method: "image-resolve", Tenant: "tenant", ImageResolve: &control.ImageResolveQuery{Ref: "alpine:latest"}}
	if !base.validQuerySelectors() || !base.validMethodFields() {
		t.Fatal("typed image resolve rejected")
	}
	for _, edit := range []func(*Request){
		func(q *Request) { q.Tenant = "" }, func(q *Request) { q.After = "cursor" }, func(q *Request) { q.Node = "node-a" },
		func(q *Request) { q.ImageResolve = nil }, func(q *Request) { q.Method = "whoami" },
		func(q *Request) { q.ImageResolve = &control.ImageResolveQuery{} },
		func(q *Request) { q.ImageResolve = &control.ImageResolveQuery{Ref: strings.Repeat("a", 1025)} },
		func(q *Request) { q.ExternalRegistryProbe = &control.ExternalRegistryProbeQuery{ID: "private"} },
	} {
		bad := base
		edit(&bad)
		if bad.validQuerySelectors() {
			t.Fatal("mixed image lookup selector accepted")
		}
	}
	bad := base
	bad.Secret = []byte("private input")
	if bad.validCredentialFields(Envelope{}, 1) {
		t.Fatal("image resolution accepted raw credential")
	}
}
