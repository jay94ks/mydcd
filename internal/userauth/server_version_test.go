// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"testing"
)

func TestServerVersionRequestIsFiniteAndSessionlessMetadata(t *testing.T) {
	r := Request{Schema: 1, Method: "server-version", Nonce: [32]byte{1}}
	if !r.validServerVersion() {
		t.Fatal("public exact shape refused")
	}
	for _, change := range []func(*Request){func(q *Request) { q.Tenant = "private" }, func(q *Request) { q.After = "cursor" }, func(q *Request) { q.Node = "node-a" }, func(q *Request) { q.PublicRead = &control.PublicReadQuery{} }} {
		bad := r
		change(&bad)
		if bad.validServerVersion() {
			t.Fatal("foreign selector accepted")
		}
	}
	v := localServerVersion()
	raw, err := json.Marshal(v)
	if err != nil || v.Version != "1" || v.Protocol != 1 || len(raw) > 512 {
		t.Fatal("invalid local version metadata", err)
	}
}
