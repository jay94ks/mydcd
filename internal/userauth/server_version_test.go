// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"github.com/jay94ks/seafield/internal/buildinfo"
	"testing"
)

func TestServerVersionRequestIsFiniteAndSessionlessMetadata(t *testing.T) {
	r := Request{Schema: 1, Method: "server-version", Nonce: [32]byte{1}, Params: []byte("{}")}
	if _, typed, ok := r.typedMethod(); !typed || !ok {
		t.Fatal("public exact shape refused")
	}
	for _, change := range []func(*Request){func(q *Request) { q.Tenant = "private" }, func(q *Request) { q.After = "cursor" }, func(q *Request) { q.Node = "node-a" }} {
		bad := r
		change(&bad)
		if _, _, ok := bad.typedMethod(); ok {
			t.Fatal("foreign selector accepted")
		}
	}
	v := localServerVersion()
	raw, err := json.Marshal(v)
	if err != nil || v.Version != buildinfo.Version() || v.Protocol != 1 || len(raw) > 512 {
		t.Fatal("invalid local version metadata", err)
	}
}
