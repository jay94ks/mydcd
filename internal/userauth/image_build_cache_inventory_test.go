// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestCacheInventoryRequestKeepsNodeFilterInsideItsTypedRead(t *testing.T) {
	q := ImageBuildsQuery{Tenant: "tenant", Query: control.ImageBuildQuery{Part: "caches", Node: "node-a", ID: "source"}}
	if !q.Valid() {
		t.Fatal("valid cache inventory rejected")
	}
	for _, query := range []control.ImageBuildQuery{{Part: "jobs", Node: "node-a"}, {Part: "caches", Job: "other"}, {Part: "caches", Upload: "other"}, {Part: "caches", Node: "../other"}} {
		bad := q
		bad.Query = query
		if bad.Valid() {
			t.Fatal("mixed/foreign cache selector accepted", query)
		}
	}
	if strict([]byte(`{"Tenant":"tenant","Query":{"Part":"caches","Node":"node-a"},"Node":"node-a"}`), &ImageBuildsQuery{}) == nil {
		t.Fatal("outer node selector accepted")
	}
}
