// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestNodeStorageQueryBounds(t *testing.T) {
	for _, q := range []NodeStorageQuery{{}, {Node: "node-a", After: "node-a/hdd"}} {
		if !q.Valid() {
			t.Fatal("valid node-storage query rejected", q)
		}
	}
	for _, q := range []NodeStorageQuery{{Node: "../node-a"}, {After: strings.Repeat("a", 513)}} {
		if q.Valid() {
			t.Fatal("invalid node-storage query accepted", q)
		}
	}
	if !(NodeStorageSpaceQuery{control.NodeStorageSelection{Node: "node-a", ID: "hdd"}}).Valid() || (NodeStorageSpaceQuery{}).Valid() {
		t.Fatal("node-storage-space selection bounds")
	}
	// A tenant field is not part of either query: strict decoding refuses it.
	if _, ok := methodRules["node-storage"].decode([]byte(`{"Tenant":"tenant"}`)); ok {
		t.Fatal("tenant accepted on node-storage")
	}
}
