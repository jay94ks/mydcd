// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"testing"
)

func TestRouteSnapshotSeparatesCountersAndHandlesWithoutHidingPolicy(t *testing.T) {
	before := []byte(`{"link":[{"ifindex":1,"handle":7}],"nft":{"nftables":[{"rule":{"family":"ip","table":"filter","chain":"DOCKER-USER","handle":9,"comment":"original","expr":[{"counter":{"packets":0,"bytes":0}},{"accept":null}]}}]}}`)
	after := bytes.ReplaceAll(before, []byte(`"handle":9`), []byte(`"handle":19`))
	after = bytes.ReplaceAll(after, []byte(`"packets":0,"bytes":0`), []byte(`"packets":12,"bytes":1024`))
	a, err := routeSnapshotStructure(before)
	if err != nil {
		t.Fatal(err)
	}
	b, err := routeSnapshotStructure(after)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("normal counter/handle observation changed rule structure", err)
	}
	for _, changed := range [][]byte{
		bytes.ReplaceAll(after, []byte(`"accept":null`), []byte(`"drop":null`)),
		bytes.ReplaceAll(after, []byte(`"comment":"original"`), []byte(`"comment":"foreign"`)),
		bytes.ReplaceAll(after, []byte(`"counter":{"packets":12,"bytes":1024}`), []byte(`"accept":null`)),
		bytes.ReplaceAll(after, []byte(`"handle":7`), []byte(`"handle":17`)),
	} {
		value, err := routeSnapshotStructure(changed)
		if err != nil || bytes.Equal(a, value) {
			t.Fatal("snapshot hid a policy/expression/non-nft change", err)
		}
	}
	if _, err := routeSnapshotStructure([]byte(`{"link":[]}`)); err == nil {
		t.Fatal("absent nft input was accepted as baseline proof")
	}
}
