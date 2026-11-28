// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// A tag Task keeps its tag in the recipe and is made from the digest the
// deploy resolved; a bare tag, or a digest of another repository, is refused.
func TestTagContainerRunsFromItsDigest(t *testing.T) {
	digest := "docker.io/library/busybox@sha256:" + strings.Repeat("c", 64)
	base := ContainerSpec{Schema: 1, Node: "owner", Image: "docker.io/library/busybox:1.37", Command: []string{"/bin/sh"}, Bridge: "bridge", BridgeGeneration: 1, IPv4: netip.MustParseAddr("192.0.2.2"), Memory: 32 << 20, NanoCPU: 100000000}
	decode := func(s ContainerSpec) (ContainerSpec, error) {
		raw, _ := json.Marshal(s)
		return DecodeContainer(string(raw))
	}
	if _, err := decode(base); err == nil {
		t.Fatal("bare tag accepted")
	}
	tagged := base
	tagged.ImageDigest = digest
	got, err := decode(tagged)
	if err != nil || got.RunImage() != digest || got.Image != base.Image {
		t.Fatal("tag with its digest refused", err)
	}
	short := tagged
	short.Image = "busybox:1.37"
	if _, err = decode(short); err != nil {
		t.Fatal("Docker Hub short name refused", err)
	}
	foreign := tagged
	foreign.ImageDigest = "docker.io/library/alpine@sha256:" + strings.Repeat("c", 64)
	if _, err = decode(foreign); err == nil {
		t.Fatal("digest of another repository accepted")
	}
	pinned := base
	pinned.Image = digest
	if got, err = decode(pinned); err != nil || got.RunImage() != digest {
		t.Fatal("digest image refused", err)
	}
}
