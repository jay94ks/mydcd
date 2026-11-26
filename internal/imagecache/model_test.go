// SPDX-License-Identifier: Apache-2.0

package imagecache

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestCachePlanBindsExplicitImmutableSelectionAndNativeUsage(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	id := "sha256:" + strings.Repeat("a", 64)
	p := Plan{Schema: 1, Cluster: [32]byte{1}, Owner: [32]byte(pub), Boot: [32]byte{2}, Node: "node-a", At: 2500, Index: 10, Selection: []string{id}, Images: []Image{{ID: id, Bytes: 100, Aliases: []string{"docker.io/library/proof:latest"}}}}
	p.Signature = ed25519.Sign(key, PlanBytes(p))
	if !p.DeleteReady() || p.Digest() == ([32]byte{}) {
		t.Fatal("explicit unused plan rejected")
	}
	protected := p
	protected.Images = append([]Image(nil), p.Images...)
	protected.Images[0].Containers = 1
	protected.Signature = ed25519.Sign(key, PlanBytes(protected))
	if !protected.Valid() || protected.DeleteReady() {
		t.Fatal("stopped/native user removed from protection")
	}
	protected.Images[0].Containers = 0
	protected.Images[0].References = 1
	protected.Signature = ed25519.Sign(key, PlanBytes(protected))
	if protected.DeleteReady() {
		t.Fatal("accepted but unmaterialized reference ignored")
	}
	changed := p
	changed.Node = "node-b"
	if changed.Valid() {
		t.Fatal("owner signature did not bind target node")
	}
	if ValidSelection([]string{id, id}, true) || ValidSelection([]string{"proof:latest"}, true) || ValidID("sha256:"+strings.Repeat("A", 64)) {
		t.Fatal("ambiguous image selection accepted")
	}
	if !p.Images[0].Matches("proof:latest") {
		t.Fatal("Docker Hub alias normalization lost reference")
	}
	if (Part{ID: id, State: "removed", Code: "unknown", At: 1}).Valid() {
		t.Fatal("failed SDK call hidden as removed")
	}
}
