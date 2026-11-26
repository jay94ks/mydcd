// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/deployment"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func TestAppSourceInputCarriesFactsBeyondMetadataFrameWithoutChangingDocument(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{29}, ed25519.SeedSize))
	cluster := [32]byte{1}
	fact := checker.SourceFact{Schema: 1, Cluster: cluster, Owner: [32]byte(key.Public().(ed25519.PublicKey)), Tenant: "tenant", SDK: 1,
		Digest: sha256.Sum256([]byte("package checker\n")), Length: uint64(len("package checker\n")),
		Modules: []checker.ModulePin{{Path: "example.invalid/checker", Version: "v1.0.0", Digest: [32]byte{2}, Length: 1024}}}
	fact.Signature = ed25519.Sign(key, checker.SourceFactBytes(fact))
	facts := map[string]checker.SourceFact{}
	for i := 0; i < 101; i++ {
		facts[fmt.Sprintf("source-%03d", i)] = fact.Clone()
	}
	document := []byte("name: app\n# source facts are separate from app.yaml\n")
	raw, err := encodeAppSourceInput(document, facts, cluster, "tenant")
	if err != nil || len(raw) <= 64<<10 {
		t.Fatal("fixture did not cross the metadata budget", err, len(raw))
	}
	decoded, returned, err := decodeAppSourceInput(raw, cluster, "tenant")
	if err != nil || !bytes.Equal(decoded, document) || len(returned) != len(facts) {
		t.Fatal("bounded source envelope roundtrip", err)
	}
	returned["source-000"].Signature[0] ^= 1
	if facts["source-000"].Verify() != nil {
		t.Fatal("decoder aliased caller facts")
	}
	if _, _, err := decodeAppSourceInput(raw, [32]byte{2}, "tenant"); err == nil {
		t.Fatal("cross-cluster fact")
	}
	if _, _, err := decodeAppSourceInput(raw, cluster, "other"); err == nil {
		t.Fatal("cross-tenant fact")
	}
	var input appSourceInput
	if json.Unmarshal(raw, &input) != nil {
		t.Fatal("fixture envelope")
	}
	var changed checker.SourceFact
	if json.Unmarshal(input.Sources["source-000"], &changed) != nil {
		t.Fatal("fixture fact")
	}
	changed.Digest[0]++
	input.Sources["source-000"], _ = json.Marshal(changed)
	altered, _ := json.Marshal(input)
	if _, _, err := decodeAppSourceInput(altered, cluster, "tenant"); err == nil {
		t.Fatal("unsigned source substitution")
	}
	if _, err := encodeAppSourceInput(make([]byte, deployment.ArtifactMaxBytes+1), facts, cluster, "tenant"); err == nil {
		t.Fatal("source envelope enlarged document budget")
	}
	meta := AppPlanInput{Length: deployment.ArtifactMaxBytes + 1, Digest: sha256.Sum256(raw)}
	if meta.valid() || !meta.validSources(true) {
		t.Fatal("old/new input budgets mixed")
	}
	meta.Length = appSourceInputMaxBytes + 1
	if meta.validSources(true) {
		t.Fatal("unbounded source envelope")
	}
}
