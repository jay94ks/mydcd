// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

// Real immutable catalog/core with SIMULATED signed native/build metadata.
// No compiler/container, current authority, physical cache or exec is proved.
func TestCheckerCompiledOriginRequiresCommittedArtifactNotOnlyOldSignature(t *testing.T) {
	book, parent, intent, batch, private := buildJobFixture(t)
	build := CompiledBuild{Schema: 1, Cluster: intent.Cluster, Builder: intent.Owner, Job: intent.Digest(), ID: intent.ID, Recipe: batch.Items[0].Recipe, Digest: [32]byte{77}, Length: 1234}
	build.Signature = ed25519.Sign(private, CompiledBuildBytes(build))
	if build.Verify() != nil || book.CompiledOrigin(build) == nil {
		t.Fatal("signature without committed job")
	}
	var err error
	book, err = book.ReserveBuild(intent)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.DispatchBuild(intent.Tenant, intent.ID, 1, intent.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if book.CompiledOrigin(build) == nil {
		t.Fatal("live build used as closed provenance")
	}
	closure := buildClosure(intent, private, "removed")
	// Legacy closures remain valid metadata, but never invent compiled output.
	legacy, err := book.CloseBuild(intent.Tenant, intent.ID, 2, closure)
	if err != nil || legacy.CompiledOrigin(build) == nil {
		t.Fatal("legacy output inferred", err)
	}
	closure.Output = [32]byte{44}
	closure.Artifacts = []BuildArtifact{{Key: build.Recipe.Key(), Digest: build.Digest, Length: build.Length}}
	closure.Signature = ed25519.Sign(private, BuildClosureBytes(closure))
	closed, err := book.CloseBuild(intent.Tenant, intent.ID, 2, closure)
	if err != nil || closed.CompiledOrigin(build) != nil {
		t.Fatal("committed artifact", err)
	}
	for label, mutate := range map[string]func(*CompiledBuild){
		"different-bytes":  func(b *CompiledBuild) { b.Digest[0]++ },
		"different-length": func(b *CompiledBuild) { b.Length++ },
		"other-source":     func(b *CompiledBuild) { b.Recipe.Source[0]++ },
		"other-recipe":     func(b *CompiledBuild) { b.Recipe.Tree[0]++ },
		"other-job":        func(b *CompiledBuild) { b.Job[0]++ },
		"other-id":         func(b *CompiledBuild) { b.ID = hashText("other-id") },
		"other-tenant":     func(b *CompiledBuild) { b.Recipe.Tenant = "foreign" },
		"other-cluster":    func(b *CompiledBuild) { b.Cluster[0]++ },
	} {
		t.Run(label, func(t *testing.T) {
			changed := build.Clone()
			mutate(&changed)
			// The OLD builder key is still valid; its new signature is not a
			// new committed output of the closed job.
			changed.Signature = ed25519.Sign(private, CompiledBuildBytes(changed))
			if changed.Verify() != nil || closed.CompiledOrigin(changed) == nil {
				t.Fatal("old key changed immutable output")
			}
		})
	}
	copy, _ := closed.BuildJob(intent.Tenant, intent.ID)
	copy.Closure.Artifacts[0].Digest[0]++
	if closed.CompiledOrigin(build) != nil {
		t.Fatal("public clone aliases artifact commitment")
	}
	closed, err = closed.Release(parent)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := closed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	closed, err = DecodeCatalog(raw)
	if err != nil || closed.CompiledOrigin(build) != nil {
		t.Fatal("retired parent/snapshot erased origin", err)
	}
	// Optional nil preserves the exact old signature bytes, not just schema1.
	unsigned := buildClosure(intent, private, "removed")
	encoded, _ := json.Marshal(unsigned)
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil || fields["Artifacts"] != nil {
		t.Fatal("nil artifacts changed legacy bytes")
	}
}

func TestCheckerBuildClosureArtifactListRejectsForeignOrNonCanonicalOutputs(t *testing.T) {
	_, _, intent, batch, private := buildJobFixture(t)
	valid := BuildArtifact{Key: batch.Items[0].Key, Digest: [32]byte{33}, Length: 100}
	for label, artifacts := range map[string][]BuildArtifact{
		"foreign-recipe": {{Key: [32]byte{44}, Digest: valid.Digest, Length: 100}},
		"empty-digest":   {{Key: valid.Key, Length: 100}},
		"empty-length":   {{Key: valid.Key, Digest: valid.Digest}},
		"oversize":       {{Key: valid.Key, Digest: valid.Digest, Length: MaxCompiledArtifactBytes + 1}},
		"duplicate":      {valid, valid},
	} {
		t.Run(label, func(t *testing.T) {
			c := buildClosure(intent, private, "removed")
			c.Output = [32]byte{4}
			c.Artifacts = artifacts
			c.Signature = ed25519.Sign(private, BuildClosureBytes(c))
			if c.Verify(intent, "dispatched") == nil {
				t.Fatal("invalid artifact list")
			}
		})
	}
	for _, disposition := range []string{"never-dispatched", "not-created", "removed"} {
		c := buildClosure(intent, private, disposition)
		c.Artifacts = []BuildArtifact{valid}
		c.Signature = ed25519.Sign(private, BuildClosureBytes(c))
		if c.Verify(intent, "dispatched") == nil {
			t.Fatal("artifact without native/output witness", disposition)
		}
	}
}
