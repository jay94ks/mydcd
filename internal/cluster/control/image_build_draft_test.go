// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestDraftWorkUsesCurrentContextPolicyRootAndUserProof(t *testing.T) {
	f, spec := imageBuildFixture(t)
	spec.ID, spec.Kind = "editable", "draft"
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{Spec: spec}, state.Applied)
	call := ImageBuildDraftCall{Session: f.sessions["manager"], Tenant: "tenant", At: 2, Request: imagebuild.DraftRequest{Context: spec.ID, Kind: "plan"}}
	work, err := f.p.ImageBuildDraftWork(f.s, call)
	if err != nil || work.Scope.Root != spec.Root || work.Scope.ContextRevision != 1 || work.Scope.PolicyRevision != 1 || work.Scope.Tenant != "tenant" {
		t.Fatal("current scope", work, err)
	}
	edit := imagebuild.DraftEdit{ID: "original", Kind: "put", Path: "Dockerfile", Expected: 1, File: &imagebuild.Entry{Path: "Dockerfile", Bytes: 13, Digest: sha256.Sum256([]byte("FROM scratch\n"))}}
	proof := imagebuild.DraftProof{Schema: 1, Scope: work.Scope.Digest(), Edit: edit.Digest(), At: 2, ExpiresAt: 100, Nonce: [32]byte{1}}
	proof.Signature = ed25519.Sign(f.manager, imagebuild.DraftProofBytes(proof))
	call.Request = imagebuild.DraftRequest{Context: spec.ID, Kind: "edit", Scope: &work.Scope, Edit: &edit, Proof: &proof, Data: []byte("FROM scratch\n")}
	if _, err := f.p.ImageBuildDraftWork(f.s, call); err != nil {
		t.Fatal("signed edit", err)
	}
	legacyScope := work.Scope
	legacyScope.Generation = 0
	legacyProof := proof
	legacyProof.Scope = legacyScope.Digest()
	legacyProof.Signature = ed25519.Sign(f.manager, imagebuild.DraftProofBytes(legacyProof))
	legacyCall := call
	legacyCall.Request.Scope, legacyCall.Request.Proof = &legacyScope, &legacyProof
	if got, err := f.p.ImageBuildDraftWork(f.s, legacyCall); err != nil || got.Scope != legacyScope {
		t.Fatal("still-current legacy signature was rewritten/rejected", got, err)
	}
	for _, mutate := range []func(*ImageBuildDraftCall){
		func(c *ImageBuildDraftCall) { c.Tenant = "other" },
		func(c *ImageBuildDraftCall) { c.At = 100 },
		func(c *ImageBuildDraftCall) {
			p := *c.Request.Proof
			p.Signature = ed25519.Sign(f.node, imagebuild.DraftProofBytes(p))
			c.Request.Proof = &p
		},
		func(c *ImageBuildDraftCall) { c.Request.Data = []byte("changed") },
	} {
		bad := call
		mutate(&bad)
		if _, err := f.p.ImageBuildDraftWork(f.s, bad); err == nil {
			t.Fatal("stale/foreign/installed-node edit was accepted")
		}
	}
	// Updating public context metadata invalidates old authority, while fresh
	// requests still address the same stored draft lifetime.
	spec.Arguments = map[string]string{"MODE": "changed"}
	f.apply("manager", "put-build-context", 1, ImageBuildContextPut{Spec: spec}, state.Applied)
	if _, err := f.p.ImageBuildDraftWork(f.s, call); err == nil {
		t.Fatal("old original silently retargeted to new context revision")
	}
	if _, err := f.p.ImageBuildDraftWork(f.s, legacyCall); err == nil {
		t.Fatal("legacy representation bypassed current revision")
	}
	call.Request = imagebuild.DraftRequest{Context: spec.ID, Kind: "plan"}
	fresh, err := f.p.ImageBuildDraftWork(f.s, call)
	if err != nil || fresh.Scope.ContextRevision != 2 || fresh.Scope.Data() != work.Scope.Data() || fresh.Scope.Digest() == work.Scope.Digest() {
		t.Fatal("configuration changed data lifetime or kept old proof scope", fresh, err)
	}
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := b.Policy("tenant")
	policy.Spec.CPUMillis *= 2
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
	current, err := f.p.ImageBuildDraftWork(f.s, call)
	if err != nil || current.Scope.PolicyRevision != 2 || current.Scope.Data() != work.Scope.Data() || current.Scope.Digest() == fresh.Scope.Digest() {
		t.Fatal("CPU policy changed source lifetime or kept old scope", current, err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("generation restore", err)
	}
	view, err := f.p.ImageBuildDraftWork(restored, call)
	if err != nil || view.Scope != current.Scope {
		t.Fatal("snapshot changed current scope/data lifetime", view, err)
	}
}

func TestDraftContextDeleteRecreateDoesNotReuseDataGeneration(t *testing.T) {
	f, spec := imageBuildFixture(t)
	spec.ID, spec.Kind = "editable", "draft"
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{Spec: spec}, state.Applied)
	call := ImageBuildDraftCall{Session: f.sessions["manager"], Tenant: "tenant", At: 2, Request: imagebuild.DraftRequest{Context: spec.ID, Kind: "plan"}}
	original, err := f.p.ImageBuildDraftWork(f.s, call)
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "delete-build-context", 1, ImageBuildSelection{Tenant: "tenant", ID: spec.ID}, state.Applied)
	if _, err := f.p.ImageBuildDraftWork(f.s, call); err == nil {
		t.Fatal("deleted context remained editable")
	}
	f.apply("manager", "put-build-context", 2, ImageBuildContextPut{Spec: spec}, state.Applied)
	recreated, err := f.p.ImageBuildDraftWork(f.s, call)
	if err != nil || recreated.Scope.Generation != 3 || recreated.Scope.Data() == original.Scope.Data() {
		t.Fatal("recreated context inherited retired source", recreated, err)
	}
}

// Remove only the new optional derived field from a canonical snapshot to
// reproduce a pre-generation record; signed user inputs remain unchanged.
func restoreLegacyBuildContext(t *testing.T, f *nodeStorageFixture, spec imagebuild.ContextSpec) {
	t.Helper()
	key := buildRecordKey("context", spec.Tenant, spec.ID)
	before := []byte(f.s.Object(key).Value)
	var legacy ImageBuildContextRecord
	if json.Unmarshal(before, &legacy) != nil {
		t.Fatal("invalid original fixture")
	}
	legacy.DataGeneration = 0
	after, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	oldValue := []byte(base64.StdEncoding.EncodeToString(before))
	newValue := []byte(base64.StdEncoding.EncodeToString(after))
	if bytes.Count(raw, oldValue) != 1 {
		t.Fatal("legacy fixture target is ambiguous")
	}
	raw = bytes.Replace(raw, oldValue, newValue, 1)
	f.s, err = state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, f.s, state.Command{}) != nil {
		t.Fatal("legacy record restore", err)
	}
}

func TestDraftLegacyContextCapturesLastVisibleRevisionOnUpdateAndDelete(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "delete"}[remove], func(t *testing.T) {
			f, spec := imageBuildFixture(t)
			spec.ID, spec.Kind = "editable", "draft"
			f.apply("manager", "put-build-context", 0, ImageBuildContextPut{Spec: spec}, state.Applied)
			spec.Arguments = map[string]string{"MODE": "revision-two"}
			f.apply("manager", "put-build-context", 1, ImageBuildContextPut{Spec: spec}, state.Applied)
			restoreLegacyBuildContext(t, f, spec)
			if remove {
				f.apply("manager", "delete-build-context", 2, ImageBuildSelection{Tenant: "tenant", ID: spec.ID}, state.Applied)
			} else {
				spec.Arguments["MODE"] = "revision-three"
				f.apply("manager", "put-build-context", 2, ImageBuildContextPut{Spec: spec}, state.Applied)
			}
			b, err := f.p.ImageBuilds(f.s)
			if err != nil {
				t.Fatal(err)
			}
			record, _ := b.Context("tenant", spec.ID)
			if record.DataGeneration != 2 || record.Revision != 3 {
				t.Fatal("legacy lifetime reset to one or advanced with metadata", record.DataGeneration, record.Revision)
			}
			if remove {
				f.apply("manager", "put-build-context", 3, ImageBuildContextPut{Spec: spec}, state.Applied)
				b, err = f.p.ImageBuilds(f.s)
				if err != nil {
					t.Fatal(err)
				}
				record, _ = b.Context("tenant", spec.ID)
				if record.DataGeneration != 4 {
					t.Fatal("legacy deletion reused source lifetime")
				}
			}
		})
	}
}
