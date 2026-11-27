// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestGitSaveWorkChecksCurrentPolicyAndOriginalUserProof(t *testing.T) {
	f, publish := gitPublicationFixture(t)
	plan := publish.Saved.Plan
	proof := imagebuild.GitSaveProof{Schema: 1, Plan: plan.Digest(), At: 2, ExpiresAt: 100, Nonce: [32]byte{1}}
	proof.Signature = ed25519.Sign(f.manager, imagebuild.GitSaveProofBytes(proof))
	call := ImageBuildGitCall{Session: f.sessions["manager"], Tenant: plan.Tenant, At: 2, Request: imagebuild.GitSaveRequest{Plan: plan, Proof: proof}}
	if work, err := f.p.ImageBuildGitWork(f.s, call); err != nil || work.Read.Spec.ID != plan.Context || work.Root.Reference(f.p.Cluster) != plan.Root {
		t.Fatal("valid owner source work rejected", err)
	}
	for _, change := range []func(*ImageBuildGitCall){
		func(c *ImageBuildGitCall) { c.Tenant = "other" }, func(c *ImageBuildGitCall) { c.At = 100 },
		func(c *ImageBuildGitCall) { c.Request.Plan.Commit = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
		func(c *ImageBuildGitCall) {
			c.Request.Proof.Signature = ed25519.Sign(f.node, imagebuild.GitSaveProofBytes(c.Request.Proof))
		},
	} {
		bad := call
		change(&bad)
		if _, err := f.p.ImageBuildGitWork(f.s, bad); err == nil {
			t.Fatal("foreign/expired/forged source request accepted")
		}
	}
	b, _ := f.p.ImageBuilds(f.s)
	policy, _ := b.Policy(plan.Tenant)
	policy.Spec.CPUMillis *= 2
	f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
	if _, err := f.p.ImageBuildGitWork(f.s, call); err == nil {
		t.Fatal("old source plan retargeted to new policy")
	}
}
