// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
)

func TestGitResultPurposeAllowsOnlyReadAfterPlanExpiryAndPreservesLegacyProofBytes(t *testing.T) {
	q, session, key := gitPlanProofFixture()
	legacy := struct {
		Schema        uint8
		Plan          [32]byte
		At, ExpiresAt int64
		Nonce         [32]byte
		Signature     []byte
	}{q.Proof.Schema, q.Proof.Plan, q.Proof.At, q.Proof.ExpiresAt, q.Proof.Nonce, nil}
	raw, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(GitSaveProofBytes(q.Proof), append([]byte("mydc-imagebuild-git-request-1\x00"), raw...)) {
		t.Fatal("optional false result flag changed original proof bytes", err)
	}
	q.Plan.ExpiresAt = 105
	q.Result, q.Proof.Result = true, true
	q.Proof.Plan, q.Proof.At, q.Proof.ExpiresAt = q.Plan.Digest(), 110, 200
	q.Proof.Signature = ed25519.Sign(key, GitSaveProofBytes(q.Proof))
	if !q.Valid() || q.Authorize(session, 111) != nil {
		t.Fatal("expired original cannot be queried with fresh result proof")
	}
	for _, change := range []func(*GitSaveRequest){
		func(q *GitSaveRequest) { q.Result = false },
		func(q *GitSaveRequest) { q.Result, q.Proof.Result = false, false },
		func(q *GitSaveRequest) { q.Plan.ExpiresAt = 1000; q.Proof.Plan = q.Plan.Digest() },
	} {
		bad := q
		change(&bad)
		if bad.Authorize(session, 111) == nil {
			t.Fatal("result proof extended plan or reexecuted save")
		}
	}
	for _, code := range []string{"PENDING", "DISCARDED", "NOT_INITIALIZED"} {
		if !(GitSaveResponse{Schema: 1, Plan: q.Plan.Digest(), Code: code}).Valid(q) {
			t.Fatal("historical state rejected", code)
		}
	}
}

func gitPlanProofFixture() (GitSaveRequest, access.Session, ed25519.PrivateKey) {
	u, _ := testScope(1, [32]byte{1})
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{67}, 32))
	session := access.Session{Cluster: u.Cluster, User: "manager", Key: [32]byte(key.Public().(ed25519.PublicKey)), ExpiresAt: 300}
	plan := GitSavePlan{Schema: 1, Tenant: u.Tenant, Context: u.Context, ID: "git-save", Creator: session.User, Root: u.Root, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20, Commit: strings.Repeat("a", 40), Tree: [32]byte{7}, CreatedAt: 100, ExpiresAt: 1000}
	proof := GitSaveProof{Schema: 1, Plan: plan.Digest(), At: 100, ExpiresAt: 200, Nonce: [32]byte{1}}
	proof.Signature = ed25519.Sign(key, GitSaveProofBytes(proof))
	return GitSaveRequest{Plan: plan, Proof: proof}, session, key
}
func TestGitSaveUserProofFixesSourceIdentityScopeAndLifetimeThroughRelay(t *testing.T) {
	q, session, key := gitPlanProofFixture()
	if !q.Valid() || q.Authorize(session, 101) != nil {
		t.Fatal("valid fixed source request rejected")
	}
	for _, change := range []func(*GitSaveRequest){
		func(q *GitSaveRequest) { q.Plan.Commit = strings.Repeat("b", 40) }, func(q *GitSaveRequest) { q.Plan.Tree[0] ^= 1 },
		func(q *GitSaveRequest) { q.Plan.ContextRevision++ }, func(q *GitSaveRequest) { q.Plan.PolicyRevision++ },
		func(q *GitSaveRequest) { q.Plan.ID = "replacement" }, func(q *GitSaveRequest) { q.Plan.Creator = "other" },
		func(q *GitSaveRequest) { q.Plan.Root.Generation++ }, func(q *GitSaveRequest) { q.Plan.ExpiresAt++ },
		func(q *GitSaveRequest) { q.Proof.Nonce = [32]byte{} },
		func(q *GitSaveRequest) {
			_, node := testScope(1, [32]byte{1})
			q.Proof.Signature = ed25519.Sign(node, GitSaveProofBytes(q.Proof))
		},
	} {
		bad := q
		change(&bad)
		if bad.Authorize(session, 101) == nil {
			t.Fatal("relay/node key replaced fixed user source input")
		}
	}
	if q.Authorize(session, 200) == nil {
		t.Fatal("expired short proof accepted")
	}
	q.Proof.At, q.Proof.ExpiresAt, q.Proof.Nonce = 201, 250, [32]byte{2}
	q.Proof.Signature = ed25519.Sign(key, GitSaveProofBytes(q.Proof))
	if q.Authorize(session, 202) != nil {
		t.Fatal("renewed proof of same original was rejected")
	}
}
func TestGitSaveResponseNeverTurnsPendingOrMissingEvidenceIntoSaved(t *testing.T) {
	q, _, _ := gitPlanProofFixture()
	r := GitSaveResponse{Schema: 1, Plan: q.Plan.Digest(), Code: "PENDING"}
	if !r.Valid(q) {
		t.Fatal("pending original not representable")
	}
	r.Code = "SAVED"
	if r.Valid(q) {
		t.Fatal("saved without original artifact evidence accepted")
	}
	r.Code = "PENDING"
	r.Saved = &SavedGit{}
	if r.Valid(q) {
		t.Fatal("pending with invented archive accepted")
	}
	r.Saved = nil
	r.Plan[0] ^= 1
	if r.Valid(q) {
		t.Fatal("response changed save ID/source target")
	}
}
