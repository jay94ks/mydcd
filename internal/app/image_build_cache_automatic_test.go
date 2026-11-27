// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

// Candidate ordering only; admission re-resolves a full signed source/policy
// from current state and native existence before any real pass is accepted.
func TestAutomaticCacheCandidatesAreFairAndSkipDisabledOrRunningScopes(t *testing.T) {
	owner := [32]byte{1}
	policy := imagebuild.Policy{Tenant: "t", BuilderImage: "builder"}
	book := control.ImageBuildCatalog{Policies: []control.ImageBuildPolicyRecord{{Spec: policy}}}
	for _, name := range []string{"one", "two"} {
		spec := imagebuild.JobSpec{Tenant: "t", Context: imagebuild.ContextSpec{ID: name}, Scope: imagebuild.UploadScope{Root: nodestorage.Reference{Node: "n", Key: owner}}, Policy: policy}
		book.Jobs = append(book.Jobs, control.ImageBuildJobRecord{Run: imagebuild.JobRun{Spec: spec, Phase: "succeeded", Closure: &imagebuild.JobClosure{}}})
	}
	now := time.Now()
	next := map[[32]byte]time.Time{}
	first, key := imageBuildCacheAutomaticCandidate(book, owner, next, now)
	if key == ([32]byte{}) || first.Context.ID == "" {
		t.Fatal("no due cache candidate")
	}
	next[key] = now.Add(time.Minute)
	second, other := imageBuildCacheAutomaticCandidate(book, owner, next, now)
	if other == ([32]byte{}) || other == key || first.Context.ID == second.Context.ID {
		t.Fatal("one cache starved the rest")
	}
	book.Policies[0].Deleted = true
	if _, key := imageBuildCacheAutomaticCandidate(book, owner, next, now); key != ([32]byte{}) {
		t.Fatal("deleted policy produced a pass")
	}
	book.Policies[0].Deleted = false
	for i := range book.Jobs {
		book.Jobs[i].Run.Phase = "running"
		book.Jobs[i].Run.Closure = nil
	}
	if _, key := imageBuildCacheAutomaticCandidate(book, owner, next, now); key != ([32]byte{}) {
		t.Fatal("running builds were scheduled as idle")
	}
}
