// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// Actual user operations/FSM and original signed publication; native ZIP facts
// are fixture inputs and do not prove filesystem collection.
func TestFreezeCleanupUsesMonotonicConfigurationFenceAndNotClockExpiry(t *testing.T) {
	for _, change := range []string{"context", "policy", "deleted", "recreated"} {
		t.Run(change, func(t *testing.T) {
			f, publication := draftPublicationFixture(t)
			plan := publication.Frozen.Plan
			owner := plan.Scope.Root.Key
			if obsolete, err := f.p.ImageBuildFreezeObsolete(f.s, owner, plan); err != nil || obsolete {
				t.Fatal("current original classified obsolete", obsolete, err)
			}
			expired := plan
			expired.ExpiresAt = expired.CreatedAt + 1
			if obsolete, err := f.p.ImageBuildFreezeObsolete(f.s, owner, expired); err != nil || obsolete {
				t.Fatal("clock expiry substituted for a shared fence", obsolete, err)
			}
			if _, err := f.p.ImageBuildFreezeObsolete(f.s, [32]byte{99}, plan); err == nil {
				t.Fatal("foreign owner authorized cleanup")
			}
			future := plan
			future.Scope.PolicyRevision++
			if _, err := f.p.ImageBuildFreezeObsolete(f.s, owner, future); err == nil {
				t.Fatal("local-ahead policy treated as obsolete")
			}
			book, _ := f.p.ImageBuilds(f.s)
			context, _ := book.Context(plan.Scope.Tenant, plan.Scope.Context)
			policy, _ := book.Policy(plan.Scope.Tenant)
			switch change {
			case "context":
				context.Spec.Tags = []string{"changed"}
				f.apply("manager", "put-build-context", context.Revision, ImageBuildContextPut{Spec: context.Spec}, state.Applied)
			case "policy":
				policy.Spec.Cleanup.UnusedDays++
				f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
			case "deleted", "recreated":
				f.apply("manager", "delete-build-context", context.Revision, ImageBuildSelection{Tenant: plan.Scope.Tenant, ID: plan.Scope.Context}, state.Applied)
				if change == "recreated" {
					f.apply("manager", "put-build-context", context.Revision+1, ImageBuildContextPut{Spec: context.Spec}, state.Applied)
				}
			}
			if obsolete, err := f.p.ImageBuildFreezeObsolete(f.s, owner, plan); err != nil || !obsolete {
				t.Fatal("configuration fence did not invalidate old freeze", obsolete, err)
			}
			f.apply("manager", "publish-build-draft", plan.Revision, publication, state.ConditionFailed)
			raw, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := state.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if obsolete, err := f.p.ImageBuildFreezeObsolete(restored, owner, plan); err != nil || !obsolete {
				t.Fatal("restore lost original fence", obsolete, err)
			}
		})
	}
}
