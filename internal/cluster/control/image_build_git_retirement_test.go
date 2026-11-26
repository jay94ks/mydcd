// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

// Real management/FSM/restore; transfer and file evidence are not fabricated
// by shared state, and are checked by native stage-retirement adapter tests.
func TestGitStageGrantSeparatesCurrentTransferFromFencedDiscard(t *testing.T) {
	for _, change := range []string{"context", "policy", "deleted", "recreated"} {
		t.Run(change, func(t *testing.T) {
			f, publication := gitPublicationFixture(t)
			plan := publication.Saved.Plan
			g, err := f.p.ImageBuildGitStageGrant(f.s, plan.Root.Key, plan)
			if err != nil || !g.Valid() || g.Obsolete() {
				t.Fatal("current plan authorized discard", g, err)
			}
			if _, err := f.p.ImageBuildGitStageGrant(f.s, [32]byte{99}, plan); !errors.Is(err, access.ErrDenied) {
				t.Fatal(err)
			}
			future := plan
			future.PolicyRevision++
			if _, err := f.p.ImageBuildGitStageGrant(f.s, plan.Root.Key, future); !errors.Is(err, access.ErrConflict) {
				t.Fatal("local-ahead policy accepted", err)
			}
			book, _ := f.p.ImageBuilds(f.s)
			context, _ := book.Context(plan.Tenant, plan.Context)
			policy, _ := book.Policy(plan.Tenant)
			switch change {
			case "context":
				context.Spec.Tags = []string{"changed"}
				f.apply("manager", "put-build-context", context.Revision, ImageBuildContextPut{Spec: context.Spec}, state.Applied)
			case "policy":
				policy.Spec.Cleanup.UnusedDays++
				f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
			case "deleted", "recreated":
				f.apply("manager", "delete-build-context", context.Revision, ImageBuildSelection{Tenant: plan.Tenant, ID: plan.Context}, state.Applied)
				if change == "recreated" {
					f.apply("manager", "put-build-context", context.Revision+1, ImageBuildContextPut{Spec: context.Spec}, state.Applied)
				}
			}
			g, err = f.p.ImageBuildGitStageGrant(f.s, plan.Root.Key, plan)
			if err != nil || !g.Valid() || !g.Obsolete() || g.Plan != plan || g.Deleted != (change == "deleted") {
				t.Fatal("original plan not fenced", g, err)
			}
			raw, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := state.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			again, err := f.p.ImageBuildGitStageGrant(restored, plan.Root.Key, plan)
			if err != nil || again != g {
				t.Fatal("restore changed grant", again, err)
			}
		})
	}
}
