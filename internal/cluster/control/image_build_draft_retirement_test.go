// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// These are real signed management operations/FSM changes. Native deletion
// and lease closure are exercised separately; no filesystem result is injected
// into shared state by this grant.
func TestDraftRetirementRequiresDeletedOrRecreatedDataLifetime(t *testing.T) {
	for _, change := range []string{"context", "policy", "deleted", "recreated"} {
		t.Run(change, func(t *testing.T) {
			f, publication := draftPublicationFixture(t)
			scope := publication.Frozen.Plan.Scope
			owner := scope.Root.Key
			if _, err := f.p.ImageBuildDraftRetirementGrant(f.s, owner, scope); !errors.Is(err, reconcile.ErrPending) {
				t.Fatal("current lifetime eligible", err)
			}
			if _, err := f.p.ImageBuildDraftRetirementGrant(f.s, [32]byte{99}, scope); !errors.Is(err, access.ErrDenied) {
				t.Fatal("foreign owner authorized", err)
			}
			future := scope
			future.ContextRevision++
			if _, err := f.p.ImageBuildDraftRetirementGrant(f.s, owner, future); !errors.Is(err, access.ErrConflict) {
				t.Fatal("local-ahead context accepted", err)
			}
			future = scope
			future.PolicyRevision++
			if _, err := f.p.ImageBuildDraftRetirementGrant(f.s, owner, future); !errors.Is(err, access.ErrConflict) {
				t.Fatal("local-ahead policy accepted", err)
			}
			book, _ := f.p.ImageBuilds(f.s)
			context, _ := book.Context(scope.Tenant, scope.Context)
			policy, _ := book.Policy(scope.Tenant)
			switch change {
			case "context":
				context.Spec.Tags = []string{"changed"}
				f.apply("manager", "put-build-context", context.Revision, ImageBuildContextPut{Spec: context.Spec}, state.Applied)
			case "policy":
				policy.Spec.Cleanup.UnusedDays++
				f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
			case "deleted", "recreated":
				f.apply("manager", "delete-build-context", context.Revision, ImageBuildSelection{Tenant: scope.Tenant, ID: scope.Context}, state.Applied)
				if change == "recreated" {
					f.apply("manager", "put-build-context", context.Revision+1, ImageBuildContextPut{Spec: context.Spec}, state.Applied)
				}
			}
			grant, err := f.p.ImageBuildDraftRetirementGrant(f.s, owner, scope)
			if change == "context" || change == "policy" {
				if !errors.Is(err, reconcile.ErrPending) {
					t.Fatal("ordinary configuration change retired mutable data", grant, err)
				}
				return
			}
			if err != nil || !grant.Valid() || grant.Scope != scope || grant.Deleted != (change == "deleted") || grant.Index != f.s.Index() || grant.Epoch != f.s.ModuleEpoch() {
				t.Fatal("original lifetime fence missing", grant, err)
			}
			if change == "recreated" && grant.Generation <= scope.Data().Generation {
				t.Fatal("recreated data did not get a new generation", grant)
			}
			raw, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := state.Decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			again, err := f.p.ImageBuildDraftRetirementGrant(restored, owner, scope)
			if err != nil || again != grant {
				t.Fatal("restore changed original fence", again, err)
			}
		})
	}
}
