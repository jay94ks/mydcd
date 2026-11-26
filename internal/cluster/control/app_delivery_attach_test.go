// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// The first 'cd set' of an app deployed without CD turns CD on: the settled
// execution becomes the running candidate under the app's inventory CAS.
func TestConfigureAppCDAttachesFirstPolicyToSettledApp(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageCD)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	managedDNSTaskCoreBegin(t, f, "plain-app", "10.80.1.2", "web", func(*deployment.Compose, *deployment.PlanningContext) {})
	policy := deployment.DeliveryDeclaration{Enabled: true}
	policy.Source.Kind, policy.Source.Repository, policy.Source.Ref, policy.Source.Path = "git", "https://git.mydc.test/team/app.git", "refs/heads/main", "app.yaml"
	policy.Poll, policy.Limits.Fetch, policy.Limits.Bytes, policy.Limits.Queued, policy.Limits.Active = 60, 30, 4<<20, 1, 1
	policy.Sync.Mode, policy.Sync.Drift = "manual", "report"
	policy.Runtime.Mode, policy.Runtime.Expiry = "require-explicit-override", "manual-release"
	a, _ := f.p.Apps(f.s)
	entry := a.entries[appKey("tenant", "plain-app")]
	if entry.Delivery != nil {
		t.Fatal("fixture already has CD")
	}
	revision := entry.Inventory.Revision()
	q := AppCDChange{Tenant: "tenant", App: "plain-app", Policy: &policy}
	f.apply("attach-stale", "configure-app-cd", revision+1, q, state.ConditionFailed)
	stale := q
	stale.PolicyRevision = 1
	f.apply("attach-policy-revision", "configure-app-cd", revision, stale, state.ConditionFailed)
	f.apply("pause-without-cd", "pause-app-cd", revision, AppCDChange{Tenant: "tenant", App: "plain-app"}, state.ConditionFailed)
	f.apply("attach", "configure-app-cd", revision, q, state.Applied)
	a, _ = f.p.Apps(f.s)
	d, ok := a.Delivery("tenant", "plain-app")
	if !ok || d.Policy().Source.Repository != policy.Source.Repository {
		t.Fatal("first cd set did not attach its policy")
	}
	f.apply("attach-again", "configure-app-cd", revision, q, state.ConditionFailed)
}
