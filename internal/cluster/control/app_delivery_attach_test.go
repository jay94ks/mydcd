// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

// CD lives only in app.yaml x-sfc.cd: configure-app-cd never turns it on.
func TestConfigureAppCDDoesNotAttachAPolicy(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageCD)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	managedDNSTaskCoreBegin(t, f, "plain-app", "10.80.1.2", "web", func(*deployment.Compose, *deployment.PlanningContext) {})
	a, _ := f.p.Apps(f.s)
	revision := a.entries[appKey("tenant", "plain-app")].Inventory.Revision()
	policy := cdTestPolicy("manual")
	f.apply("attach", "configure-app-cd", revision, AppCDChange{Tenant: "tenant", App: "plain-app", Policy: &policy}, state.ConditionFailed)
}

func cdTestPolicy(mode string) deployment.DeliveryDeclaration {
	policy := deployment.DeliveryDeclaration{Enabled: true}
	policy.Source.Kind, policy.Source.Repository, policy.Source.Ref, policy.Source.Path = "git", "https://git.sfc.test/team/app.git", "refs/heads/main", "app.yaml"
	policy.Poll, policy.Limits.Fetch, policy.Limits.Bytes, policy.Limits.Queued, policy.Limits.Active = 60, 30, 4<<20, 1, 1
	policy.Sync.Mode, policy.Sync.Drift = mode, "report"
	policy.Runtime.Mode, policy.Runtime.Expiry = "require-explicit-override", "manual-release"
	return policy
}

// uploadSourceApp uploads source-app's own input, after edit, as a new deploy.
func uploadSourceApp(t *testing.T, f *backupCoreFixture, id string, edit func(*deployment.Compose)) (AppBegin, uint64) {
	t.Helper()
	apps, _ := f.p.Apps(f.s)
	e, _ := apps.Execution("tenant", "source-app")
	encoded, err := e.Blueprint().Encode()
	if err != nil {
		t.Fatal(err)
	}
	var original struct{ Input deployment.Compose }
	if json.Unmarshal(encoded, &original) != nil {
		t.Fatal("original app input")
	}
	edit(&original.Input)
	ctx, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	ctx.Project, ctx.Deployment = "source-app", "deploy"
	catalog, _ := f.p.Catalog(f.s)
	plan, err := deployment.CompileApp(original.Input, catalog, ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := plan.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.apply(id+"-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "source-app", Deployment: "deploy", ID: id, Length: len(raw), Digest: sha256.Sum256(raw)}, state.Applied)
	for index, start := 0, 0; start < len(raw); index, start = index+1, start+deployment.ArtifactPartBytes {
		f.apply(fmt.Sprintf("%s-part-%d", id, index), "put-app-part", uint64(index+1), AppUploadPart{Tenant: "tenant", ID: id, Index: index, Data: raw[start:min(len(raw), start+deployment.ArtifactPartBytes)]}, state.Applied)
	}
	apps, _ = f.p.Apps(f.s)
	return AppBegin{Tenant: "tenant", App: "source-app", Deployment: "deploy", Upload: id, Operation: id}, apps.entries[appKey("tenant", "source-app")].Inventory.Revision()
}

// Deploying an app that follows Git with x-sfc.cd changes only its policy:
// no new execution starts and the services keep coming from Git.
func TestDeployWithCDBlockChangesOnlyThePolicy(t *testing.T) {
	f := deliveryControlFixture(t)
	apps, _ := f.p.Apps(f.s)
	before, _ := apps.Delivery("tenant", "source-app")
	beforeExecution, _ := apps.Execution("tenant", "source-app")
	q, revision := uploadSourceApp(t, f, "policy", func(c *deployment.Compose) {
		p := cdTestPolicy("automatic")
		c.Sfc.Delivery = &p
	})
	f.apply("policy-begin", "begin-app", revision, q, state.Applied)
	apps, _ = f.p.Apps(f.s)
	after, _ := apps.Delivery("tenant", "source-app")
	if after.Policy().Sync.Mode != "automatic" || after.PolicyRevision() != before.PolicyRevision()+1 {
		t.Fatal("policy not changed", after.Policy().Sync.Mode, after.PolicyRevision())
	}
	if e, _ := apps.Execution("tenant", "source-app"); e.ActiveOperation() != beforeExecution.ActiveOperation() {
		t.Fatal("a policy change started a new execution")
	}
	for _, u := range apps.uploads {
		if u.ID == "policy" {
			t.Fatal("upload kept")
		}
	}
}

// A file without x-sfc.cd turns CD off only when the deploy says so.
func TestDeployWithoutCDBlockNeedsDisableCD(t *testing.T) {
	f, _ := fieldCASFixture(t) // the Git execution finished, so a deploy may replace it
	q, revision := uploadSourceApp(t, f, "plain", func(c *deployment.Compose) { c.Sfc.Delivery = nil })
	f.apply("plain-begin", "begin-app", revision, q, state.ConditionFailed)
	apps, _ := f.p.Apps(f.s)
	if _, on := apps.Delivery("tenant", "source-app"); !on {
		t.Fatal("refused deploy turned CD off")
	}
	q.DisableCD = true
	f.apply("plain-begin-off", "begin-app", revision, q, state.Applied)
	apps, _ = f.p.Apps(f.s)
	if _, on := apps.Delivery("tenant", "source-app"); on {
		t.Fatal("DisableCD left CD on")
	}
	if e, _ := apps.Execution("tenant", "source-app"); e.ActiveOperation() != "plain" {
		t.Fatal("the file was not deployed after CD went off", e.ActiveOperation())
	}
}
