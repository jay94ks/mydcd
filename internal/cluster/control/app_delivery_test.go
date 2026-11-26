// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"

	"gopkg.in/yaml.v3"
)

// Accepted graph/native facts remain explicit Mock inputs. The source ticket,
// signed member report, CAS, upload ownership, candidate and checkpoint paths
// are the reusable product implementations. No HTTPS/native result is claimed.
func deliveryControlFixture(t *testing.T) *backupCoreFixture {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageCD)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	managedDNSTaskCoreBegin(t, f, "source-app", "10.80.1.2", "web", func(c *deployment.Compose, ctx *deployment.PlanningContext) {
		c.MyDC.Delivery = &deployment.DeliveryDeclaration{}
		c.MyDC.Delivery.Enabled = true
		c.MyDC.Delivery.Source.Kind, c.MyDC.Delivery.Source.Repository, c.MyDC.Delivery.Source.Ref, c.MyDC.Delivery.Source.Path = "git", "https://git.mydc.test/team/app.git", "refs/heads/main", "app.yaml"
		c.MyDC.Delivery.Poll, c.MyDC.Delivery.Limits.Fetch, c.MyDC.Delivery.Limits.Bytes, c.MyDC.Delivery.Limits.Queued, c.MyDC.Delivery.Limits.Active = 60, 30, 4<<20, 1, 1
		c.MyDC.Delivery.Sync.Mode, c.MyDC.Delivery.Sync.Drift = "manual", "report"
		c.MyDC.Delivery.Runtime.Mode, c.MyDC.Delivery.Runtime.Expiry = "require-explicit-override", "manual-release"
		if !ctx.Features["git-cd"] {
			t.Fatal("product planning omitted its connected Git/CD input contract")
		}
	})
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := a.entries[appKey("tenant", "source-app")]
	e, _ := entry.Inventory.Execution()
	c, _ := f.p.Catalog(f.s)
	d, err := deployment.NewAcceptedDelivery(e.Blueprint(), entry.Inventory, c)
	if err != nil {
		t.Fatal(err)
	}
	entry.Delivery = &d
	a.entries[appKey("tenant", "source-app")] = entry
	writes, code := f.p.appsCheckpoint(f.s, a)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "attach-source-fixture", Key: AppsKey, Expected: f.s.Object(AppsKey).Revision, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func deliveryControlProgress(t *testing.T, f *backupCoreFixture, r AppDeliveryProgress, want state.Code) {
	t.Helper()
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	d, exists := a.Delivery("tenant", "source-app")
	if !exists {
		t.Fatal("missing source state")
	}
	r.Schema, r.Kind, r.Cluster, r.Reporter = 1, "app-delivery", f.p.Cluster, [32]byte(f.node.Public().(ed25519.PublicKey))
	r.TargetCAS = true
	r.Tenant, r.App, r.Expected, r.RootRevision, r.Epoch, r.At = "tenant", "source-app", d.Revision(), f.s.Object(AppsKey).Revision, f.s.ModuleEpoch(), 10
	r.Signature = ed25519.Sign(f.node, AppDeliveryProgressBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(r.Action, result, want, err)
	}
	f.s = next
}

func TestDeliverySourceOriginalTicketUploadAndErrorPreserveInventory(t *testing.T) {
	f := deliveryControlFixture(t)
	a, _ := f.p.Apps(f.s)
	original, _ := a.entries[appKey("tenant", "source-app")].Inventory.Encode()
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	a, _ = f.p.Apps(f.s)
	d, _ := a.Delivery("tenant", "source-app")
	ticket, _ := d.FetchTicket()
	body := []byte("not an app but immutable partial input")
	source := AppDeliveryInput{Ticket: ticket, Upload: "original-git-input", Commit: strings.Repeat("1", 40)}
	begin := AppUploadBegin{Tenant: "tenant", App: "source-app", Deployment: "deploy", ID: source.Upload, Length: len(body), Digest: sha256.Sum256(body)}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "input", Ticket: &ticket, Input: &source, Begin: &begin}, state.Applied)
	a, _ = f.p.Apps(f.s)
	if !a.deliveryUploadHeld(a.uploads[0]) {
		t.Fatal("pending source upload lost its original hold")
	}
	f.apply("cannot-abort-source-input", "abort-app-upload", a.uploads[0].Revision, AppUploadSelection{Tenant: "tenant", ID: source.Upload}, state.ConditionFailed)
	part := AppUploadPart{Tenant: "tenant", ID: source.Upload, Index: 0, Data: body}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "part", Ticket: &ticket, Part: &part}, state.Applied)
	// Invalid complete input is one recorded source outcome, never an empty
	// app plan or an infinite sequence of denied Received proposals.
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "received", Ticket: &ticket}, state.Applied)
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := a.entries[appKey("tenant", "source-app")]
	after, _ := entry.Inventory.Encode()
	if !bytes.Equal(original, after) || entry.DeliveryInput != nil || len(a.uploads) != 0 {
		t.Fatal("source failure changed original app or retained a dead read-only upload")
	}
	if _, pending := entry.Delivery.FetchTicket(); pending {
		t.Fatal("failed source ticket still active")
	}
	before := f.s.Object(AppsKey)
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "source-error", Ticket: &ticket, Error: "fetch"}, state.ConditionFailed)
	if f.s.Object(AppsKey) != before {
		t.Fatal("late old error rewrote completed source outcome")
	}
	var row appCheckpoint
	raw, _, err := readCheckpoint(f.s, AppsKey, f.p.Cluster, f.p.TrustRoot)
	if err != nil || json.Unmarshal(raw, &row) != nil || len(row.Apps) != 1 || len(row.Apps[0].Inventory) != 0 || len(row.Apps[0].Delivery) == 0 {
		t.Fatal("checkpoint persisted duplicate inventory authorities", err)
	}
}

func TestDeliverySourceCandidatePublicationRetainsOriginalAcceptedRun(t *testing.T) {
	f := deliveryControlFixture(t)
	a, _ := f.p.Apps(f.s)
	entry := a.entries[appKey("tenant", "source-app")]
	original, _ := entry.Inventory.Encode()
	e, _ := entry.Inventory.Execution()
	// Get canonical current app input from the frozen public Blueprint.
	rawPlan, _ := e.Blueprint().Encode()
	var record struct{ Input deployment.Compose }
	if json.Unmarshal(rawPlan, &record) != nil {
		t.Fatal("frozen app input")
	}
	body, err := yaml.Marshal(record.Input)
	if err != nil {
		t.Fatal(err)
	}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	a, _ = f.p.Apps(f.s)
	d, _ := a.Delivery("tenant", "source-app")
	ticket, _ := d.FetchTicket()
	source := AppDeliveryInput{Ticket: ticket, Upload: "valid-git-input", Commit: strings.Repeat("2", 40)}
	begin := AppUploadBegin{Tenant: "tenant", App: "source-app", Deployment: "deploy", ID: source.Upload, Length: len(body), Digest: sha256.Sum256(body)}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "input", Ticket: &ticket, Input: &source, Begin: &begin}, state.Applied)
	for index, at := 0, 0; at < len(body); index, at = index+1, at+deployment.ArtifactPartBytes {
		part := AppUploadPart{Tenant: "tenant", ID: source.Upload, Index: index, Data: body[at:min(at+deployment.ArtifactPartBytes, len(body))]}
		deliveryControlProgress(t, f, AppDeliveryProgress{Action: "part", Ticket: &ticket, Part: &part}, state.Applied)
	}
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "received", Ticket: &ticket}, state.Applied)
	a, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry = a.entries[appKey("tenant", "source-app")]
	after, _ := entry.Inventory.Encode()
	if !bytes.Equal(original, after) {
		t.Fatal("source publication started/replaced an app operation")
	}
	statusCtx, _ := f.p.AppPlanning(f.s, "admin", "tenant")
	statusCtx.Project, statusCtx.Deployment = "source-app", "deploy"
	catalog, _ := f.p.Catalog(f.s)
	status, err := entry.Delivery.Status(catalog, statusCtx, 10)
	if err != nil || status.Commit != source.Commit || status.SourceError != "" {
		t.Fatal("candidate was not selected", status.SourceError, status.Commit, err)
	}
}
