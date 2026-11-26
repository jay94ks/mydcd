// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"

	"gopkg.in/yaml.v3"
)

func localControlFixture(t *testing.T) (*backupCoreFixture, []byte) {
	t.Helper()
	f := syncCASFixture(t)
	publishSyncCASSource(t, f, "git-before-local", syncCASBody(t, f))
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := apps.Delivery("tenant", "source-app")
	b, _ := d.CandidateBlueprint()
	raw, _ := b.Encode()
	var record struct{ Input deployment.Compose }
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("candidate input")
	}
	service := record.Input.Services["web"]
	service.DependsOn = nil
	for name, attachment := range service.Networks {
		attachment.Aliases = nil
		if attachment.IPv4 != "" {
			ip := netip.MustParseAddr(attachment.IPv4)
			for range 20 {
				ip = ip.Next()
			}
			attachment.IPv4 = ip.String()
		}
		service.Networks[name] = attachment
	}
	service.Volumes, service.Secrets = nil, nil
	service.MyDC.Sources, service.MyDC.SecretEnv, service.MyDC.Lifecycle = nil, nil, nil
	service.LifecycleProgram, service.LifecycleSources, service.FixedVolumes = nil, nil, nil
	input := deployment.Compose{Name: "source-app", MyDC: deployment.AppExtension{Schema: 1, Tenant: "tenant", Deployment: "deploy"}, Services: map[string]deployment.ComposeService{"worker": service}, Networks: record.Input.Networks}
	body, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return f, body
}

func stageLocalControl(t *testing.T, f *backupCoreFixture, id string, body []byte) AppLocalChange {
	t.Helper()
	f.apply(id+"-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "source-app", Deployment: "deploy", ID: id, Length: len(body), Digest: sha256.Sum256(body)}, state.Applied)
	for start, index := 0, 0; start < len(body); start, index = start+deployment.ArtifactPartBytes, index+1 {
		f.apply(id+"-part", "put-app-part", uint64(index+1), AppUploadPart{Tenant: "tenant", ID: id, Index: index, Data: body[start:min(start+deployment.ArtifactPartBytes, len(body))]}, state.Applied)
	}
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := apps.entries[appKey("tenant", "source-app")]
	target := appLocalTarget(entry)
	return AppLocalChange{Tenant: "tenant", App: "source-app", Upload: id, Registration: appRegistrationDigest(entry.Origin), Revision: entry.Delivery.LocalRevision(), Digest: sha256.Sum256(body), Services: []string{"worker"}, Target: &target}
}

func TestLocalServicesHaveIndependentAcceptedAuthorAndRetainOriginalExecution(t *testing.T) {
	f, body := localControlFixture(t)
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", "source-app")]
	before, _ := entry.Inventory.Encode()
	origin, _ := json.Marshal(entry.Origin)
	// Local author may Deploy but cannot sync/manage the Git app. The original
	// registration retains its distinct frozen Session and Group requester.
	f.session.Scopes[0].Actions = slices.DeleteFunc(slices.Clone(f.session.Scopes[0].Actions), func(action access.Action) bool { return action == access.ManageCD })
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	q := stageLocalControl(t, f, "local-worker", body)
	apps, _ = f.p.Apps(f.s)
	entry = apps.entries[appKey("tenant", "source-app")]
	wrong := q
	wrong.Services = []string{"another"}
	f.apply("wrong-local-names", "put-app-local-services", entry.Delivery.Revision(), wrong, state.Invalid)
	f.apply("accept-local", "put-app-local-services", entry.Delivery.Revision(), q, state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry = apps.entries[appKey("tenant", "source-app")]
	after, _ := entry.Inventory.Encode()
	afterOrigin, _ := json.Marshal(entry.Origin)
	b, _ := entry.Delivery.CandidateBlueprint()
	if !bytes.Equal(before, after) || !bytes.Equal(origin, afterOrigin) || entry.Local == nil || entry.LocalEdit == nil || entry.Local.Revision != 1 || len(apps.uploads) != 0 || verifyLocalBlueprint(entry, entry.Local, b) != nil {
		t.Fatal("local edit replaced original execution/grant or failed to retain its own signed input")
	}
	// The pending document is readable before any sync takes it.
	pending, err := f.p.AppSource(f.s, f.session, 10, "tenant", AppSourceSelection{App: "source-app", Section: "pending-local"})
	if err != nil || pending.Section != "pending-local" || pending.Pending == nil || pending.Pending.Revision != 1 || pending.Pending.Length != len(body) || pending.Pending.Digest != sha256.Sum256(body) || !bytes.Equal(pending.Data, body[:min(len(body), deployment.ArtifactPartBytes)]) {
		t.Fatal("pending local document", pending.Pending, err)
	}
	if _, err := f.p.AppSource(f.s, f.session, 10, "tenant", AppSourceSelection{App: "source-app", Section: "pending-local", Revision: 1}); err == nil {
		t.Fatal("pending local with a version")
	}
	c, _ := f.p.Catalog(f.s)
	if p := f.p.authorizeLocalBlueprint(f.s, c, entry, entry.Local, b); p != nil {
		t.Fatal("local author unexpectedly required ManageCD", p)
	}
	old := ownLocalGrant(entry.Local)
	owned, copyErr := apps.owned()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	copyEntry := owned.entries[appKey("tenant", "source-app")]
	copyEntry.Local.Services[0] = "caller-mutation"
	copyEntry.LocalEdit.Change.Payload[0] ^= 1
	if entry.Local.Services[0] != "worker" || validateAppLocal(entry) != nil {
		t.Fatal("owned app metadata aliases accepted local grant/edit")
	}
	view := appCDView(entry)
	view.LocalServices[0] = "caller-mutation"
	if entry.Local.Services[0] != "worker" {
		t.Fatal("public local service names alias checkpoint")
	}
	target := appLocalTarget(entry)
	clear := AppLocalChange{Tenant: "tenant", App: "source-app", Registration: q.Registration, Revision: 1, Target: &target}
	f.apply("clear-local", "clear-app-local-services", entry.Delivery.Revision(), clear, state.Applied)
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry = apps.entries[appKey("tenant", "source-app")]
	if entry.Local != nil || entry.LocalEdit == nil || entry.Delivery.LocalRevision() != 2 || old.verify(entry.Origin, entry.Inventory.Scope(), b.OriginalDocument().LocalServices) != nil {
		t.Fatal("clear erased an old accepted author or lost its own signed edit")
	}
	if verifyLocalBlueprint(entry, nil, b) == nil || validateAppLocal(entry) != nil {
		t.Fatal("historical local plan borrowed the cleared current grant")
	}
	if _, err := f.p.AppSource(f.s, f.session, 10, "tenant", AppSourceSelection{App: "source-app", Section: "pending-local"}); !errors.Is(err, ErrAppSourceSection) {
		t.Fatal("cleared pending local", err)
	}
}

func TestLocalGrantCASAndTamperingFailClosed(t *testing.T) {
	f, body := localControlFixture(t)
	q := stageLocalControl(t, f, "local-cas", body)
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", "source-app")]
	raw, _ := ChangeBytes("put-app-local-services", "admin", entry.Delivery.Revision(), q)
	var change Change
	_ = json.Unmarshal(raw, &change)
	op := UserOperation{Schema: 1, Session: f.session, At: 10, Epoch: f.s.ModuleEpoch(), RequestID: "local-cas-original", RootRevision: f.s.Object(AppsKey).Revision, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil || cmd.Kind != state.ModuleAppCAS {
		t.Fatal("local target did not select scoped CAS", err)
	}
	grant := &AppLocalGrant{Revision: 1, Digest: q.Digest, Services: slices.Clone(q.Services), Origin: op}
	if grant.verify(entry.Origin, entry.Inventory.Scope(), nil) != nil {
		t.Fatal("original signed author rejected")
	}
	for _, mutate := range []func(*AppLocalGrant){
		func(g *AppLocalGrant) { g.Revision++ },
		func(g *AppLocalGrant) { g.Digest[0] ^= 1 },
		func(g *AppLocalGrant) { g.Services[0] = "web" },
		func(g *AppLocalGrant) { g.Origin.Change.Payload[0] ^= 1 },
		func(g *AppLocalGrant) { g.Origin.Session.User = "another" },
	} {
		changed := ownLocalGrant(grant)
		mutate(changed)
		if changed.verify(entry.Origin, entry.Inventory.Scope(), nil) == nil {
			t.Fatal("tampered local authority accepted")
		}
	}
	// Unrelated staged input advances the Apps root only, not the edit target.
	f.apply("unrelated-local-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "other", Deployment: "deploy", ID: "other-local", Length: 1, Digest: sha256.Sum256([]byte{1})}, state.Applied)
	applyDownCAS(t, f, cmd, state.Applied)
	apps, _ = f.p.Apps(f.s)
	entry = apps.entries[appKey("tenant", "source-app")]
	if validateAppLocal(entry) != nil {
		t.Fatal("scoped acceptance did not survive checkpoint decode")
	}
	entry.LocalEdit = nil
	if validateAppLocal(entry) == nil {
		t.Fatal("missing signed edit accepted")
	}
}

func TestLocalEditRequiresCurrentDeployAndExactUploadScope(t *testing.T) {
	f, body := localControlFixture(t)
	q := stageLocalControl(t, f, "local-permission", body)
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", "source-app")]
	wrong := q
	wrong.App = "other"
	f.apply("wrong-local-scope", "put-app-local-services", entry.Delivery.Revision(), wrong, state.ConditionFailed)
	wrong = q
	wrong.Digest[0] ^= 1
	f.apply("wrong-local-digest", "put-app-local-services", entry.Delivery.Revision(), wrong, state.ConditionFailed)
	session := f.session
	f.session.Scopes[0].Actions = []access.Action{access.Read}
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.apply("without-local-deploy", "put-app-local-services", entry.Delivery.Revision(), q, state.Forbidden)
	f.session = session
	apps, _ = f.p.Apps(f.s)
	if len(apps.uploads) != 1 || apps.entries[appKey("tenant", "source-app")].Delivery.LocalRevision() != 0 {
		t.Fatal("denial consumed someone else's source or published a local edit")
	}
}
