// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/tests/gitfixture"
	"gopkg.in/yaml.v3"
)

func TestRQ5CDLocalServicesHistoryAndSourceNative(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppCDLocalServices, true)
}

// Extends the owned CLI/Git/Docker fixture. All candidates, accepted documents,
// operation receipts and native results are produced by the ordinary engine.
func verifyManagedCDLocalServices(t *testing.T, ctx context.Context, runtime **Runtime, cfg config.Node, root string, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, wait func(string, func() bool), source *gitfixture.Fixture, original []byte, first string) {
	t.Helper()
	call := func(want int, args ...string) []byte {
		t.Helper()
		body, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), append([]string{"--tenant", "tenant"}, args...), nil)
		code := 0
		if err != nil {
			if exited, ok := err.(interface{ ExitCode() int }); ok {
				code = exited.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != want {
			t.Fatal("local services CLI", args, code, want, string(diagnostic), string(body))
		}
		return body
	}
	delivery := func() (control.Apps, deployment.Delivery) {
		t.Helper()
		apps, err := p.ReadApps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		d, ok := apps.Delivery("tenant", "app")
		if !ok {
			t.Fatal("ordinary app has no registered Git source")
		}
		return apps, d
	}
	candidate := func(commit string) bool {
		_, d := delivery()
		s, ok := d.CandidateSelection()
		return ok && s.Commit == commit && d.SourceError() == ""
	}
	key := func(service string) string { return deployment.ResourceKey("task", "tenant", "app", service) }
	ready := func(operation string) bool {
		apps, d := delivery()
		e, ok := apps.Execution("tenant", "app")
		if ok && e.ActiveOperation() == operation && e.Status() == "Failed" {
			for _, step := range e.Steps() {
				stage, _ := e.Stage(step.Key)
				if stage.Result != nil && stage.Result.Code != 0 {
					t.Log("failed original local/CD stage", step.Key, *stage.Result)
				}
			}
			t.Fatal("original local/CD operation failed", operation)
		}
		selected, chosen := d.Selection()
		return ok && chosen && selected.Operation == operation && e.ActiveOperation() == operation && e.Status() == "Succeeded"
	}
	inspect := func(service string) string {
		t.Helper()
		s, err := (*runtime).workload.Status(ctx, key(service))
		if err != nil || !s.Ready || !s.Running || s.NativeID == "" {
			t.Fatal("actual local service", service, err)
		}
		return s.NativeID
	}
	sync := func(request, operation string) {
		t.Helper()
		// The operation ID is also the deployment operation; request only
		// names the step in this test.
		_ = request
		call(0, "cd", "sync", "app", "--id", operation)
		wait("actual local/Git native operation "+operation, func() bool { return ready(operation) })
		call(0, "op", "show", operation)
	}
	wait("initial local source candidate", func() bool { return candidate(first) })
	_, initial := delivery()
	if !initial.Policy().Sync.Prune {
		t.Fatal("local service preservation/removal fixture requires explicit prune policy")
	}
	model, err := deployment.ParseApp(original)
	if err != nil {
		t.Fatal(err)
	}
	service := model.Services["web"]
	service.DependsOn, service.Volumes, service.Secrets = nil, nil, nil
	// The source fixture image declares VOLUME /data. The added stateless
	// service covers it explicitly instead of creating an anonymous Volume.
	service.Tmpfs = append(service.Tmpfs, "/data:size=4m,uid=10001,gid=10001,mode=0750")
	service.MyDC.Sources, service.MyDC.SecretEnv, service.MyDC.Lifecycle = nil, nil, nil
	service.Environment = deployment.Environment{"MYDC_READINESS_FIXTURE": "1", "REVISION": "local"}
	service.Healthcheck = &deployment.Healthcheck{Test: []string{"CMD", "/backend", "--probe"}, Interval: "1s", Timeout: "1s", Retries: 2}
	for alias, attachment := range service.Networks {
		attachment.Aliases = nil
		if attachment.IPv4 != "" {
			// This fixture owns one original Task at .2; .3 also fits the
			// existing /28 native envelope. Do not assume a larger pool.
			attachment.IPv4 = netip.MustParseAddr(attachment.IPv4).Next().String()
		}
		service.Networks[alias] = attachment
	}
	local := deployment.Compose{Name: "app", MyDC: deployment.AppExtension{Schema: 1, Tenant: "tenant", Deployment: "app"}, Services: map[string]deployment.ComposeService{"worker": service}, Networks: model.Networks}
	body, err := yaml.Marshal(local)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise real multipart input and raw output beyond one MYDCP record.
	body = append([]byte("# "+strings.Repeat("local-source-padding", 1800)+"\n"), body...)
	path := filepath.Join(root, "local-services.yaml")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	webBefore := inspect("web")
	call(0, "cd", "put-local", "app", "-f", path, "--id", "rq5-local-put")
	// The same ID continues the saved upload and change; nothing new is sent.
	call(0, "cd", "put-local", "app", "-f", path, "--id", "rq5-local-put")
	if webBefore != inspect("web") {
		t.Fatal("candidate edit replaced original Git native before sync")
	}
	_, d := delivery()
	if d.LocalRevision() != 1 || d.LocalServices() == nil || !bytes.Equal(d.LocalServices().Body, body) {
		t.Fatal("multipart local document not retained separately")
	}
	sync("rq5-local-sync", "rq5-with-local")
	workerNative := inspect("worker")
	raw, version, err := user.ReadAppSource(ctx, peer, session, "tenant", control.AppSourceSelection{App: "app", Section: "local-services"})
	if err != nil || !bytes.Equal(raw, body) || version.LocalRevision != 1 || version.LocalActor != session.User || version.LocalDigest == ([32]byte{}) {
		t.Fatal("accepted local source lost author/version/exact bytes", err)
	}
	if raw := call(0, "manage", "app-source", "--app", "app", "--section", "local-services", "--revision", strconv.FormatUint(version.Revision, 10), "--raw"); !bytes.Equal(raw, body) {
		t.Fatal("CLI exact local source differs")
	}
	if err := (*runtime).Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := (*runtime).Close(); err != nil {
		t.Fatal(err)
	}
	*runtime = nil
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	*runtime = reopened
	if _, err := reopened.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	wait("same DB local source/native recovery", func() bool {
		apps, err := p.ReadApps(read().State)
		e, ok := apps.Execution("tenant", "app")
		stage, found := e.Stage(key("worker"))
		return err == nil && ok && found && stage.Observation != nil && stage.Observation.Healthy
	})
	if workerNative != inspect("worker") {
		t.Fatal("same DB restore replaced independently owned local native")
	}
	_, d = delivery()
	policy := d.Policy()
	secondDocument := nativeGitServiceRevision(t, original, "2", &policy, "web")
	second := source.Commit(secondDocument)
	wait("Git update retains separately accepted local input", func() bool { return candidate(second) })
	var diff control.AppCDDiff
	if json.Unmarshal(call(0, "cd", "diff", "app"), &diff) != nil || diff.ChangeCount != len(diff.Changes) {
		t.Fatal("public candidate diff/count")
	}
	for _, change := range diff.Changes {
		if change.Service == "worker" {
			t.Fatal("Git fetch silently changed/pruned local service")
		}
	}
	sync("rq5-git-with-local", "rq5-git-two")
	if workerNative != inspect("worker") {
		t.Fatal("Git update pruned/replaced unchanged local native")
	}
	collision, err := deployment.ParseApp(secondDocument)
	if err != nil {
		t.Fatal(err)
	}
	collision.Services["worker"] = service
	collisionDocument, err := yaml.Marshal(collision)
	if err != nil {
		t.Fatal(err)
	}
	source.Commit(collisionDocument)
	wait("Git/local name collision blocks candidate", func() bool { _, d := delivery(); return d.SourceError() == "name-conflict" })
	if workerNative != inspect("worker") {
		t.Fatal("name conflict replaced original local native")
	}
	call(1, "cd", "sync", "app", "--id", "rq5-never-run")
	thirdDocument := nativeGitServiceRevision(t, original, "3", &policy, "web")
	third := source.Commit(thirdDocument)
	wait("collision resolves only after explicit source edit", func() bool { return candidate(third) })
	var field control.AppCDField
	if json.Unmarshal(call(0, "cd", "field", "app", "services/web/environment/REVISION"), &field) != nil || field.Values == nil || string(field.Values.Source.Value) != `"3"` || string(field.Values.Current.Value) != `"2"` {
		t.Fatal("original Git and actual accepted values were conflated")
	}
	call(0, "cd", "override", "app", "services/web/environment/REVISION", `"local-override"`, "--id", "rq5-field-override")
	if json.Unmarshal(call(0, "cd", "field", "app", "services/web/environment/REVISION"), &field) != nil || field.Values == nil || !field.Values.Overridden || field.Values.CurrentOrigin != "override-intent" || string(field.Values.Source.Value) != `"3"` || string(field.Values.Current.Value) != `"local-override"` {
		t.Fatal("explicit override was reported as Git or an applied native value")
	}
	call(0, "cd", "release", "app", "services/web/environment/REVISION", "--id", "rq5-field-release")
	call(0, "cd", "clear-local", "app", "--id", "rq5-clear-local")
	if workerNative != inspect("worker") {
		t.Fatal("clearing candidate metadata stopped live local service")
	}
	sync("rq5-sync-clear", "rq5-without-local")
	wait("explicit sync/prune positively closes local Task", func() bool {
		gone, err := (*runtime).docker.Gone(ctx, "container", key("worker"))
		return err == nil && gone
	})
	retained, _, err := user.ReadAppSource(ctx, peer, session, "tenant", control.AppSourceSelection{App: "app", Revision: version.Revision, Section: "local-services"})
	if err != nil || !bytes.Equal(retained, body) {
		t.Fatal("clear discarded accepted historical local source", err)
	}
	var history []control.AppCDHistoryRecord
	if json.Unmarshal(call(0, "cd", "history", "app"), &history) != nil {
		t.Fatal("public CD history")
	}
	found := false
	for _, row := range history {
		if row.Operation == "rq5-with-local" {
			found = row.Status == "succeeded" && row.CompletedAt != 0 && row.LocalRevision == 1 && row.LocalActor == session.User
		}
	}
	if !found {
		t.Fatal("actual local execution missing successful provenance history")
	}
	verifyCDLocalAuthorRevocation(t, ctx, root, user, peer, session, p, read, body, call, func() string { return inspect("web") })
	// A source-only image candidate need not exist in the registry: it is never
	// executed. Diff must count one field, not every normalized service field.
	imageOnly, err := deployment.ParseApp(thirdDocument)
	if err != nil {
		t.Fatal(err)
	}
	web := imageOnly.Services["web"]
	imageParts := strings.Split(web.Image, "@sha256:")
	if len(imageParts) != 2 {
		t.Fatal("fixture image is not digest-pinned")
	}
	newDigest := strings.Repeat("b", 64)
	if imageParts[1] == newDigest {
		newDigest = strings.Repeat("c", 64)
	}
	web.Image = imageParts[0] + "@sha256:" + newDigest
	imageOnly.Services["web"] = web
	imageDocument, err := yaml.Marshal(imageOnly)
	if err != nil {
		t.Fatal(err)
	}
	imageCommit := source.Commit(imageDocument)
	wait("image-only candidate", func() bool { return candidate(imageCommit) })
	if json.Unmarshal(call(0, "cd", "diff", "app"), &diff) != nil || diff.ChangeCount != 1 || len(diff.Changes) != 1 || diff.Changes[0].Service != "web" || strings.Join(diff.Changes[0].Path, "/") != "services/web/image" {
		t.Fatal("image-only field diff/count", diff.ChangeCount, diff.Changes)
	}
	t.Log("RQ5 actual multipart CLI local edit/replay; original native preserved until sync; same DB/native recovery; Git update/prune preservation and explicit collision refusal; clear/sync exact closure; immutable source/provenance and accepted history; Git/current values and one-field image candidate")
}

// Real user login and management RPCs exercise the same author grant used by
// CLI edits. Only input staging precedes revocation; no second native rollout
// is manufactured just to check that the revoked author cannot start one.
func verifyCDLocalAuthorRevocation(t *testing.T, ctx context.Context, root string, admin userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, body []byte, cli func(int, ...string) []byte, native func() string) {
	t.Helper()
	home := filepath.Join(root, "rq5-author-journals")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal("author journal home", err)
	}
	mutate := func(client userauth.Client, actor access.Session, id, action string, expected uint64, payload any, want state.Code) {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		op, err := client.Prepare(ctx, peer, actor, id, control.Change{Schema: 1, Principal: actor.User, Action: action, Expected: expected, Payload: raw})
		if err != nil {
			t.Fatal("author operation prepare", action, err)
		}
		if _, err = userauth.StageOperation(home, client, op); err != nil {
			t.Fatal("author original intent", action, err)
		}
		reply, err := client.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != want {
			t.Fatal("author management result", action, reply.Result, want, err)
		}
		if err = userauth.RecordOperationResult(home, client, actor, op, *reply.Result); err != nil {
			t.Fatal(err)
		}
	}
	key, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	account := access.User{ID: "local-author", Username: "local-author", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}}
	mutate(admin, session, "rq5-author-create", "put-user", 0, account, state.Applied)
	mutate(admin, session, "rq5-author-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: account.ID, Role: access.Manager, Enabled: true}, state.Applied)
	mutate(admin, session, "rq5-other-tenant", "create-tenant", 0, control.TenantID{ID: "other"}, state.Applied)
	writer := admin
	author, err := writer.Login(ctx, peer, account.Username, key.Private)
	if err != nil {
		t.Fatal("actual local author login", err)
	}
	if raw, _, err := writer.ReadAppSource(ctx, peer, author, "other", control.AppSourceSelection{App: "app", Section: "local-services"}); err == nil || len(raw) != 0 {
		t.Fatal("local author read another tenant's source", err)
	} else {
		var denied *userauth.Error
		if !errors.As(err, &denied) || denied.Code != "denied" {
			t.Fatal("cross-tenant source lookup did not deny before object existence", err)
		}
	}
	const upload = "rq5-author-local"
	digest := sha256.Sum256(body)
	mutate(writer, author, "rq5-author-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "app", ID: upload, Length: len(body), Digest: digest}, state.Applied)
	for start, index := 0, 0; start < len(body); start, index = start+deployment.ArtifactPartBytes, index+1 {
		mutate(writer, author, "rq5-author-part-"+strconv.Itoa(index), "put-app-part", uint64(index+1), control.AppUploadPart{Tenant: "tenant", ID: upload, Index: index, Data: body[start:min(len(body), start+deployment.ArtifactPartBytes)]}, state.Applied)
	}
	apps, err := p.ReadApps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	var view control.AppCDView
	for _, row := range apps.Records() {
		if row.Tenant == "tenant" && row.App == "app" && row.CD != nil {
			view = *row.CD
		}
	}
	if view.LocalTarget == ([32]byte{}) {
		t.Fatal("original local edit target missing")
	}
	mutate(writer, author, "rq5-author-local-put", "put-app-local-services", view.Revision, control.AppLocalChange{Tenant: "tenant", App: "app", Upload: upload, Registration: view.Registration, Revision: view.LocalRevision, Digest: digest, Services: []string{"worker"}, Target: &view.LocalTarget}, state.Applied)
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	membership, exists := catalog.Membership("tenant", account.ID)
	if !exists {
		t.Fatal("accepted local author membership missing")
	}
	mutate(admin, session, "rq5-author-revoke", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: account.ID, Role: access.Manager, Enabled: false}, state.Applied)
	before := native()
	apps, _ = p.ReadApps(read().State)
	original, _ := apps.Execution("tenant", "app")
	cli(1, "cd", "sync", "app", "--id", "rq5-author-must-not-run")
	apps, err = p.ReadApps(read().State)
	after, ok := apps.Execution("tenant", "app")
	if err != nil || !ok || after.ActiveOperation() != original.ActiveOperation() || native() != before {
		t.Fatal("revoked local author started a new deployment or replaced original native", err)
	}
	cli(0, "cd", "clear-local", "app", "--id", "rq5-clear-revoked-author")
	t.Log("actual independent local author login/upload/edit; cross-tenant source denied; membership revocation rejects new sync and preserves accepted Git native; administrator clears candidate metadata")
}
