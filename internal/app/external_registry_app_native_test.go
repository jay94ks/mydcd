// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/observability"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/tests/registryfixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

// This selects only the existing managed app/Volume/Vault/native lifecycle.
// No managed-registry push, Git, draft, builder or large-content opt-in runs.
func TestRQ6RealExternalPrivateRegistryAppCLIAndOriginalReaderReturn(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppExternalRegistry, true)
}

type externalRegistryAppNative struct {
	cli                     *managedRegistryNative
	remote                  *registryfixture.Fixture
	user                    userauth.Client
	peer                    mydcp.Peer
	session                 access.Session
	root, reference, config string
	manifest, nativeImage   string
	public                  map[string]any
	save                    func()
	values                  [][]byte
	readers                 []control.ExternalRegistryReader
	task                    deployment.ObjectRef
	binding                 deployment.Binding
	origin                  control.AppBindingSource
	native, startedAt       string
	authorized, blobs       int64
}

func prepareExternalRegistryAppNative(t *testing.T, ctx context.Context, r *Runtime, root string, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), source *registryfixture.Fixture, public map[string]any, save func()) *externalRegistryAppNative {
	t.Helper()
	const usernameA, passwordA = "owned-app-reader-a", "private-rq6-app-registry-a"
	const usernameB, passwordB = "owned-app-reader-b", "private-rq6-app-registry-b"
	maintenance := os.Getenv("MYDC_TEST_RQ6_REMAINING") == "external-maintenance"
	credentials := map[string]registryfixture.BasicCredential{"fixture": {Username: usernameA, Password: passwordA}, "second": {Username: usernameB, Password: passwordB}}
	if maintenance {
		credentials["fixture"] = registryfixture.BasicCredential{Username: usernameA, Password: passwordA, DeleteStatus: 202}
		credentials["second"] = registryfixture.BasicCredential{Username: usernameB, Password: passwordB, DeleteStatus: 403}
		credentials["unsupported"] = registryfixture.BasicCredential{Username: usernameB, Password: passwordB} // default DELETE 405
	}
	remote := registryfixture.OpenPrivatePrepared(t, os.Getenv("MYDC_DOCKER_TEST_BACKEND"), container.Config{Cmd: []string{"/backend"}, User: "10001:10001", Volumes: map[string]struct{}{"/data": {}}, Labels: map[string]string{"org.mydc.test.owner": public["Tag"].(string)}}, credentials)
	f := &externalRegistryAppNative{remote: remote, user: user, peer: peer, session: session, root: root, reference: remote.Reference, config: remote.ConfigDigest, values: [][]byte{[]byte(usernameA), []byte(passwordA), []byte(usernameB), []byte(passwordB), remote.Certificate, []byte("private-native-group-password")}}
	_, f.manifest, _ = strings.Cut(remote.Reference, "@")
	f.public, f.save = public, save
	f.cli = &managedRegistryNative{}
	f.cli.prepareCLI(t, ctx, root, p.Cluster, peer)
	run := f.cli.runCLI
	f.cli.runCLI = func(inputs []*os.File, args ...string) ([]byte, []byte, error) {
		output, diagnostic, err := run(inputs, args...)
		f.publicBytes(t, "external CLI response", output)
		f.publicBytes(t, "external CLI diagnostic", diagnostic)
		return output, diagnostic, err
	}
	f.cli.externalNativeValues(t, root, map[string][]byte{"USER_A": []byte(usernameA), "PASS_A": []byte(passwordA), "USER_B": []byte(usernameB), "PASS_B": []byte(passwordB), "CA": remote.Certificate})
	users, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	trust := append(tenant.ImageSources, access.TrustRule{Registry: remote.Registry, Repository: "fixture"}, access.TrustRule{Registry: remote.Registry, Repository: "second"})
	if maintenance {
		trust = append(trust, access.TrustRule{Registry: remote.Registry, Repository: "unsupported"})
	}
	change("external-app-trust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant", Rules: trust})
	// A closed, previously owned numeric endpoint exercises connection refusal,
	// separately from a reachable registry's repository-specific HTTP 401.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unavailable := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	sources := []struct{ id, authority, repository, username, password string }{
		{"external-app", remote.Registry, "fixture", "USER_A", "PASS_A"},
		{"external-second", remote.Registry, "second", "USER_B", "PASS_B"},
		{"external-offline", unavailable, "fixture", "USER_A", "PASS_A"},
	}
	if maintenance {
		sources = append(sources, struct{ id, authority, repository, username, password string }{"external-unsupported", remote.Registry, "unsupported", "USER_B", "PASS_B"})
	}
	for _, selected := range sources {
		spec := imagesource.Source{Tenant: "tenant", ID: selected.id, Authority: selected.authority, Repository: selected.repository, Enabled: true, Auth: "password", Credential: &imagesource.Credential{Realm: "tenant", ID: "registry-auth", UsernameKey: selected.username, PasswordKey: selected.password}, CA: &imagesource.CertificateAuthority{Realm: "tenant", ID: "registry-auth", Key: "CA"}}
		change(selected.id+"-put", "put-external-registry", 0, control.ExternalRegistryPut{Spec: spec})
		f.cli.bindExternalNative(t, root, selected.id, selected.id+"-bind")
		entries, err := p.ExternalRegistries(read().State)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			if entry.Spec.ID == selected.id && entry.Spec.Tenant == "tenant" && entry.Reader != nil && !entry.Reader.Draining {
				if len(entry.Reader.Grants) != 1 || entry.Reader.Grants[0].Use.Purpose != "registry-source" {
					t.Fatal("private source lost its independent approved reader")
				}
				f.readers = append(f.readers, *entry.Reader)
				found = true
			}
		}
		if !found {
			t.Fatal("original external reader missing", selected.id)
		}
	}
	if maintenance {
		// The finite DELETE scope consumes these same installed readers and
		// original credentials without deploying an app or repeating query/build cases.
		f.verifyExternalRegistryMaintenanceNative(t, ctx, r, p, read, change)
		return f
	}
	f.probe(t, "external-app", remote.Reference, "OK")
	remote.DenyPrivate("second", true)
	f.probe(t, "external-second", remote.PrivateReference("second"), "UNAUTHORIZED")
	remote.DenyPrivate("second", false)
	f.probe(t, "external-second", remote.PrivateReference("second"), "OK")
	f.probe(t, "external-offline", "", "UNAVAILABLE")
	change("external-app-foreign-tenant", "create-tenant", 0, control.TenantID{ID: "foreign"})
	f.verifyPrivateImageQueriesNative(t, ctx, p, read, change)
	before, _ := remote.PrivateStats("fixture")
	for _, denied := range []struct{ tenant, image string }{
		{"foreign", remote.Reference},
		{"tenant", unavailable + strings.TrimPrefix(remote.Reference, remote.Registry)},
		{"tenant", remote.PrivateReference("second")},
	} {
		if _, err := user.ProbeExternalRegistry(ctx, peer, session, denied.tenant, control.ExternalRegistryProbeQuery{ID: "external-app", Image: denied.image}); err == nil {
			t.Fatal("external credential escaped its exact tenant/authority/repository")
		}
	}
	after, _ := remote.PrivateStats("fixture")
	if after != before {
		t.Fatal("denied scope reached the original private repository")
	}
	for _, id := range []string{f.config, f.manifest} {
		if _, err = r.docker.API.ImageInspect(ctx, id); !cerrdefs.IsNotFound(err) {
			t.Fatal("external app must load its own uncached immutable image", err)
		}
	}
	// Both stores use a content ID: legacy config or preserved OCI manifest.
	// Record the exact two candidates before ImageLoad; cleanup still verifies
	// this fixture's image ownership label before removing either one.
	public["Image"], public["ExternalAppReference"], public["ExternalAppAuthority"] = f.manifest, remote.Reference, remote.Registry
	public["OwnedImageIDs"] = []string{f.config, f.manifest}
	save()
	source.Reference, source.Registry = remote.Reference, remote.Registry
	source.ConfigDigest, source.LayerDigest = remote.ConfigDigest, remote.LayerDigest
	f.authorized, _ = remote.PrivateStats("fixture")
	f.blobs = remote.Blobs.Load()
	f.publicState(t, r, read())
	return f
}

func (f *externalRegistryAppNative) publicBytes(t *testing.T, label string, raw []byte) {
	t.Helper()
	for _, value := range f.values {
		quoted, _ := json.Marshal(string(value))
		if bytes.Contains(raw, value) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(value))) || len(quoted) > 2 && bytes.Contains(raw, quoted[1:len(quoted)-1]) {
			t.Fatal(label, "contains protected registry input")
		}
	}
}

func (f *externalRegistryAppNative) probe(t *testing.T, id, image, code string) {
	t.Helper()
	args := []string{"registry", "login-test", id, "--tenant", "tenant"}
	if image != "" {
		args = append(args, "--image", image)
	}
	output, _, err := f.cli.runCLI(nil, args...)
	var result control.ExternalRegistryProbeResult
	if json.Unmarshal(output, &result) != nil || result.Code != code {
		t.Fatal("private login-test public outcome", id, "want", code, "got", result.Code, "error", err)
	}
	if code == "OK" && err != nil {
		t.Fatal("private login-test failed", err)
	}
	if code != "OK" {
		var exit interface{ ExitCode() int }
		if !errors.As(err, &exit) || exit.ExitCode() != 3 {
			t.Fatal("private login-test did not return a refused outcome", err)
		}
	}
}

func (f *externalRegistryAppNative) checkRunning(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View) {
	t.Helper()
	view := read()
	apps, err := p.Apps(view.State)
	if err != nil {
		t.Fatal(err)
	}
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	execution, _ := apps.Execution("tenant", "app")
	stage, ok := execution.Stage(key)
	if !ok || stage.Result == nil || stage.Observation == nil || !stage.Observation.Healthy {
		t.Fatal("external app lacks original healthy Task")
	}
	f.task = deployment.ObjectRef{Key: key, Revision: stage.Result.Revision, Generation: stage.Result.Generation}
	f.binding, ok = apps.Binding(f.task)
	if !ok || len(f.binding.ProjectionGrants()) != 1 || len(f.binding.RegistryGrants()) != 1 || !reflect.DeepEqual(f.binding.Needs().RegistrySources, []deployment.Source{{Realm: "tenant", Object: "registry-auth"}}) {
		t.Fatal("external credential was not reserved separately from app projection")
	}
	f.origin, ok = apps.BindingSource(f.binding.Digest())
	if !ok || f.origin.Task != f.task {
		t.Fatal("external app lost original signed binding source")
	}
	grant, projection := f.binding.RegistryGrants()[0], f.binding.ProjectionGrants()[0]
	if grant.Consumer == projection.Consumer || len(grant.Pins) != 1 || len(projection.Pins) != 1 || grant.Pins[0] == projection.Pins[0] {
		t.Fatal("registry input reused the projection consumer/pin")
	}
	native, err := r.docker.API.ContainerInspect(ctx, stage.Observation.Native, client.ContainerInspectOptions{})
	if err != nil || native.Container.State == nil || !native.Container.State.Running || native.Container.Image != f.config && native.Container.Image != f.manifest || native.Container.State.Health == nil || string(native.Container.State.Health.Status) != "healthy" {
		t.Fatal("actual private config did not become a healthy native app", err)
	}
	f.native, f.startedAt = native.Container.ID, native.Container.State.StartedAt
	f.nativeImage = native.Container.Image
	encoded, _ := json.Marshal(native)
	f.publicBytes(t, "native container configuration", encoded)
	loaded, err := r.docker.API.ImageInspect(ctx, f.nativeImage)
	if err != nil || loaded.ID != f.nativeImage || loaded.Config == nil {
		t.Fatal("external ImageLoad did not retain the exact verified native image", err)
	}
	authorized, _ := f.remote.PrivateStats("fixture")
	if authorized <= f.authorized || f.remote.Blobs.Load() <= f.blobs {
		t.Fatal("actual app did not consume private metadata and image blobs")
	}
	page, err := f.user.ExternalRegistryPage(ctx, f.peer, f.session, "tenant", "")
	if err != nil || len(page.ExternalRegistries) != len(f.readers) {
		t.Fatal("actual external source management page", err)
	}
	encoded, _ = json.Marshal(page)
	f.publicBytes(t, "public external source page", encoded)
	reports, err := r.reports.ScanBounded("node-observation/", 256, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	loadedReport := false
	for _, raw := range reports {
		report, err := observability.Decode(raw)
		if err == nil && report.Key == r.Identity.Public && report.RegistryPull != nil && report.RegistryPull.Source == "external-app" && report.RegistryPull.Stage == "load" && report.RegistryPull.Code == "OK" {
			loadedReport = true
		}
	}
	if !loadedReport {
		t.Fatal("actual external Docker load lacks its owner outcome")
	}
	f.public["ExternalAppNativeImage"], f.public["ExternalAppHealthy"] = f.nativeImage, true
	f.save()
	t.Log("actual private HTTPS/Vault/CLI Binding -> verified image load and healthy Docker Task")
	// A remote credential withdrawal must still fail with the config cached.
	// This is the same app permit -> SecretFetch -> Engine boundary used by Task.
	f.remote.DenyPrivate("fixture", true)
	f.probe(t, "external-app", f.reference, "UNAUTHORIZED")
	auth, err := r.appRegistryImageAuth(ctx, f.task, f.binding.Digest(), f.reference)
	if err != nil {
		t.Fatal("unrevoked original app input permit", err)
	}
	_, err = r.docker.ImageWithAuth(ctx, f.reference, true, auth)
	if registryclient.ResultCode(err) != "UNAUTHORIZED" {
		t.Fatal("cached private config bypassed revoked remote credential")
	}
	f.remote.DenyPrivate("fixture", false)
	f.sameNative(t, ctx, r)
	// Revoke the actual provider reference while retaining its original usage.
	// A new app has a distinct, otherwise valid plan and correct Group password.
	// It must fail before any new Binding/native Task, rather than borrowing the
	// accepted app's grant or falling back to anonymous/ambient credentials.
	address := netip.MustParsePrefix(os.Getenv("MYDC_DOCKER_TEST_CIDR")).Addr().Next().Next().Next()
	document := fmt.Sprintf("name: after-revoke\nservices:\n web:\n  image: %s\n  cpus: 0.1\n  mem_limit: 16m\n  networks: {app: {ipv4_address: %s}}\n  x-mydc: {node: node-a}\nnetworks:\n app: {external: true, name: shared-services}\n", f.reference, address)
	file := filepath.Join(f.root, "after-revoke.yaml")
	if err := os.WriteFile(file, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	planned := f.cli.cli(nil, "compose", "plan", "--tenant", "tenant", "-f", file)
	if _, err := deployment.DecodeBlueprint(bytes.TrimSpace(planned)); err != nil {
		t.Fatal("fresh external app planning precondition", err)
	}
	f.cli.cli(nil, "--tenant", "tenant", "secret", "revoke", "--id", "registry-auth", "--request-id", "external-app-revoke-secret")
	if _, err := r.appRegistryImageAuth(ctx, f.task, f.binding.Digest(), f.reference); err == nil {
		t.Fatal("revoked provider reference granted fresh app image access")
	}
	password, err := os.CreateTemp(f.root, "external-app-group-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = password.Close(); _ = os.Remove(password.Name()) }()
	if _, err = password.WriteString("private-native-group-password"); err != nil {
		t.Fatal(err)
	}
	if _, err = password.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	output, _, err := f.cli.runCLI([]*os.File{password}, "compose", "up", "--tenant", "tenant", "-f", file, "--operation", "external-app-after-revoke", "--no-input", "--group-password-fd", "tenant/group=3")
	var exit interface{ ExitCode() int }
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Fatal("fresh app did not reject revoked provider reference", err)
	}
	var denied struct {
		Phase, Status string
	}
	if json.Unmarshal(output, &denied) != nil || denied.Phase != "accept" || denied.Status != "approval-required" {
		t.Fatal("fresh app denial did not identify its original approval boundary")
	}
	f.publicBytes(t, "rejected app response", output)
	apps, err = p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := apps.Inventory("tenant", "after-revoke"); exists {
		t.Fatal("revoked app acquired an inventory")
	}
	f.sameNative(t, ctx, r)
	f.publicState(t, r, read())
}

func (f *externalRegistryAppNative) sameNative(t *testing.T, ctx context.Context, r *Runtime) {
	t.Helper()
	current, err := r.docker.API.ContainerInspect(ctx, f.native, client.ContainerInspectOptions{})
	if err != nil || current.Container.State == nil || !current.Container.State.Running || current.Container.State.StartedAt != f.startedAt || current.Container.Image != f.nativeImage {
		t.Fatal("credential withdrawal replaced/stopped existing private app", err)
	}
}

func (f *externalRegistryAppNative) publicState(t *testing.T, r *Runtime, view cluster.View) {
	t.Helper()
	for _, object := range view.State.Objects("") {
		f.publicBytes(t, "replicated object", []byte(object.Value))
	}
	rows, err := r.reports.ScanBounded("node-observation/", 256, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range rows {
		f.publicBytes(t, "owner observation", raw)
	}
	for _, file := range []string{"compose.yaml", "after-revoke.yaml"} {
		raw, err := os.ReadFile(filepath.Join(f.root, file))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		f.publicBytes(t, "app declaration", raw)
	}
}

func (f *externalRegistryAppNative) checkRecovered(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View) {
	t.Helper()
	f.sameNative(t, ctx, r)
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	bound, ok := apps.Binding(f.task)
	origin, found := apps.BindingSource(f.binding.Digest())
	if !ok || !found || bound.Digest() != f.binding.Digest() || !bytes.Equal(control.OperationBytes(origin.Origin), control.OperationBytes(f.origin.Origin)) || !bytes.Equal(origin.Origin.Signature, f.origin.Origin.Signature) {
		t.Fatal("same DB reopen substituted original private app/grant")
	}
	vault, err := p.Vault(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range f.binding.RegistryGrants() {
		if _, held := vault.Approvals.Usage(grant); !held {
			t.Fatal("revocation/reopen returned live original registry usage")
		}
	}
	result, err := f.user.ObserveContainer(ctx, f.peer, f.session, "tenant", containerops.Query{Schema: 1, Kind: "logs", Selection: containerops.Selection{App: "app", Service: "web"}, Tail: 20, Stdout: true, Stderr: true, MaxBytes: 4096})
	if err != nil || result.Container == nil || result.Container.Target.NativeID != f.native {
		t.Fatal("actual external app log path", err)
	}
	raw, _ := json.Marshal(result)
	f.publicBytes(t, "public app logs", raw)
	f.publicBytes(t, "app stdout", result.Container.Stdout)
	f.publicBytes(t, "app stderr", result.Container.Stderr)
	f.publicState(t, r, read())
}

func (f *externalRegistryAppNative) checkRetired(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	vault, err := p.Vault(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range f.binding.RegistryGrants() {
		if _, held := vault.Approvals.Usage(grant); held {
			t.Fatal("normal app down retained original registry grant")
		}
	}
	for _, reader := range f.readers {
		entries, err := p.ExternalRegistries(read().State)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Spec.Key() == reader.Spec.Key() {
				change("delete-"+reader.Spec.ID, "delete-external-registry", entry.Revision, control.RegistrySelection{Tenant: "tenant", ID: reader.Spec.ID})
			}
		}
		registryNativeWait(t, ctx, "original external app source reader return "+reader.Spec.ID, func() bool {
			entries, err := p.ExternalRegistries(read().State)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Spec.Key() == reader.Spec.Key() && entry.Deleted && entry.Reader == nil && entry.Closed != nil {
					if entry.Closed.Reader.Generation != reader.Generation || !reflect.DeepEqual(entry.Closed.Reader.Grants, reader.Grants) || !bytes.Equal(control.OperationBytes(entry.Closed.Reader.Origin), control.OperationBytes(reader.Origin)) {
						t.Fatal("external source closure substituted original reader")
					}
					return true
				}
			}
			return false
		})
		vault, err = p.Vault(read().State)
		if err != nil {
			t.Fatal(err)
		}
		for _, grant := range reader.Grants {
			if _, held := vault.Approvals.Usage(grant); held {
				t.Fatal("closed original reader retained approval usage")
			}
		}
	}
	f.cli.cli(nil, "--tenant", "tenant", "secret", "retire", "--id", "registry-auth", "--request-id", "external-app-retire-secret")
	f.publicState(t, r, read())
}
