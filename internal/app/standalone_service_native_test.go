// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

func TestRQ9RealStandaloneServiceFieldsAndOriginalRecovery(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppStandaloneService, true, false, true)
}

// The fields/permission/stream prefix is already covered by native13–16. This
// selector retains real create→same-node update→clear→sameDB→retirement, while
// omitting those independent assertions rather than extending fixture budgets.
func TestRQ9RealStandaloneServiceRecreationAndOriginalRecovery(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppStandaloneServiceRecreation, true, false, true)
}

// prepareStandaloneServiceNative belongs in cliChecks[0], immediately after
// the original managed app is healthy. Its returned hook belongs in the same
// fixture's recovered callback. In particular, explicit log recreation runs
// BEFORE verifyManagedTaskVolume seals Vault; recovery subsequently consumes
// the retained original projection without unsealing/replacing the provider.
//
// The caller supplies its FINAL managed app document (external shared-services
// network, retained data Volume, Group-backed password and enabled Ingress).
// This is intentionally a hook, not an independently launched fixture/root.
// This fixture uses the Ingress listener -> service backend port 8080.
// Direct Compose ports have separate fixed/dynamic TCP and UDP native tests.
func prepareStandaloneServiceNative(t *testing.T, ctx context.Context, r *Runtime, root string, document []byte, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), recreationOnly bool) func(*Runtime) {
	t.Helper()
	const name = "service-fields"
	input, err := deployment.ParseApp(document)
	if err != nil || len(input.Services) != 1 || input.Sfc.Ingress == nil || r.ingress == nil {
		t.Fatal("standalone service requires the original single-service/Ingress app input", err)
	}
	service, ok := input.Services["web"]
	if !ok || len(service.Volumes) != 1 || len(service.Secrets) != 1 || len(service.Sfc.Sources) != 1 || service.Healthcheck == nil || service.Sfc.Readiness == nil || service.Environment["SFC_PROJECTION_FILE"] == "" {
		t.Fatal("standalone service requires the original Volume/Secret/Group/health/readiness fields")
	}
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	appExecution, ok := apps.Execution("tenant", "app")
	appKey := deployment.ResourceKey("task", "tenant", "app", "web")
	appStage, staged := appExecution.Stage(appKey)
	if !ok || !staged || appStage.Result == nil || appStage.Observation == nil {
		t.Fatal("original managed app Task and owner observation required")
	}
	appTask := deployment.ObjectRef{Key: appKey, Generation: appStage.Result.Generation, Revision: appStage.Result.Revision}
	appBinding, bound := apps.Binding(appTask)
	appSource, sourced := apps.BindingSource(appBinding.Digest())
	if !bound || !sourced || len(appBinding.Pins()) != 1 || len(appBinding.ProjectionGrants()) != 1 {
		t.Fatal("original app shared consumer references required")
	}
	appNative := appStage.Observation.Native
	appInspect, err := r.docker.API.ContainerInspect(ctx, appNative, client.ContainerInspectOptions{})
	if err != nil || appInspect.Container.Config == nil {
		t.Fatal("original app native process", err)
	}
	unchangedApp := func() {
		t.Helper()
		a, e := p.Apps(read().State)
		b, found := a.Binding(appTask)
		s, exists := a.BindingSource(appBinding.Digest())
		n, nativeErr := r.workload.Status(ctx, appKey)
		if e != nil || !found || !exists || b.Digest() != appBinding.Digest() || !reflect.DeepEqual(s, appSource) || nativeErr != nil || n.NativeID != appNative || !n.Ready {
			t.Fatal("standalone action changed the original app Task/Binding/source/native", e, nativeErr)
		}
	}
	var lastDiagnostic []byte
	call := func(want int, files []*os.File, args ...string) []byte {
		t.Helper()
		out, diagnostic, e := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), append([]string{"--tenant", "tenant"}, args...), files)
		code := 0
		if e != nil {
			if exit, ok := e.(interface{ ExitCode() int }); ok {
				code = exit.ExitCode()
			} else {
				t.Fatal("standalone service CLI transport", e)
			}
		}
		lastDiagnostic = bytes.Clone(diagnostic)
		// Do not print credential-bearing inputs or arbitrary response bodies.
		if code != want {
			// Classify only fixed public errors. Never dump arbitrary stderr,
			// argv, declarations, Secret input or interactive output.
			cause := "unclassified; original journal retained"
			for _, known := range []string{userauth.ErrPrivateState.Error(), userauth.ErrApprovalUnknown.Error(), "original result unknown", "context deadline exceeded", "user request: denied", "user request: invalid", "user request: conflict", "VOLUME_WRITER_CONFLICT"} {
				if bytes.Contains(diagnostic, []byte(known)) {
					cause = known
					break
				}
			}
			method := "unknown"
			if len(args) > 1 {
				method = args[1]
			}
			t.Fatal("standalone service CLI", method, "exit", code, "want", want, "cause", cause)
		}
		if bytes.Contains(out, []byte("private-db-value")) || bytes.Contains(diagnostic, []byte("private-db-value")) || bytes.Contains(diagnostic, []byte("private-native-group-password")) || bytes.Contains(out, []byte("private-native-group-password")) {
			t.Fatal("standalone CLI exposed a Secret or Group password")
		}
		return out
	}
	write := func(file string, c deployment.Compose) string {
		t.Helper()
		raw, e := yaml.Marshal(c)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(root, file+".yaml")
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	fixed := prepareFixedAppNativeSource(t, ctx, r, root, p, read, change)
	fixedState := func() {
		t.Helper()
		info, e := os.Stat(fixed.source)
		value, readErr := os.ReadFile(filepath.Join(fixed.source, "original"))
		if e != nil || !os.SameFile(fixed.before, info) || readErr != nil || string(value) != "preexisting-original" {
			t.Fatal("standalone changed or removed the registered fixed path/data", e, readErr)
		}
	}
	keep := true
	input.Volumes["shared-fixed"] = deployment.ComposeVolume{Name: "data", External: true, Sfc: deployment.VolumeExtension{Driver: "local", Access: "single-writer", Retain: &keep, Quota: "observe"}}
	service.Volumes = append(service.Volumes, deployment.Mount{Type: "volume", Source: "shared-fixed", Target: "/shared"})
	// Keep all service storage/projection/readiness fields. Only workload-owned
	// coordinates and explicit backend process/logging fixture inputs change.
	input.Name, input.Sfc.Deployment = name, "standalone-service-deploy"
	entry, command := deployment.Arguments{"/backend"}, deployment.Arguments{}
	service.Entrypoint, service.Command = &entry, &command
	service.Environment["SFC_OBSERVATION_FIXTURE"] = "1"
	service.Environment["SFC_STANDALONE_UPDATE"] = "initial"
	// Finite Docker exec and the serving Go process share this one cgroup.
	service.Memory = "64m"
	service.Logging = &workload.LogPolicy{Driver: "local", Options: map[string]string{"max-size": "16k", "max-file": "2", "compress": "false"}}
	originalNetworks := make(map[string]deployment.Attachment, len(service.Networks))
	for alias, attachment := range service.Networks {
		originalNetworks[alias] = attachment
		network := input.Networks[alias]
		if !network.External || network.Name != "shared-services" {
			t.Fatal("standalone service needs the original managed external network")
		}
		// The original app's static reservation remains alive. One adjacent
		// explicitly selected address belongs to the standalone Task.
		address, e := netip.ParseAddr(attachment.IPv4)
		prefix, pe := netip.ParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
		if e != nil || pe != nil || !prefix.Contains(address.Next()) {
			t.Fatal("owned fixture address requires room for one standalone")
		}
		attachment.IPv4 = address.Next().String()
		service.Networks[alias] = attachment
	}
	input.Services["web"] = service
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	input.Sfc.Ingress.Listeners = []deployment.ListenerDeclaration{{Address: address}}
	input.Sfc.Ingress.Host = "app.test"
	file := write("standalone-service", input)
	planArgs := []string{"standalone", "run", name, "-f", file, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--dry-run"}
	call(0, nil, planArgs...)
	// A valid plan above is the positive control for the same request with the
	// existing app's address. Denial must preserve its native and source pins.
	collision, e := deployment.ParseStandalone(mustReadStandaloneServiceInput(t, file))
	if e != nil {
		t.Fatal(e)
	}
	collidingService := collision.Services["web"]
	for alias, original := range originalNetworks {
		a := collidingService.Networks[alias]
		a.IPv4 = original.IPv4
		collidingService.Networks[alias] = a
	}
	collision.Services["web"] = collidingService
	collisionFile := write("standalone-service-address-conflict", collision)
	call(1, nil, "standalone", "run", name, "-f", collisionFile, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--dry-run")
	unchangedApp()
	up := func(operation, file string) []byte {
		t.Helper()
		password, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer password.Close()
		_, err = io.WriteString(writer, "private-native-group-password\n")
		_ = writer.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Log("standalone service original up", operation)
		out := call(0, []*os.File{password}, "standalone", "run", name, "-f", file, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--id", operation, "--group-password-fd", "tenant/group=3")
		intent, ie := userauth.LoadCompose(filepath.Join(root, "cli-home"), user, session, operation)
		accepted, ae := userauth.LoadOperation(filepath.Join(root, "cli-home"), user, session, "standalone/"+operation+"/accept")
		var begin control.AppBegin
		if ie != nil || ae != nil || intent.Target == nil || !control.StandaloneCASAllowed(accepted.Operation.Change) || json.Unmarshal(accepted.Operation.Change.Payload, &begin) != nil || begin.Target == nil || *begin.Target != *intent.Target || accepted.Result == nil || accepted.Result.Code != state.Applied {
			t.Fatal("standalone CLI lost original management Target/signature/receipt", ie, ae)
		}
		_ = out
		view, ve := user.AppOperation(ctx, peer, session, "tenant", control.AppOperationRequest{Standalone: name, ID: operation})
		if ve != nil || view.AppOperation == nil {
			t.Fatal("standalone run has no accepted operation", ve)
		}
		raw, _ := json.Marshal(view.AppOperation)
		return raw
	}
	up("service-create", file)
	page := func() control.StandaloneView {
		t.Helper()
		v, e := user.StandalonePage(ctx, peer, session, "tenant", name, "")
		if e != nil || len(v.Standalones) != 1 {
			t.Fatal("standalone service current User page", e)
		}
		return v.Standalones[0]
	}
	selection := containerops.Selection{Standalone: name}
	scope := deployment.StandaloneScopeName("tenant", name)
	key := deployment.ResourceKey("task", "tenant", scope, "web")
	ingressKey := deployment.ResourceKey("ingress", "tenant", scope, "http")
	var target containerops.Target
	running := func() containerops.Target {
		t.Helper()
		wait("standalone service actual health/readiness/Ingress", func() bool {
			status, e := r.workload.Status(ctx, key)
			in, ie := r.ingress.Observe(ingressKey)
			if e != nil || !status.Ready || !status.HealthConfigured || !status.HTTPConfigured || ie != nil || !in.Ready {
				return false
			}
			query := containerops.Query{Schema: 1, Selection: selection, Kind: "stats", MaxBytes: 16384}
			target, e = user.ResolveContainerSession(ctx, peer, session, "tenant", selection, containerops.SessionSpec{Kind: "stats", Query: &query, Interval: time.Second})
			return e == nil && target.NativeID == status.NativeID
		})
		v := page()
		if v.Metadata.Scope != scope || v.Metadata.Lifetime != "fixed" || v.Metadata.Mode != "entrypoint" || len(v.Tasks) != 1 || v.Tasks[0].Kind != "standalone" || v.Tasks[0].Standalone != name {
			t.Fatal("standalone service owner-kind/scope/definition changed")
		}
		return target
	}
	first := running()
	binding := func() (deployment.Binding, control.AppBindingSource) {
		t.Helper()
		a, e := p.Apps(read().State)
		x, found := a.Execution("tenant", scope)
		s, exists := x.Stage(key)
		if e != nil || !found || !exists || s.Result == nil {
			t.Fatal("standalone original Task result", e)
		}
		b, found := a.Binding(deployment.ObjectRef{Key: key, Generation: s.Result.Generation, Revision: s.Result.Revision})
		origin, exists := a.BindingSource(b.Digest())
		if !found || !exists || origin.Task.Key != key || origin.Origin.RequestID == "" || len(b.Pins()) != 2 || len(b.ProjectionGrants()) != 1 || len(b.ProjectionGrants()[0].Pins) == 0 {
			t.Fatal("standalone did not reserve original Task/Volume/approved Group")
		}
		return b, origin
	}
	initialBinding, initialSource := binding()
	verifyNativeStandaloneResourceReads(t, ctx, user, peer, session, name, key, true)
	fixedPin := func(b deployment.Binding) deployment.VolumePin {
		t.Helper()
		for _, pin := range b.Pins() {
			if pin.Scope == fixed.ready.Spec.Scope {
				if !pin.Consumer.Writable || pin.Consumer.Owner != fixed.ready.Owner {
					t.Fatal("standalone did not borrow the original fixed writer")
				}
				return pin
			}
		}
		t.Fatal("standalone Binding lacks the registered tenant fixed Volume")
		return deployment.VolumePin{}
	}
	_ = fixedPin(initialBinding)
	inspect := func(current containerops.Target) string {
		t.Helper()
		n, e := r.docker.API.ContainerInspect(ctx, current.NativeID, client.ContainerInspectOptions{})
		if e != nil || n.Container.Config == nil || n.Container.HostConfig == nil || n.Container.State == nil || n.Container.State.Health == nil || n.Container.State.Health.Status != "healthy" {
			t.Fatal("standalone actual Docker health", e)
		}
		c := n.Container.Config
		if !reflect.DeepEqual([]string(c.Entrypoint), []string{"/backend"}) || len(c.Cmd) != 0 || c.User != appInspect.Container.Config.User || c.WorkingDir != appInspect.Container.Config.WorkingDir || c.Healthcheck == nil || !reflect.DeepEqual(c.Healthcheck.Test, service.Healthcheck.Test) || n.Container.HostConfig.LogConfig.Type != "local" || !reflect.DeepEqual(n.Container.HostConfig.LogConfig.Config, service.Logging.Options) {
			t.Fatal("standalone lost declared process/health/logging fields")
		}
		environment := "SFC_STANDALONE_UPDATE=" + service.Environment["SFC_STANDALONE_UPDATE"]
		declaredEnvironment := false
		for _, value := range c.Env {
			declaredEnvironment = declaredEnvironment || value == environment
		}
		if !declaredEnvironment {
			t.Fatal("standalone native did not consume the current declared environment")
		}
		volume, secret, shared := "", false, false
		for _, m := range n.Container.Mounts {
			if m.Destination == "/shared" && m.RW {
				shared = true
			}
			if m.Destination == "/data" && m.RW {
				volume = m.Name
			}
			if m.Destination == service.Secrets[0].Target && !m.RW {
				secret = true
			}
		}
		if volume == "" || !secret || !shared {
			t.Fatal("standalone lost writable app/fixed Volume or read-only Secret projection")
		}
		source, e := os.Open(fixed.source)
		if e != nil {
			t.Fatal(e)
		}
		e = engine.CheckProcessBindSources(n.Container.State.Pid, []engine.BindSource{{Path: "/shared", DirectoryFD: int(source.Fd())}})
		_ = source.Close()
		if e != nil {
			t.Fatal("standalone native did not mount the registered fixed source inode", e)
		}
		fixedState()
		for _, m := range appInspect.Container.Mounts {
			if m.Destination == "/data" && m.Name == volume {
				t.Fatal("standalone adopted the live app's Volume writer")
			}
		}
		v, e := r.docker.API.VolumeInspect(ctx, volume, client.VolumeInspectOptions{})
		if e != nil {
			t.Fatal(e)
		}
		if data, e := os.ReadFile(filepath.Join(v.Volume.Mountpoint, "marker")); e != nil || string(data) != "volume-original" {
			t.Fatal("standalone nonroot Volume write was not consumed", e)
		}
		return volume
	}
	volume := inspect(first)
	if !recreationOnly {
		// The competitor uses a distinct valid address and no listener, so its
		// refusal cannot be confused with address or Ingress ownership. Its sole
		// conflicting input is a second writable consumer of this fixed source.
		competitor, e := deployment.ParseStandalone(mustReadStandaloneServiceInput(t, file))
		if e != nil {
			t.Fatal(e)
		}
		competitor.Name, competitor.Sfc.Deployment, competitor.Sfc.Ingress = "service-fixed-rival", "service-fixed-rival-deploy", nil
		rivalService := competitor.Services["web"]
		for alias, attachment := range rivalService.Networks {
			a, e := netip.ParseAddr(attachment.IPv4)
			prefix, pe := netip.ParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
			if e != nil || pe != nil || !prefix.Contains(a.Next()) {
				t.Fatal("owned fixture needs a distinct address for the fixed writer rival")
			}
			attachment.IPv4 = a.Next().String()
			rivalService.Networks[alias] = attachment
		}
		competitor.Services["web"] = rivalService
		rivalFile := write("standalone-service-fixed-rival", competitor)
		denial := call(1, nil, "standalone", "run", competitor.Name, "-f", rivalFile, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--dry-run")
		if !bytes.Contains(denial, []byte("VOLUME_WRITER_CONFLICT")) && !bytes.Contains(lastDiagnostic, []byte("VOLUME_WRITER_CONFLICT")) {
			t.Fatal("competing standalone did not report the specific live Volume writer conflict")
		}
		// Change only the /shared mount; the same fixed registration, public name,
		// address, process, app-owned data and Secret/Group fields remain valid.
		rivalService.Volumes = append(deployment.Mounts(nil), rivalService.Volumes...)
		for index, mount := range rivalService.Volumes {
			if mount.Source == "shared-fixed" && mount.Target == "/shared" {
				rivalService.Volumes = append(rivalService.Volumes[:index], rivalService.Volumes[index+1:]...)
				break
			}
		}
		competitor.Services["web"] = rivalService
		rivalFile = write("standalone-service-fixed-rival-positive", competitor)
		call(0, nil, "standalone", "run", competitor.Name, "-f", rivalFile, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--dry-run")
		registry, err := p.Volumes(read().State)
		fixedVolume, exists := registry.Volume(fixed.ready.Spec.Scope)
		if err != nil || !exists || len(fixedVolume.Consumers()) != 1 || fixedVolume.Consumers()[0] != fixedPin(initialBinding).Consumer {
			t.Fatal("rejected rival changed the original retained fixed writer", err)
		}
		rivalPage, err := user.StandalonePage(ctx, peer, session, "tenant", competitor.Name, "")
		if err != nil || len(rivalPage.Standalones) != 0 {
			t.Fatal("read-only rejected rival created a standalone owner", err)
		}
		if running() != first {
			t.Fatal("fixed writer refusal replaced the original standalone")
		}
		fixedState()
		unchangedApp()
		t.Log("actual live fixed writer refused the competing standalone with VOLUME_WRITER_CONFLICT; same input without /shared planned successfully")
	}
	transport := &http.Transport{Proxy: nil}
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	request := func(method, path string, status int) {
		t.Helper()
		q, e := http.NewRequestWithContext(ctx, method, "http://"+address+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		q.Host = "app.test"
		reply, e := httpClient.Do(q)
		if e != nil {
			t.Fatal("standalone actual listener/backend port", e)
		}
		body, readErr := io.ReadAll(io.LimitReader(reply.Body, 4096))
		_ = reply.Body.Close()
		if readErr != nil || reply.StatusCode != status || path == "/ping" && string(body) != "sfc-boundary /ping" {
			t.Fatal("standalone actual listener response", reply.StatusCode, readErr)
		}
	}
	request(http.MethodGet, "/ping", http.StatusOK)
	unchangedApp()
	if !recreationOnly {
		for _, kind := range []string{"logs", "top", "stats", "inspect"} {
			var observed struct{ Target containerops.Target }
			if json.Unmarshal(call(0, nil, "standalone", kind, name), &observed) != nil || observed.Target.NativeID != first.NativeID || observed.Target.Standalone != name {
				t.Fatal("standalone common CLI observation target", kind)
			}
		}
		execArgs := []string{"standalone", "exec", name, "--id", "service-exec", "--", "/backend", "--exec-args-fixture", "standalone service", "literal;$value"}
		output := call(0, nil, execArgs...)
		if !bytes.Contains(output, []byte(`["standalone service","literal;$value"]`)) {
			t.Fatal("standalone CLI exec did not preserve literal argv")
		}
		// Running exec again with the same --id reads the first exec's receipt.
		var repeatedExec, execStatus containerops.ExecStatus
		if json.Unmarshal(call(0, nil, execArgs...), &repeatedExec) != nil || json.Unmarshal(call(0, nil, execArgs...), &execStatus) != nil || repeatedExec.Receipt.ExecID == "" || repeatedExec.Receipt.ExecID != execStatus.Receipt.ExecID || execStatus.Receipt.Phase != containerops.ExecFinished {
			t.Fatal("standalone exec replay did not preserve its original native exec receipt")
		}
		open := func(id string, spec containerops.SessionSpec) (*userauth.ContainerChannel, containerops.SessionIntent) {
			t.Helper()
			target, e := user.ResolveContainerSession(ctx, peer, session, "tenant", selection, spec)
			if e != nil {
				t.Fatal(e)
			}
			intent := containerops.SessionIntent{Schema: 1, Request: id, User: session.User, Session: access.ExactSessionDigest(session), At: time.Now().Unix(), Target: target, Spec: spec}
			intent.Signature = ed25519.Sign(user.Self.Private, containerops.SessionIntentBytes(intent))
			ch, e := user.OpenContainerSession(ctx, peer, session, intent, 10*time.Second)
			if e != nil {
				t.Fatal("standalone common purpose15", e)
			}
			t.Cleanup(func() { _ = ch.Close() })
			return ch, intent
		}
		q := containerops.Query{Schema: 1, Selection: selection, Kind: "logs", Tail: 1, Stdout: true, Stderr: true, MaxBytes: 16384}
		follow, _ := open("service-follow", containerops.SessionSpec{Kind: "logs", Query: &q})
		var logs nativeSessionOutput
		logs.receive(t, follow, func(record containerops.SessionRecord) bool { return record.Kind == "sample" })
		// Drain purpose15 while the same actual listener writes its bounded burst;
		// no detached producer or fixture-specific log transport is introduced.
		httpDone := make(chan error, 1)
		go func() {
			q, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+address+"/logburst?marker=rq9-service-follow", nil)
			if e == nil {
				q.Host = "app.test"
				var reply *http.Response
				reply, e = httpClient.Do(q)
				if e == nil {
					_, e = io.Copy(io.Discard, reply.Body)
					_ = reply.Body.Close()
					if reply.StatusCode != http.StatusNoContent {
						e = fmt.Errorf("owned standalone log input status %d", reply.StatusCode)
					}
				}
			}
			httpDone <- e
		}()
		logs.receive(t, follow, func(containerops.SessionRecord) bool {
			return strings.Contains(logs.stdout.String(), "rq9-service-follow-031:")
		})
		_ = follow.Close()
		if err = <-httpDone; err != nil {
			t.Fatal("standalone actual new log output", err)
		}
		for _, kind := range []string{"top", "stats"} {
			query := containerops.Query{Schema: 1, Selection: selection, Kind: kind, MaxBytes: 16384}
			watch, intent := open("service-watch-"+kind, containerops.SessionSpec{Kind: kind, Query: &query, Interval: time.Second})
			var previous time.Time
			for count := 0; count < 2; {
				record, e := watch.Receive()
				if e != nil || record.Kind == "error" || record.Kind == "end" {
					t.Fatal("standalone actual watch", kind, e)
				}
				if record.Kind == "sample" {
					if record.Sample == nil || record.Sample.Target != intent.Target || !record.Sample.ObservedAt.After(previous) {
						t.Fatal("standalone watch rebound or reused stale sample", kind)
					}
					previous = record.Sample.ObservedAt
					count++
				}
			}
			_ = watch.Close()
		}
		// A real second account first reads successfully, then loses current
		// membership. Its old login cannot override that committed revocation.
		viewerKey, err := identity.Create(filepath.Join(root, "service-viewer"))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(viewerKey.Private)
		change("service-viewer-create", "put-user", 0, access.User{ID: "service-viewer", Username: "service-viewer", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: viewerKey.Public, Enabled: true}}})
		change("service-viewer-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: "service-viewer", Role: access.Viewer, Enabled: true})
		viewer, err := user.Login(ctx, peer, "service-viewer", viewerKey.Private)
		if err != nil {
			t.Fatal(err)
		}
		query := containerops.Query{Schema: 1, Selection: selection, Kind: "stats", MaxBytes: 16384}
		if reply, e := user.ObserveContainer(ctx, peer, viewer, "tenant", query); e != nil || reply.Container == nil || reply.Container.Target.NativeID != first.NativeID {
			t.Fatal("standalone viewer success control", e)
		}
		if _, e := user.ResolveContainerSession(ctx, peer, viewer, "tenant", selection, containerops.SessionSpec{Kind: "exec", Exec: &containerops.ExecSpec{Argv: []string{"/backend", "--exec-args-fixture"}}}); e == nil {
			t.Fatal("standalone viewer created an exec target")
		}
		change("service-foreign-tenant", "create-tenant", 0, control.TenantID{ID: "service-foreign"})
		if _, e := user.ObserveContainer(ctx, peer, viewer, "service-foreign", query); e == nil {
			t.Fatal("standalone cross-tenant observation accepted")
		}
		catalog, err := p.Catalog(read().State)
		member, exists := catalog.Membership("tenant", "service-viewer")
		if err != nil || !exists {
			t.Fatal("current viewer membership", err)
		}
		member.Enabled = false
		expectedMembership := member.Revision
		member.Revision = 0
		change("service-viewer-revoke", "set-membership", expectedMembership, member)
		if _, e := user.ObserveContainer(ctx, peer, viewer, "tenant", query); e == nil {
			t.Fatal("old standalone login bypassed current membership revocation")
		}
		if current := running(); current != first {
			t.Fatal("permission denials replaced the original native lifetime")
		}
		unchangedApp()
	}
	// One new, explicit same-node definition update consumes the existing
	// replacement DAG. Its old native and input writer must close positively
	// before the new Task generation can acquire either retained Volume.
	wait("original standalone execution complete before new definition", func() bool {
		a, e := p.Apps(read().State)
		x, found := a.Execution("tenant", scope)
		return e == nil && found && x.ActiveOperation() == "service-create" && x.Status() == "Succeeded"
	})
	updatedInput, e := deployment.ParseStandalone(mustReadStandaloneServiceInput(t, file))
	if e != nil {
		t.Fatal(e)
	}
	service = updatedInput.Services["web"]
	service.Environment["SFC_STANDALONE_UPDATE"] = "updated"
	updatedInput.Services["web"] = service
	updatedFile := write("standalone-service-updated", updatedInput)
	call(0, nil, "standalone", "run", name, "-f", updatedFile, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--dry-run")
	var updateAccepted control.AppOperationView
	if json.Unmarshal(up("service-update", updatedFile), &updateAccepted) != nil || !updateAccepted.Found || !updateAccepted.Current || updateAccepted.ID != "service-update" || updateAccepted.Operation == nil {
		t.Fatal("same-node standalone update lost its accepted original operation")
	}
	wait("same-node standalone update completes original replacement DAG", func() bool {
		a, err := p.Apps(read().State)
		x, found := a.Execution("tenant", scope)
		status, nativeErr := r.workload.Status(ctx, key)
		return err == nil && found && x.ActiveOperation() == "service-update" && x.Status() == "Succeeded" && nativeErr == nil && status.Ready && status.NativeID != first.NativeID
	})
	updated := running()
	if updated.NativeID == first.NativeID || inspect(updated) != volume {
		t.Fatal("same-node definition update did not replace only the native while preserving Volume data")
	}
	if _, err = r.docker.API.ContainerInspect(ctx, first.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("standalone update retained its original native after replacement", err)
	}
	updatedBinding, updatedSource := binding()
	_ = fixedPin(updatedBinding)
	afterUpdate, err := p.Apps(read().State)
	updatedExecution, exists := afterUpdate.Execution("tenant", scope)
	updatedStage, staged := updatedExecution.Stage(key)
	if err != nil || !exists || !staged || updatedStage.Result == nil || updatedStage.Previous == nil || updatedStage.Previous.Removal == nil {
		t.Fatal("same-node standalone update lost the original native closure proof", err)
	}
	previous, removal := updatedStage.Previous, updatedStage.Previous.Removal
	if previous.Native != first.NativeID || previous.Result.Generation != initialSource.Task.Generation || previous.Result.Revision != initialSource.Task.Revision || !previous.Removed || removal.Drain == nil || removal.Proof == nil || removal.Delete == nil || removal.Drain.Result == nil || removal.Proof.Result == nil || removal.Delete.Result == nil || removal.Drain.Result.Code != state.Applied || removal.Proof.Result.Code != state.Applied || removal.Delete.Result.Code != state.Applied || !(removal.Drain.Result.Index < removal.Proof.Result.Index && removal.Proof.Result.Index < removal.Delete.Result.Index && removal.Delete.Result.Index < updatedStage.Result.Index) || updatedStage.Result.Generation <= previous.Result.Generation {
		t.Fatal("replacement did not preserve positive original drain/proof/delete before its new Task generation")
	}
	if e := schema.VerifyGone(previous.Step.Owner, p.Cluster, key, previous.Result.Generation, []byte(removal.Drain.Command.Value), removal.Gone); e != nil {
		t.Fatal("replacement original native closure signature", e)
	}
	if _, held := afterUpdate.Binding(initialSource.Task); held {
		t.Fatal("same-node replacement retained the old Task Binding")
	}
	if updatedBinding.Digest() == initialBinding.Digest() || updatedSource.Task.Generation <= initialSource.Task.Generation || updatedSource.Origin.RequestID != "standalone/service-update/accept" {
		t.Fatal("same-node replacement reused an old binding or changed the new operation source")
	}
	updatedVault, err := p.Vault(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range initialBinding.ProjectionGrants() {
		if _, held := updatedVault.Approvals.Usage(grant); held {
			t.Fatal("same-node update retained the old Secret/Group usage")
		}
	}
	for _, grant := range updatedBinding.ProjectionGrants() {
		if _, held := updatedVault.Approvals.Usage(grant); !held {
			t.Fatal("same-node update did not reserve the new Secret/Group usage")
		}
	}
	updatedVolumes, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, pin := range updatedBinding.Pins() {
		volumeState, found := updatedVolumes.Volume(pin.Scope)
		if !found || len(volumeState.Consumers()) != 1 || volumeState.Consumers()[0] != pin.Consumer {
			t.Fatal("same-node update did not exclusively reserve the replacement Volume consumer")
		}
		for _, old := range initialBinding.Pins() {
			if old.Key == pin.Key && (old.Scope != pin.Scope || old.Consumer == pin.Consumer) {
				t.Fatal("same-node update changed retained Volume identity or reused its old writer lease")
			}
		}
	}
	updatedInventory, found := afterUpdate.Inventory("tenant", scope)
	if old, exists := updatedInventory.Operation("service-create"); !found || !exists || old.Plan != initialSource.Plan || old.ID != "service-create" {
		t.Fatal("same-node update erased the initial accepted operation history")
	}
	call(0, nil, "standalone", "run", name, "-f", updatedFile, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--id", "service-update")
	replayReply, replayErr := user.AppOperation(ctx, peer, session, "tenant", control.AppOperationRequest{Standalone: name, ID: "service-update"})
	if replayErr != nil || replayReply.AppOperation == nil {
		t.Fatal("same standalone update ID has no accepted operation", replayErr)
	}
	updateReplay := *replayReply.AppOperation
	if !updateReplay.Found || updateReplay.ID != updateAccepted.ID || updateReplay.Tenant != updateAccepted.Tenant || updateReplay.App != updateAccepted.App || updateReplay.Deployment != updateAccepted.Deployment || updateReplay.Operation == nil || updateReplay.Operation.Plan != updateAccepted.Operation.Plan || updateReplay.Operation.Submitter != updateAccepted.Operation.Submitter || updateReplay.Operation.Epoch != updateAccepted.Operation.Epoch {
		t.Fatal("same standalone update ID changed its original accepted operation")
	}
	if running() != updated {
		t.Fatal("same standalone update ID caused a second native replacement")
	}
	replayedBinding, replayedSource := binding()
	if replayedBinding.Digest() != updatedBinding.Digest() || !reflect.DeepEqual(replayedSource, updatedSource) {
		t.Fatal("same standalone update ID replaced its retained binding/source")
	}
	fixedState()
	unchangedApp()
	t.Log("same-node standalone definition update positively closed its old native before the new Task and preserved retained app/fixed Volume data; same ID is result-only")
	// The definition update legitimately replaced the original logs. Produce
	// bounded logs on the new native so the later explicit log-clear still has
	// a positive precondition instead of passing because update discarded logs.
	request(http.MethodPost, "/logburst?marker=rq9-service-update-before-clear", http.StatusNoContent)
	readLogs := func() containerops.Result {
		t.Helper()
		var result containerops.Result
		if json.Unmarshal(call(0, nil, "standalone", "logs", name), &result) != nil || result.Kind != "logs" || result.Target.Standalone != name {
			t.Fatal("standalone actual log JSON result")
		}
		return result
	}
	beforeClearLogs := readLogs()
	if !bytes.Contains(beforeClearLogs.Stdout, []byte("rq9-service-update-before-clear")) && !bytes.Contains(beforeClearLogs.Stderr, []byte("rq9-service-update-before-clear")) {
		t.Fatal("updated standalone did not expose the logs that explicit clear must remove")
	}
	// clear-logs clears each server's stored logs and leaves the container
	// as it is (devel/proposals/seafield-log-clear.md): no plan, no
	// recreate, no operation. Sending it again is the same request.
	for range 2 {
		var cleared struct {
			Nodes []struct{ Node, Code string }
		}
		if raw := call(0, nil, "standalone", "clear-logs", name); json.Unmarshal(raw, &cleared) != nil || len(cleared.Nodes) == 0 {
			t.Fatal("standalone log clear reply")
		}
		for _, n := range cleared.Nodes {
			if n.Code != "ok" {
				t.Fatal("standalone log clear server answer", n.Node, n.Code)
			}
		}
	}
	afterClear := running()
	if afterClear != updated || inspect(afterClear) != volume {
		t.Fatal("standalone log clear touched the container or its Volume")
	}
	currentBinding, currentSource := binding()
	_ = fixedPin(currentBinding)
	unchangedApp()
	return func(next *Runtime) {
		r = next
		if running() != afterClear || inspect(afterClear) != volume {
			t.Fatal("same DB reopen lost standalone Task/native/Volume/health")
		}
		b, s := binding()
		if b.Digest() != currentBinding.Digest() || !reflect.DeepEqual(s, currentSource) {
			t.Fatal("daemon recovery replaced original standalone Binding/source")
		}
		request(http.MethodGet, "/ping", http.StatusOK)
		unchangedApp()
		call(1, nil, "compose", "down", "-p", scope, "--operation", "service-deny-app-down")
		if running() != afterClear {
			t.Fatal("ordinary app down adopted standalone")
		}
		call(0, nil, "standalone", "remove", name, "--id", "service-remove")
		wait("standalone service original owned retirement", func() bool {
			a, e := p.Apps(read().State)
			inv, found := a.Inventory("tenant", scope)
			gone, ge := r.docker.Gone(ctx, "container", key)
			return e == nil && found && inv.Quiescent() && ge == nil && gone
		})
		verifyNativeStandaloneResourceReads(t, ctx, user, peer, session, name, key, false)
		if connection, e := (&net.Dialer{}).DialContext(ctx, "tcp", address); e == nil {
			_ = connection.Close()
			t.Fatal("retired standalone retained its owned ingress listener")
		}
		vault, e := p.Vault(read().State)
		if e != nil {
			t.Fatal(e)
		}
		for _, binding := range []deployment.Binding{initialBinding, updatedBinding, currentBinding} {
			for _, grant := range binding.ProjectionGrants() {
				if _, held := vault.Approvals.Usage(grant); held {
					t.Fatal("retired standalone retained original Secret/Group usage")
				}
			}
		}
		volumes, e := p.Volumes(read().State)
		if e != nil {
			t.Fatal(e)
		}
		for _, pin := range currentBinding.Pins() {
			state, found := volumes.Volume(pin.Scope)
			if !found || len(state.Consumers()) != 0 {
				t.Fatal("standalone retirement did not return its exact Volume consumer")
			}
		}
		for _, grant := range appBinding.ProjectionGrants() {
			if _, held := vault.Approvals.Usage(grant); !held {
				t.Fatal("standalone retirement returned the live app's approval usage")
			}
		}
		if got := inspectRetainedStandaloneServiceVolume(t, ctx, r, volume); got != "volume-original" {
			t.Fatal("standalone retirement deleted retained Volume data")
		}
		fixedState()
		unchangedApp()
	}
}

func mustReadStandaloneServiceInput(t *testing.T, file string) []byte {
	t.Helper()
	value, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func inspectRetainedStandaloneServiceVolume(t *testing.T, ctx context.Context, r *Runtime, name string) string {
	t.Helper()
	v, err := r.docker.API.VolumeInspect(ctx, name, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal("retained standalone Volume", err)
	}
	value, err := os.ReadFile(filepath.Join(v.Volume.Mountpoint, "marker"))
	if err != nil {
		t.Fatal("retained standalone Volume data", err)
	}
	return string(value)
}
