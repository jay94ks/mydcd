// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

// Uses the existing private Engine/backend, managed network, CLI wallet,
// original app lifetime, same-DB reopen and rollback; no extra daemon/image.
func TestRealAppAndStandaloneComposeTCPUDPPublishingAndOriginalRecovery(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppPublishedPorts, true, false, false)
}

type managedPublishedPorts struct{ app, standalone string }

func ownedPublishedAddress(t *testing.T) string {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := tcp.Addr().String()
	udpAddress, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", udpAddress)
	if err != nil {
		_ = tcp.Close()
		t.Fatal("owned TCP/UDP fixture port unavailable", err)
	}
	if err = udp.Close(); err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	if err = tcp.Close(); err != nil {
		t.Fatal(err)
	}
	// Release only the two fixture sockets. Docker's original bind can still
	// explicitly fail; the test never retries with another operation or port.
	return address
}
func publishingIntent(t *testing.T, address string) []workload.PublishedPort {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := workload.NormalizePublishedPorts([]workload.PublishedPort{{Target: 8080, HostIP: host, Published: port}, {Target: 53100, HostIP: host, Published: port, Protocol: "udp"}})
	if err != nil {
		t.Fatal(err)
	}
	return ports
}
func prepareManagedPublishedPortsDocument(t *testing.T, document []byte) ([]byte, *managedPublishedPorts) {
	t.Helper()
	input, err := deployment.ParseApp(document)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &managedPublishedPorts{app: ownedPublishedAddress(t), standalone: ownedPublishedAddress(t)}
	if fixture.app == fixture.standalone {
		t.Fatal("fixture selected the same free port twice")
	}
	service := input.Services["web"]
	service.Ports = publishingIntent(t, fixture.app)
	if service.Environment == nil {
		service.Environment = deployment.Environment{}
	}
	service.Environment["SFC_PUBLISHED_PORTS_FIXTURE"] = "1"
	service.Memory = "64m"
	input.Services["web"] = service
	raw, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return raw, fixture
}
func publishedEcho(ctx context.Context, address string) error {
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: time.Second}
	q, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/ping", nil)
	if err != nil {
		return err
	}
	reply, err := httpClient.Do(q)
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(reply.Body, 128))
	_ = reply.Body.Close()
	if readErr != nil || reply.StatusCode != http.StatusOK || string(body) != "sfc-boundary /ping" {
		return fmt.Errorf("published TCP response differs")
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "udp4", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	payload := []byte("owned-compose-published-udp")
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	data := make([]byte, 128)
	n, err := conn.Read(data)
	if err != nil {
		return err
	}
	if !bytes.Equal(data[:n], payload) {
		return fmt.Errorf("published UDP response differs")
	}
	return nil
}
func closedPublishedAddress(t *testing.T, ctx context.Context, address string) {
	t.Helper()
	if conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", address); err == nil {
		_ = conn.Close()
		t.Fatal("retired original retained published TCP port")
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "udp4", address)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err = conn.Write([]byte("owned-compose-published-udp"))
	if err != nil {
		return
	}
	data := make([]byte, 128)
	if _, err = conn.Read(data); err == nil {
		t.Fatal("retired original retained published UDP echo")
	}
}
func (f *managedPublishedPorts) assertClosed(t *testing.T, ctx context.Context) {
	closedPublishedAddress(t, ctx, f.app)
	closedPublishedAddress(t, ctx, f.standalone)
}

func prepareManagedPublishedPortsNative(t *testing.T, ctx context.Context, r *Runtime, root string, document []byte, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, wait func(string, func() bool), ports *managedPublishedPorts) func(*Runtime) {
	t.Helper()
	inspect := func(key, address string) string {
		t.Helper()
		status, err := r.workload.Status(ctx, key)
		if err != nil || !status.Ready {
			t.Fatal("published exact Task unavailable", err)
		}
		got, err := r.docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
		if err != nil || got.Container.State == nil || !got.Container.State.Running || got.Container.Config == nil || got.Container.HostConfig == nil || got.Container.NetworkSettings == nil {
			t.Fatal("published actual Docker inspection", err)
		}
		_, hostPort, _ := net.SplitHostPort(address)
		for _, target := range []string{"8080/tcp", "53100/udp"} {
			port := dockernet.MustParsePort(target)
			configured := got.Container.HostConfig.PortBindings[port]
			actual := got.Container.NetworkSettings.Ports[port]
			if len(configured) != 1 || len(actual) != 1 || configured[0].HostPort != hostPort || actual[0].HostPort != hostPort || configured[0].HostIP != netip.MustParseAddr("127.0.0.1") || actual[0].HostIP != configured[0].HostIP {
				t.Fatal("Docker lost declared TCP/UDP publication", target)
			}
			if _, present := got.Container.Config.ExposedPorts[port]; !present {
				t.Fatal("Docker target exposure missing", target)
			}
		}
		if err = publishedEcho(ctx, address); err != nil {
			t.Fatal("actual host TCP/UDP publishing", err)
		}
		return status.NativeID
	}
	appKey := deployment.ResourceKey("task", "tenant", "app", "web")
	appNative := inspect(appKey, ports.app)
	binding := func(scope, key string) (deployment.Binding, control.AppBindingSource) {
		t.Helper()
		apps, err := p.Apps(read().State)
		execution, ok := apps.Execution("tenant", scope)
		stage, staged := execution.Stage(key)
		if err != nil || !ok || !staged || stage.Result == nil {
			t.Fatal("published original execution", err)
		}
		b, ok := apps.Binding(deployment.ObjectRef{Key: key, Revision: stage.Result.Revision, Generation: stage.Result.Generation})
		source, found := apps.BindingSource(b.Digest())
		if !ok || !found {
			t.Fatal("published original Binding/source missing")
		}
		return b, source
	}
	appBinding, appSource := binding("app", appKey)
	var lastDiagnostic []byte
	call := func(want int, args ...string) []byte {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), append([]string{"--tenant", "tenant"}, args...), nil)
		lastDiagnostic = bytes.Clone(diagnostic)
		code := 0
		if err != nil {
			if exit, ok := err.(interface{ ExitCode() int }); ok {
				code = exit.ExitCode()
			} else {
				t.Fatal("published CLI transport", err)
			}
		}
		if code != want {
			t.Fatal("published CLI exit", code, "want", want)
		}
		return out
	}
	const name = "published-service"
	input, err := deployment.ParseApp(document)
	if err != nil {
		t.Fatal(err)
	}
	input.Name, input.Sfc.Deployment, input.Sfc.Ingress = name, "published-service-deploy", nil
	input.Volumes = nil
	input.Secrets = nil
	service := input.Services["web"]
	service.Volumes = nil
	// The shared fixture image declares VOLUME /data. Cover it explicitly
	// without borrowing the live app writer or creating anonymous storage.
	service.Tmpfs = []string{"/data:size=1m,uid=10001,gid=10001,mode=0700"}
	service.Secrets = nil
	service.Sfc.Sources = nil
	service.Healthcheck = nil
	delete(service.Environment, "SFC_VOLUME_FIXTURE")
	delete(service.Environment, "SFC_VOLUME_SECOND_FIXTURE")
	delete(service.Environment, "SFC_PROJECTION_FILE")
	service.Ports = publishingIntent(t, ports.standalone)
	for alias, attachment := range service.Networks {
		a, e := netip.ParseAddr(attachment.IPv4)
		prefix, pe := netip.ParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
		if e != nil || pe != nil || !prefix.Contains(a.Next()) {
			t.Fatal("fixture requires one adjacent standalone address")
		}
		attachment.IPv4 = a.Next().String()
		service.Networks[alias] = attachment
	}
	input.Services["web"] = service
	write := func(filename string, input deployment.Compose) string {
		t.Helper()
		raw, e := yaml.Marshal(input)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(root, filename)
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	path := write("published-standalone.yaml", input)
	args := []string{"standalone", "run", name, "-f", path, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--dry-run"}
	call(0, args...)
	// Change only the port intent to the still-live app's original socket. The
	// valid positive plan proves address/quota/trust prerequisites above.
	rival := input
	rival.Services = map[string]deployment.ComposeService{"web": service}
	rivalService := service
	rivalService.Ports = publishingIntent(t, ports.app)
	rival.Services["web"] = rivalService
	conflict := write("published-conflict.yaml", rival)
	denied := call(1, "standalone", "run", name, "-f", conflict, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--dry-run")
	if !bytes.Contains(denied, []byte("HOST_PORT_CONFLICT")) && !bytes.Contains(lastDiagnostic, []byte("HOST_PORT_CONFLICT")) {
		t.Fatal("valid rival did not reach the specific deterministic host-port conflict")
	}
	call(0, "standalone", "run", name, "-f", path, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--id", "published-create")
	scope := deployment.StandaloneScopeName("tenant", name)
	key := deployment.ResourceKey("task", "tenant", scope, "web")
	running := func() containerops.Target {
		t.Helper()
		var target containerops.Target
		wait("published standalone exact current Task/native", func() bool {
			status, e := r.workload.Status(ctx, key)
			if e != nil || !status.Ready {
				return false
			}
			selection := containerops.Selection{Standalone: name}
			query := containerops.Query{Schema: 1, Selection: selection, Kind: "stats", MaxBytes: 16384}
			target, e = user.ResolveContainerSession(ctx, peer, session, "tenant", selection, containerops.SessionSpec{Kind: "stats", Query: &query, Interval: time.Second})
			return e == nil && target.NativeID == status.NativeID && target.StartedAt == status.StartedAt && publishedEcho(ctx, ports.standalone) == nil
		})
		return target
	}
	original := running()
	if inspect(key, ports.standalone) != original.NativeID {
		t.Fatal("standalone native changed")
	}
	standaloneBinding, standaloneSource := binding(scope, key)
	controlDone := func(operation string, running bool) {
		wait("original published standalone control "+operation, func() bool {
			apps, e := p.Apps(read().State)
			record, ok := apps.TaskRestart("tenant", scope, operation)
			if e != nil || !ok || record.Control == nil || record.Control.Phase != checker.ControlCompleted {
				return false
			}
			got, e := r.docker.API.ContainerInspect(ctx, original.NativeID, client.ContainerInspectOptions{})
			return e == nil && got.Container.State != nil && got.Container.State.Running == running
		})
	}
	call(0, "standalone", "stop", name, "--id", "published-stop")
	controlDone("published-stop", false)
	closedPublishedAddress(t, ctx, ports.standalone)
	call(0, "standalone", "start", name, "--id", "published-start")
	controlDone("published-start", true)
	afterStart := running()
	if afterStart.NativeID != original.NativeID || afterStart.StartedAt == original.StartedAt {
		t.Fatal("stop/start recreated or did not restart original published container")
	}
	if inspect(key, ports.standalone) != original.NativeID || inspect(appKey, ports.app) != appNative {
		t.Fatal("control changed another exact native")
	}
	return func(next *Runtime) {
		r = next
		recovered := running()
		if recovered.NativeID != original.NativeID || recovered.StartedAt != afterStart.StartedAt || inspect(key, ports.standalone) != original.NativeID || inspect(appKey, ports.app) != appNative {
			t.Fatal("same-DB recovery recreated published original")
		}
		for _, entry := range []struct {
			scope, key string
			binding    deployment.Binding
			source     control.AppBindingSource
		}{{scope, key, standaloneBinding, standaloneSource}, {"app", appKey, appBinding, appSource}} {
			b, s := binding(entry.scope, entry.key)
			if b.Digest() != entry.binding.Digest() || !reflect.DeepEqual(s, entry.source) {
				t.Fatal("publishing/control/recovery replaced original source")
			}
		}
		call(0, "standalone", "remove", name, "--id", "published-remove")
		wait("published original native retirement", func() bool {
			apps, e := p.Apps(read().State)
			inv, ok := apps.Inventory("tenant", scope)
			gone, ge := r.docker.Gone(ctx, "container", key)
			return e == nil && ok && inv.Quiescent() && ge == nil && gone
		})
		closedPublishedAddress(t, ctx, ports.standalone)
		if inspect(appKey, ports.app) != appNative {
			t.Fatal("standalone removal changed original app publication")
		}
	}
}
