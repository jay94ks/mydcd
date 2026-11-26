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
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

func TestRealAppAndStandaloneComposeDynamicRangeAllocationAndOriginalRecovery(t *testing.T) {
	runManagedAppOwner(t, true, true, false, true, managedAppAllocatedPorts, true, false, false)
}

// Follow-up hooks for the SAME runManagedAppOwner lifecycle as fixed ports.
// Wiring: a separate scenario calls prepareManagedAllocatedPortsDocument before
// prepareManagedComposeCLI; cliChecks[0] calls prepareManagedAllocatedPortsNative
// after the original app check, its returned function is the existing recovered
// callback, and cliChecks[2] calls fixture.assertClosed after original app down.
// No alternate fixture, root setup, cleanup or daemon belongs in this file.
type allocatedPublishedCase struct {
	target                    uint32
	protocol, host, published string
	explicitZero              bool
}

func (c allocatedPublishedCase) key() string {
	return fmt.Sprintf("%d/%s@%s", c.target, c.protocol, c.host)
}

type allocatedPublishedSnapshot struct {
	native, started string
	selected        map[string]netip.AddrPort
}
type managedAllocatedPorts struct {
	cases           []allocatedPublishedCase
	app, standalone allocatedPublishedSnapshot
}

func prepareManagedAllocatedPortsDocument(t *testing.T, document []byte) ([]byte, *managedAllocatedPorts) {
	t.Helper()
	input, err := deployment.ParseApp(document)
	if err != nil {
		t.Fatal(err)
	}
	// Only the fixture's existing finite free-socket preflight is reused. This
	// is not a reservation of this range: Docker chooses and binds, or the
	// original operation explicitly fails; no retry/new port/ID is manufactured.
	_, free, _ := net.SplitHostPort(ownedPublishedAddress(t))
	first, e := strconv.ParseUint(free, 10, 16)
	if e != nil || first == 0 || first > 65532 {
		t.Fatal("fixture requires one bounded Docker selection range")
	}
	selectionRange := fmt.Sprintf("%d-%d", first, first+3)
	f := &managedAllocatedPorts{cases: []allocatedPublishedCase{
		{target: 8080, protocol: "tcp", host: "127.0.0.1"},
		{target: 33100, protocol: "tcp", host: "127.0.0.1", explicitZero: true},
		{target: 33101, protocol: "tcp", host: "127.0.0.1", published: selectionRange},
		{target: 53100, protocol: "udp", host: "127.0.0.1"},
		{target: 53101, protocol: "udp", host: "127.0.0.1", explicitZero: true},
		// The existing UDP echo target accepts both host bindings. Distinct exact
		// host IPs keep omitted/zero/range forms independently observable.
		{target: 53100, protocol: "udp", host: "127.0.0.2", published: selectionRange},
	}}
	service := input.Services["web"]
	service.Ports = f.intent(t)
	if service.Environment == nil {
		service.Environment = deployment.Environment{}
	}
	service.Environment["MYDC_PUBLISHED_PORTS_FIXTURE"] = "1"
	service.Memory = "64m"
	input.Services["web"] = service
	return f.document(t, input), f
}
func (f *managedAllocatedPorts) intent(t *testing.T) []workload.PublishedPort {
	t.Helper()
	var ports []workload.PublishedPort
	for _, c := range f.cases {
		ports = append(ports, workload.PublishedPort{Target: c.target, HostIP: c.host, Published: c.published, Protocol: c.protocol})
	}
	ports, err := workload.NormalizePublishedPorts(ports)
	if err != nil {
		t.Fatal(err)
	}
	return ports
}
func (f *managedAllocatedPorts) document(t *testing.T, input deployment.Compose) []byte {
	t.Helper()
	raw, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var tree yaml.Node
	if err = yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	field := func(n *yaml.Node, name string) *yaml.Node {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == name {
				return n.Content[i+1]
			}
		}
		return nil
	}
	root := tree.Content[0]
	services := field(root, "services")
	web := field(services, "web")
	ports := field(web, "ports")
	if ports == nil || len(ports.Content) != len(f.cases) {
		t.Fatal("allocation fixture lost normalized port intent")
	}
	zeroCount, omittedCount := 0, 0
	for _, entry := range ports.Content {
		var port workload.PublishedPort
		if err = entry.Decode(&port); err != nil {
			t.Fatal(err)
		}
		matched := false
		for _, c := range f.cases {
			if port.Target != c.target || port.Protocol != c.protocol || port.HostIP != c.host {
				continue
			}
			matched = true
			published := field(entry, "published")
			if c.explicitZero {
				if published != nil {
					t.Fatal("zero fixture unexpectedly had a fixed/range publication")
				}
				entry.Content = append(entry.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "published"}, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "0"})
				zeroCount++
			} else if c.published == "" {
				if published != nil {
					t.Fatal("omitted publication was materialized before submission")
				}
				omittedCount++
			}
			break
		}
		if !matched {
			t.Fatal("allocation fixture contains an undeclared target")
		}
	}
	if zeroCount != 2 || omittedCount != 2 {
		t.Fatal("omitted/explicit zero TCP/UDP inputs were not separately present")
	}
	raw, err = yaml.Marshal(&tree)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the real parser on the actual bytes sent by the CLI, retaining
	// explicit zero in OriginalDocument while the shared effective intent is nil.
	var parsed deployment.Compose
	if input.Standalone {
		parsed, err = deployment.ParseStandalone(raw)
	} else {
		parsed, err = deployment.ParseApp(raw)
	}
	if err != nil || !slices.Equal(parsed.Services["web"].Ports, f.intent(t)) {
		t.Fatal("actual omitted/zero/range input changed meaning", err)
	}
	return raw
}

func allocatedPublishedNumber(want, got string, selected bool) bool {
	if !selected && (want == got || want == "" && got == "0") {
		return true
	}
	n, err := strconv.ParseUint(got, 10, 16)
	if err != nil || n == 0 {
		return false
	}
	if want == "" {
		return true
	}
	r, err := dockernet.ParsePortRange(want)
	return err == nil && uint16(n) >= r.Start() && uint16(n) <= r.End()
}
func (f *managedAllocatedPorts) inspect(ctx context.Context, r *Runtime, key string) (allocatedPublishedSnapshot, error) {
	out := allocatedPublishedSnapshot{selected: map[string]netip.AddrPort{}}
	status, err := r.workload.Status(ctx, key)
	if err != nil {
		return out, err
	}
	if !status.Ready {
		return out, fmt.Errorf("exact original Task not ready")
	}
	got, err := r.docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
	if err != nil {
		return out, err
	}
	c := got.Container
	if c.Config == nil || c.HostConfig == nil || c.NetworkSettings == nil || c.State == nil || !c.State.Running || c.HostConfig.PublishAllPorts || c.ID != status.NativeID || c.State.StartedAt == "" {
		return out, fmt.Errorf("exact owned Docker allocation unavailable")
	}
	out.native, out.started = c.ID, c.State.StartedAt
	totalConfigured, totalSelected := 0, 0
	for _, b := range c.HostConfig.PortBindings {
		totalConfigured += len(b)
	}
	for _, b := range c.NetworkSettings.Ports {
		totalSelected += len(b)
	}
	if totalConfigured != len(f.cases) || totalSelected != len(f.cases) {
		return out, fmt.Errorf("unexpected configured/selected binding count")
	}
	for _, want := range f.cases {
		target, ok := dockernet.PortFrom(uint16(want.target), dockernet.IPProtocol(want.protocol))
		if !ok {
			return out, fmt.Errorf("invalid fixture target")
		}
		if _, ok = c.Config.ExposedPorts[target]; !ok {
			return out, fmt.Errorf("declared target was not exposed")
		}
		host := netip.MustParseAddr(want.host)
		configured, selected := 0, 0
		for _, b := range c.HostConfig.PortBindings[target] {
			if b.HostIP == host {
				if !allocatedPublishedNumber(want.published, b.HostPort, false) {
					return out, fmt.Errorf("configured binding changed original intent")
				}
				configured++
			}
		}
		for _, b := range c.NetworkSettings.Ports[target] {
			if b.HostIP == host {
				if !allocatedPublishedNumber(want.published, b.HostPort, true) {
					return out, fmt.Errorf("selected port not within original dynamic/range intent")
				}
				n, _ := strconv.ParseUint(b.HostPort, 10, 16)
				out.selected[want.key()] = netip.AddrPortFrom(host, uint16(n))
				selected++
			}
		}
		if configured != 1 || selected != 1 {
			return out, fmt.Errorf("exact target/protocol/host binding missing or duplicated")
		}
	}
	return out, nil
}
func allocatedPublishedEcho(ctx context.Context, c allocatedPublishedCase, address netip.AddrPort) error {
	if c.target == 8080 && c.protocol == "tcp" {
		transport := &http.Transport{Proxy: nil}
		defer transport.CloseIdleConnections()
		q, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address.String()+"/ping", nil)
		if err != nil {
			return err
		}
		reply, err := (&http.Client{Transport: transport, Timeout: time.Second}).Do(q)
		if err != nil {
			return err
		}
		body, e := io.ReadAll(io.LimitReader(reply.Body, 128))
		_ = reply.Body.Close()
		if e != nil || reply.StatusCode != http.StatusOK || string(body) != "mydc-boundary /ping" {
			return fmt.Errorf("dynamic HTTP target response changed")
		}
		return nil
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, c.protocol+"4", address.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	payload := []byte("owned-compose-allocated-" + c.key())
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	data := make([]byte, len(payload))
	if c.protocol == "tcp" {
		_, err = io.ReadFull(conn, data)
	} else {
		var n int
		n, err = conn.Read(data)
		if err == nil && n != len(payload) {
			return fmt.Errorf("UDP allocation echo length changed")
		}
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(data, payload) {
		return fmt.Errorf("allocation echo changed")
	}
	return nil
}
func (f *managedAllocatedPorts) live(ctx context.Context, r *Runtime, key string) (allocatedPublishedSnapshot, error) {
	snapshot, err := f.inspect(ctx, r, key)
	if err != nil {
		return snapshot, err
	}
	for _, c := range f.cases {
		if err = allocatedPublishedEcho(ctx, c, snapshot.selected[c.key()]); err != nil {
			return snapshot, err
		}
	}
	return snapshot, nil
}
func (f *managedAllocatedPorts) closed(t *testing.T, ctx context.Context, snapshot allocatedPublishedSnapshot) {
	t.Helper()
	if len(snapshot.selected) != len(f.cases) {
		t.Fatal("missing original selected ports before closure assertion")
	}
	for _, c := range f.cases {
		address := snapshot.selected[c.key()]
		conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, c.protocol+"4", address.String())
		if err != nil {
			continue
		}
		if c.protocol == "tcp" {
			_ = conn.Close()
			t.Fatal("stopped/retired original retained TCP allocation")
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, err = conn.Write([]byte("owned-compose-allocated-" + c.key()))
		if err == nil {
			data := make([]byte, 128)
			_, err = conn.Read(data)
		}
		_ = conn.Close()
		if err == nil {
			t.Fatal("stopped/retired original retained UDP echo allocation")
		}
	}
}
func (f *managedAllocatedPorts) assertClosed(t *testing.T, ctx context.Context) {
	f.closed(t, ctx, f.app)
	f.closed(t, ctx, f.standalone)
}

func prepareManagedAllocatedPortsNative(t *testing.T, ctx context.Context, r *Runtime, root string, document []byte, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, wait func(string, func() bool), fixture *managedAllocatedPorts) func(*Runtime) {
	t.Helper()
	appKey := deployment.ResourceKey("task", "tenant", "app", "web")
	frozenDocuments := map[string][]byte{"app": bytes.Clone(document)}
	live := func(key string) allocatedPublishedSnapshot {
		t.Helper()
		var snapshot allocatedPublishedSnapshot
		wait("owned omitted/zero/range Docker selection and TCP/UDP "+key, func() bool { var e error; snapshot, e = fixture.live(ctx, r, key); return e == nil })
		return snapshot
	}
	binding := func(scope, key string) (deployment.Binding, control.AppBindingSource) {
		t.Helper()
		apps, e := p.Apps(read().State)
		execution, ok := apps.Execution("tenant", scope)
		stage, found := execution.Stage(key)
		if e != nil || !ok || !found || stage.Result == nil {
			t.Fatal("allocation original Task missing", e)
		}
		original := execution.Blueprint().OriginalDocument()
		service, _, inputErr := execution.Blueprint().TaskInput("web")
		if original == nil || !bytes.Equal(original.Body, frozenDocuments[scope]) || inputErr != nil || !slices.Equal(service.Ports, fixture.intent(t)) {
			t.Fatal("allocation lost exact omitted/zero source or normalized accepted intent", inputErr)
		}
		b, ok := apps.Binding(deployment.ObjectRef{Key: key, Revision: stage.Result.Revision, Generation: stage.Result.Generation})
		source, found := apps.BindingSource(b.Digest())
		if !ok || !found {
			t.Fatal("allocation original Binding/source missing")
		}
		return b, source
	}
	appOriginal := live(appKey)
	appBinding, appSource := binding("app", appKey)
	call := func(args ...string) {
		t.Helper()
		_, _, e := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), append([]string{"--tenant", "tenant"}, args...), nil)
		if e != nil {
			t.Fatal("allocated standalone original CLI action failed", e)
		}
	}
	// Use the existing signed app Stop/Start operation. A bare SDK start would
	// change the process incarnation without its required original receipt.
	call("compose", "restart", "-p", "app", "web", "--operation", "allocated-app-restart")
	wait("allocated app original signed restart completed", func() bool {
		apps, err := p.Apps(read().State)
		record, ok := apps.TaskRestart("tenant", "app", "allocated-app-restart")
		return err == nil && ok && record.Control != nil && record.Control.Phase == checker.ControlCompleted && record.Plan.Container.NativeID == appOriginal.native
	})
	fixture.app = live(appKey)
	if fixture.app.native != appOriginal.native || fixture.app.started == appOriginal.started {
		t.Fatal("app restart did not reuse its original native")
	}
	t.Log("actual app omitted/zero/range TCP/UDP and original signed restart verified")
	// Docker can select another member of the same accepted dynamic/range
	// intent on restart. An uninterrupted same-DB reopen must keep that map.
	const name = "allocated-service"
	input, e := deployment.ParseApp(document)
	if e != nil {
		t.Fatal(e)
	}
	input.Name, input.MyDC.Deployment, input.MyDC.Ingress = name, "allocated-service-deploy", nil
	input.Volumes = nil
	input.Secrets = nil
	service := input.Services["web"]
	service.Volumes = nil
	// The shared fixture image declares VOLUME /data. Cover it explicitly
	// without borrowing the live app writer or creating anonymous storage.
	service.Tmpfs = []string{"/data:size=1m,uid=10001,gid=10001,mode=0700"}
	service.Secrets = nil
	service.MyDC.Sources = nil
	service.Healthcheck = nil
	delete(service.Environment, "MYDC_VOLUME_FIXTURE")
	delete(service.Environment, "MYDC_VOLUME_SECOND_FIXTURE")
	delete(service.Environment, "MYDC_PROJECTION_FILE")
	service.Ports = fixture.intent(t)
	for alias, attachment := range service.Networks {
		a, ae := netip.ParseAddr(attachment.IPv4)
		prefix, pe := netip.ParsePrefix(os.Getenv("MYDC_DOCKER_TEST_CIDR"))
		if ae != nil || pe != nil || !prefix.Contains(a.Next()) {
			t.Fatal("allocation fixture requires adjacent owned standalone address")
		}
		attachment.IPv4 = a.Next().String()
		service.Networks[alias] = attachment
	}
	input.Services["web"] = service
	path := filepath.Join(root, "allocated-standalone.yaml")
	raw := fixture.document(t, input)
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	call("standalone", "plan", name, "-f", path, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no")
	call("standalone", "up", name, "-f", path, "--mode", "entrypoint", "--lifetime", "fixed", "--restart", "no", "--operation", "allocated-create", "--no-input")
	scope := deployment.StandaloneScopeName("tenant", name)
	key := deployment.ResourceKey("task", "tenant", scope, "web")
	frozenDocuments[scope] = bytes.Clone(raw)
	currentTarget := func() containerops.Target {
		t.Helper()
		var target containerops.Target
		wait("allocated standalone current exact owner observation", func() bool {
			selection := containerops.Selection{Standalone: name}
			query := containerops.Query{Schema: 1, Selection: selection, Kind: "stats", MaxBytes: 16384}
			var e error
			target, e = user.ResolveContainerSession(ctx, peer, session, "tenant", selection, containerops.SessionSpec{Kind: "stats", Query: &query, Interval: time.Second})
			if e != nil {
				return false
			}
			snapshot, e := fixture.live(ctx, r, key)
			return e == nil && target.NativeID == snapshot.native && target.StartedAt == snapshot.started
		})
		return target
	}
	originalTarget := currentTarget()
	standaloneOriginal := live(key)
	t.Log("actual standalone omitted/zero/range TCP/UDP selection verified")
	standaloneBinding, standaloneSource := binding(scope, key)
	controlDone := func(operation string, running bool) {
		wait("allocated original signed control "+operation, func() bool {
			apps, e := p.Apps(read().State)
			record, ok := apps.TaskRestart("tenant", scope, operation)
			if e != nil || !ok || record.Control == nil || record.Control.Phase != checker.ControlCompleted {
				return false
			}
			if record.Plan.Container.NativeID != standaloneOriginal.native || record.Control.Target.NativeID != standaloneOriginal.native {
				t.Fatal("original signed control selected another native")
			}
			got, e := r.docker.API.ContainerInspect(ctx, standaloneOriginal.native, client.ContainerInspectOptions{})
			return e == nil && got.Container.State != nil && got.Container.State.Running == running
		})
	}
	call("standalone", "stop", name, "--operation", "allocated-stop")
	controlDone("allocated-stop", false)
	fixture.closed(t, ctx, standaloneOriginal)
	call("standalone", "start", name, "--operation", "allocated-start")
	controlDone("allocated-start", true)
	afterStart := currentTarget()
	fixture.standalone = live(key)
	t.Log("actual standalone signed stop/start and current incarnation verified")
	if afterStart.NativeID != originalTarget.NativeID || afterStart.StartedAt == originalTarget.StartedAt || fixture.standalone.native != standaloneOriginal.native {
		t.Fatal("standalone start recreated allocation owner")
	}
	if afterApp := live(appKey); !reflect.DeepEqual(afterApp, fixture.app) {
		t.Fatal("standalone allocation changed live original app selection")
	}
	assertSources := func() {
		t.Helper()
		for _, entry := range []struct {
			scope, key string
			b          deployment.Binding
			s          control.AppBindingSource
		}{{"app", appKey, appBinding, appSource}, {scope, key, standaloneBinding, standaloneSource}} {
			b, s := binding(entry.scope, entry.key)
			if b.Digest() != entry.b.Digest() || !reflect.DeepEqual(s, entry.s) {
				t.Fatal("allocation effects changed accepted Task/Binding/origin")
			}
		}
	}
	assertSources()
	return func(next *Runtime) {
		r = next
		if got := live(appKey); !reflect.DeepEqual(got, fixture.app) {
			t.Fatal("same-DB reopen changed app native/StartedAt/selected allocation")
		}
		if got := live(key); !reflect.DeepEqual(got, fixture.standalone) {
			t.Fatal("same-DB reopen changed standalone native/StartedAt/selected allocation")
		}
		if currentTarget() != afterStart {
			t.Fatal("same-DB reopen changed exact admitted standalone observation")
		}
		assertSources()
		call("standalone", "remove", name, "--operation", "allocated-remove")
		wait("allocated original standalone retirement", func() bool {
			apps, e := p.Apps(read().State)
			inventory, ok := apps.Inventory("tenant", scope)
			gone, ge := r.docker.Gone(ctx, "container", key)
			return e == nil && ok && inventory.Quiescent() && ge == nil && gone
		})
		fixture.closed(t, ctx, fixture.standalone)
		if got := live(appKey); !reflect.DeepEqual(got, fixture.app) {
			t.Fatal("standalone removal changed app Docker selection")
		}
	}
}
