// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
	"github.com/moby/moby/client"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

func TestRealBoundaryManagedTwoTenantAPIAndNativeIsolation(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppTenantIsolation, true, true, true)
}

func verifyManagedTenantIsolation(t *testing.T, ctx context.Context, r *Runtime, root string, cfg config.Node, admin userauth.Client, peer sfcp.Peer, adminSession access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), image string) map[string]any {
	t.Helper()
	change("isolation-second", "create-tenant", 0, control.TenantID{ID: "second"})
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("second")
	change("second-nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("second", tenant.AllowedNodes, []string{"node-a"}))
	change("second-quota", "set-node-quota", 0, tenancy.NodeLimit{Tenant: "second", Node: "node-a", Capacity: workload.Resources{CPU: 100000000, Memory: 16 << 20}, Networks: 1, MaxConsumers: 8, MaxIngressInstances: 1, MaxIngressListeners: 2, MaxIngressRequests: 2, MaxIngressConnections: 8, IngressBufferBytes: 128 << 10})
	type manager struct {
		user    userauth.Client
		session access.Session
	}
	managers := map[string]manager{}
	for _, v := range []struct{ user, tenant string }{{"alice", "tenant"}, {"bob", "second"}} {
		key, err := identity.Create(filepath.Join(root, v.user+"-key"))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key.Private)
		change("user-"+v.user, "put-user", 0, access.User{ID: v.user, Username: v.user, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}})
		change("membership-"+v.user, "set-membership", 0, access.Membership{Tenant: v.tenant, User: v.user, Role: access.Manager, Enabled: true})
		self, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(self.Private)
		mesh, err := sfcp.NewTransport(self, admin.Cluster, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key })
		if err != nil {
			t.Fatal(err)
		}
		defer mesh.Close()
		user := userauth.Client{Mesh: mesh, Self: self, Cluster: admin.Cluster, Peers: []sfcp.Peer{peer}}
		session, err := user.Login(ctx, peer, v.user, key.Private)
		if err != nil {
			t.Fatal(err)
		}
		managers[v.tenant] = manager{user, session}
	}
	bob := managers["second"]
	apply := func(callCtx context.Context, m manager, id, action string, expected uint64, payload any, want state.Code) error {
		raw, err := control.ChangeBytes(action, m.session.User, expected, payload)
		if err != nil {
			return err
		}
		var change control.Change
		if json.Unmarshal(raw, &change) != nil {
			return fmt.Errorf("typed change")
		}
		op, err := m.user.Prepare(callCtx, peer, m.session, id, change)
		if err != nil {
			return err
		}
		reply, err := m.user.Operation(callCtx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != want {
			return fmt.Errorf("%s outcome code=%s result=%v error=%v", id, reply.Code, reply.Result, err)
		}
		return nil
	}
	// Cleanup is registered before accepting any second-tenant app. It also
	// handles a response loss by inspecting the actual shared entry first.
	retireSecond := func(callCtx context.Context) error {
		v, err := r.Engine().Read(callCtx, true)
		if err != nil {
			return err
		}
		a, err := p.Apps(v.State)
		if err != nil {
			return err
		}
		i, exists := a.Inventory("second", "second")
		if !exists {
			return nil
		}
		started := false
		for _, view := range a.Records() {
			if view.Tenant == "second" && view.App == "second" && view.Retirement != nil {
				if view.Retirement.Status == "Retired" {
					return nil
				}
				started = true
			}
		}
		if !started {
			if err := apply(callCtx, bob, "second-down", "down-app", i.Revision(), control.AppDown{Tenant: "second", App: "second", Operation: "second-stop"}, state.Applied); err != nil {
				return err
			}
		}
		for {
			v, err := r.Engine().Read(callCtx, true)
			if err != nil {
				return err
			}
			a, err := p.Apps(v.State)
			if err != nil {
				return err
			}
			for _, view := range a.Records() {
				if view.Tenant == "second" && view.App == "second" && view.Retirement != nil && view.Retirement.Status == "Retired" {
					return nil
				}
			}
			select {
			case <-callCtx.Done():
				return callCtx.Err()
			case <-time.After(30 * time.Millisecond):
			}
		}
	}
	retired := false
	defer func() {
		if !retired {
			clean, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			if err := retireSecond(clean); err != nil {
				t.Error("second app original rollback", err)
			}
		}
	}()
	registry := strings.Split(image, "/")[0]
	catalog, _ = p.Catalog(read().State)
	tenant, _ = catalog.Tenant("second")
	if err := apply(ctx, bob, "second-trust", "set-trust", tenant.Revision, control.TrustChange{Tenant: "second", Add: []access.TrustRule{access.TrustRule{Registry: registry, Repository: "fixture"}}}, state.Applied); err != nil {
		t.Fatal(err)
	}
	primary := netip.MustParsePrefix(os.Getenv("SFC_DOCKER_TEST_CIDR"))
	if !primary.Addr().Is4() || primary.Bits() != 28 {
		t.Fatal("two preflighted adjacent /28 fixture required")
	}
	next := primary.Addr()
	for range 16 {
		next = next.Next()
	}
	second := netip.PrefixFrom(next, 28)
	// An app.yaml cannot declare its own network: the second tenant's app
	// borrows a network the administrator gives that tenant.
	resources, err := p.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	change("second-network", "create-tun-network", resources.Networks.Revision(), tenancy.TUNDefinition{Tenant: "second", Name: "second-services", Members: []tenancy.TUNNode{{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: second, Gateway: second.Addr().Next(), MTU: 1280}}}}})
	change("second-hosts", "set-ingress-host-policy", 0, control.IngressHostPolicyChange{Tenant: "second", Policy: ingress.HostPolicy{ExternalAllowed: true, ExternalHosts: []string{"second.test"}}})
	document := []byte(fmt.Sprintf(`name: second
x-sfc:
 ingress:
  - {node: node-a, host: second.test, service: web, port: 8080, health: /readyz}
services:
 web:
  image: %s
  cpus: 0.1
  mem_limit: 16m
  environment: {SFC_READINESS_FIXTURE: "1", SFC_TENANT_FIXTURE: second}
  tmpfs: ["/data:size=4m,uid=10001,gid=10001,mode=0700"]
  healthcheck: {test: [CMD, /backend, --probe], interval: 1s, timeout: 1s, retries: 2}
  networks: {app: {ipv4_address: %s}}
  x-sfc: {node: node-a, ready: {http: /readyz, port: 8080}}
networks:
 app: {external: true, name: second-services}
`, image, second.Addr().Next().Next()))
	// CIDR overlap is now checked when the administrator creates a network,
	// not when an app is planned (the app names no CIDR).
	for label, raw := range map[string][]byte{
		"foreign": []byte(strings.Replace(string(document), "name: second-services", "name: shared-services", 1)),
		"quota":   []byte(strings.Replace(string(document), "cpus: 0.1", "cpus: 0.5", 1)),
		"node":    []byte(strings.ReplaceAll(string(document), "node-a", "foreign-node")),
	} {
		if _, err := bob.user.StreamAppPlan(ctx, peer, bob.session, "second", control.AppPlanRequest{Document: raw}); err == nil {
			t.Fatal(label, "invalid tenant plan accepted")
		}
	}
	artifact, err := bob.user.StreamAppPlan(ctx, peer, bob.session, "second", control.AppPlanRequest{Document: document})
	if err != nil {
		t.Fatal("own tenant plan", err)
	}
	if err := apply(ctx, bob, "second-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "second", App: "second", Deployment: "second", ID: "second-artifact", Length: len(artifact), Digest: sha256.Sum256(artifact)}, state.Applied); err != nil {
		t.Fatal(err)
	}
	for offset, index := 0, 0; offset < len(artifact); index++ {
		end := min(len(artifact), offset+(24<<10))
		if err := apply(ctx, bob, fmt.Sprintf("second-part-%d", index), "put-app-part", uint64(index+1), control.AppUploadPart{Tenant: "second", ID: "second-artifact", Index: index, Data: artifact[offset:end]}, state.Applied); err != nil {
			t.Fatal(err)
		}
		offset = end
	}
	if err := apply(ctx, bob, "second-begin", "begin-app", 0, control.AppBegin{Tenant: "second", App: "second", Deployment: "second", Upload: "second-artifact", Operation: "second-rollout"}, state.Applied); err != nil {
		t.Fatal(err)
	}
	for {
		reply, err := bob.user.AppPage(ctx, peer, bob.session, "second", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(reply.Apps) == 1 && reply.Apps[0].Health == "Healthy" && reply.Apps[0].Operation.Status == "Succeeded" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("second real native app", ctx.Err())
		case <-time.After(30 * time.Millisecond):
		}
	}
	ids := map[string]string{}
	// An external reference is not authority to borrow another tenant's source.
	// Confirm the same API accepts the exact current own-tenant reference first.
	for _, scope := range []string{"tenant", "second"} {
		pool, networkID := primary, "shared-services"
		if scope == "second" {
			pool, networkID = second, "second-services"
		}
		services := strings.Index(string(document), "\nservices:")
		networks := strings.Index(string(document), "\nnetworks:")
		if services < 0 || networks <= services {
			t.Fatal("external source fixture")
		}
		// A changed running Task requires an additional full reservation. Use
		// a separate read-only candidate in the first tenant's existing free
		// capacity and a free address; do not inflate the second tenant quota.
		body := "name: network-check\nx-sfc: {}" + string(document[services:networks])
		body = strings.Replace(body, second.Addr().Next().Next().String(), pool.Addr().Next().Next().Next().String(), 1)
		body += fmt.Sprintf("\nnetworks:\n app: {external: true, name: %s}\n", networkID)
		request := control.AppPlanRequest{Document: []byte(body)}
		alice := managers["tenant"]
		if scope == "tenant" {
			v := read().State
			current, err := p.Current(v)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := current.AppPlanArtifact(v, alice.session, time.Now().Unix(), "tenant", request); err != nil {
				t.Fatal("own current reference exact planning precondition", err)
			}
		}
		_, err := alice.user.StreamAppPlan(ctx, peer, alice.session, "tenant", request)
		if scope == "tenant" && err != nil {
			t.Fatal("own current external network reference", err)
		}
		if scope == "second" && err == nil {
			t.Fatal("foreign tenant native network borrowed")
		}
	}
	for scope, m := range managers {
		foreign := "tenant"
		if scope == "tenant" {
			foreign = "second"
		}
		for _, method := range []string{"apps", "volumes", "vault"} {
			if _, err := m.user.Query(ctx, peer, m.session, method, foreign); err == nil {
				t.Fatal("foreign tenant API allowed", scope, method)
			}
		}
		if _, err := m.user.Resources(ctx, peer, m.session, userauth.ResourcesQuery{Tenant: foreign}); err == nil {
			t.Fatal("foreign tenant resources allowed", scope)
		}
		if _, err := m.user.AppOperation(ctx, peer, m.session, foreign, control.AppOperationRequest{App: "app", ID: "rollout"}); err == nil {
			t.Fatal("foreign original operation exposed")
		}
		page, err := m.user.Resources(ctx, peer, m.session, userauth.ResourcesQuery{Tenant: scope})
		if err != nil || page.Index == 0 {
			t.Fatal("current projected resource view", err)
		}
		networks, tasks := 0, 0
		for _, entry := range page.Items {
			if entry.Limit != nil && entry.Limit.Tenant != scope || entry.Network != nil && entry.Network.Tenant != scope || entry.Reservation != nil && entry.Reservation.Tenant != scope {
				t.Fatal("foreign resource leaked")
			}
			if entry.Network != nil {
				networks++
			}
			if entry.Reservation != nil && strings.HasPrefix(entry.Reservation.Key, "workload/task/") {
				tasks++
			}
		}
		if networks != 1 || tasks != 1 {
			t.Fatal("actual app resources omitted", scope, networks, tasks)
		}
		apps, err := m.user.AppPage(ctx, peer, m.session, scope, "")
		if err != nil || len(apps.Apps) != 1 || apps.Apps[0].Tenant != scope || apps.Apps[0].Health != "Healthy" {
			t.Fatal("own app observations", err)
		}
		app := "app"
		if scope == "second" {
			app = "second"
		}
		status, err := r.workload.Status(ctx, deployment.ResourceKey("task", scope, app, "web"))
		if err != nil || !status.Running {
			t.Fatal(err)
		}
		ids[scope] = status.NativeID
	}
	probe := func(scope string, target netip.Addr, want int) {
		t.Helper()
		created, err := r.docker.API.ExecCreate(ctx, ids[scope], client.ExecCreateOptions{User: "10001:10001", Cmd: []string{"/backend", "--tcp-probe", net.JoinHostPort(target.String(), "8080")}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.docker.API.ExecStart(ctx, created.ID, client.ExecStartOptions{Detach: true}); err != nil {
			t.Fatal(err)
		}
		for {
			got, err := r.docker.API.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !got.Running {
				if got.ContainerID != ids[scope] || got.ExitCode != want {
					t.Fatal("actual source TCP isolation", scope, target, got.ExitCode, want)
				}
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(15 * time.Millisecond):
			}
		}
	}
	probe("tenant", primary.Addr().Next().Next(), 0)
	probe("second", second.Addr().Next().Next(), 0)
	probe("tenant", second.Addr().Next().Next(), 1)
	probe("second", primary.Addr().Next().Next(), 1)
	probe("tenant", primary.Addr().Next().Next(), 0)
	probe("second", second.Addr().Next().Next(), 0)
	projection, err := p.ProjectResources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	spec := projection.Goals[deployment.ResourceKey("ingress", "tenant", "app", "http")].Ingress
	if spec == nil {
		t.Fatal("primary actual Ingress")
	}
	// Trust the public chain the store serves for the host.
	certificates, err := p.Certificates(read().State)
	if err != nil {
		t.Fatal(err)
	}
	served := certificates.LookupHost("app.test", time.Now().Unix())
	if len(served) == 0 {
		t.Fatal("no store certificate for app.test")
	}
	pem := served[0].Chain
	tlsConfig := &tls.Config{ServerName: "app.test", MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(pem) {
		t.Fatal("actual fixture CA")
	}
	h1 := &http.Transport{Proxy: nil}
	defer h1.CloseIdleConnections()
	h2 := &http2.Transport{TLSClientConfig: tlsConfig.Clone()}
	defer h2.CloseIdleConnections()
	h3 := &http3.Transport{TLSClientConfig: tlsConfig.Clone()}
	defer h3.Close()
	checkHTTP := func(transport http.RoundTripper, url, host string, status, proto int, body string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, "GET", url+"/tenant", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, 128))
		_ = response.Body.Close()
		if err != nil || response.StatusCode != status || response.ProtoMajor != proto || body != "" && string(raw) != body {
			t.Fatal("Ingress scope", host, response.StatusCode, response.ProtoMajor, string(raw), err)
		}
	}
	for i, transport := range []http.RoundTripper{h1, h2, h3} {
		url := "http://" + gatewayListenerAddress(t, cfg, spec.Listeners[0])
		if i > 0 {
			url = "https://" + gatewayListenerAddress(t, cfg, spec.Listeners[1])
		}
		checkHTTP(transport, url, "app.test", 200, i+1, "tenant")
		// The node gateway's shared listeners serve each tenant's own host only.
		checkHTTP(transport, url, "foreign.test", 404, i+1, "")
	}
	checkHTTP(h1, "http://"+gatewayListenerAddress(t, cfg, spec.Listeners[0]), "second.test", 200, 1, "second")
	// Revoke one manager's current membership, without changing the admin's
	// accepted original app or the other manager's authorization.
	catalog, _ = p.Catalog(read().State)
	membership, _ := catalog.Membership("tenant", "alice")
	change("alice-revoke", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: "alice", Role: access.Manager, Enabled: false})
	if _, err := managers["tenant"].user.AppPage(ctx, peer, managers["tenant"].session, "tenant", ""); err == nil {
		t.Fatal("revoked current tenant read allowed")
	}
	if _, err := bob.user.AppPage(ctx, peer, bob.session, "second", ""); err != nil {
		t.Fatal("other tenant session revoked", err)
	}
	if _, err := admin.AppPage(ctx, peer, adminSession, "second", ""); err != nil {
		t.Fatal("implicit system admin scope", err)
	}
	if err := retireSecond(ctx); err != nil {
		t.Fatal("actual second tenant retirement", err)
	}
	retired = true
	if gone, err := r.docker.Gone(ctx, "container", deployment.ResourceKey("task", "second", "second", "web")); err != nil || !gone {
		t.Fatal("second native Task not Gone", err)
	}
	t.Log("two real tenant manager sessions/current API lists and owner observations; committed app networks/reservations are included and filtered; cross-tenant reads/original operation and overlap/quota/foreign-node plans denied; actual Exec source namespace self TCP before+after succeeds and both cross-Bridge TCP probes fail; public H1/H2/H3 correct host reaches own tenant marker, foreign host404; current membership revoke scoped; system admin remains implicit; second app down/original native closure before primary same DB/CLI retirement")
	return map[string]any{"tenants": 2, "native_ids": ids, "per_tenant_projected_networks": 1, "per_tenant_projected_tasks": 1, "cross_bridge_tcp_exit_codes": []int{1, 1}, "positive_controls_before_after": true, "ingress_foreign_host_protocols": []int{1, 2, 3}, "second_retired": true}
}
