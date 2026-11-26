// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/observability"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// These assertions are called by the existing managed DNS, checker and network
// CLI fixtures at their positive native healthy/retired boundaries. They share
// the original app, wallet, DB, owner observations and independent rollback.
// No new native runner or fixture-signed closure is introduced here.
func TestRQ10VolumeFileGrantReadsActualCLIAndOwner(t *testing.T) {
	// RQ9 owns this fixture, grant reducer and native file contract. The
	// callback runs after its actual CLI grant and revoke with both real users.
	runManagedAppOwnerWithVolumeFileRead(t, true, true, false, true, managedAppVolumeFiles, verifyNativeVolumeFileGrantReads, true)
}

func verifyNativeVolumeFileGrantReads(t *testing.T, ctx context.Context, admin, delegated userauth.Client, peer mydcp.Peer, adminSession, delegatedSession access.Session, granted bool) {
	t.Helper()
	query := control.PublicReadQuery{Name: "data", App: "app"}
	adminPage := readNativePublicPage(t, ctx, admin, peer, adminSession, "volume-file-grants", "tenant", query)
	delegatePage := readNativePublicPage(t, ctx, delegated, peer, delegatedSession, "volume-file-grants", "tenant", query)
	want := 0
	if granted {
		want = 1
	}
	if len(adminPage.Rows) != want || len(delegatePage.Rows) != want || !reflect.DeepEqual(adminPage.Rows, delegatePage.Rows) {
		t.Fatal("actual folder grant/revoke differs between manager and delegate", granted, adminPage, delegatePage)
	}
	if granted {
		grant := delegatePage.Rows[0].FileGrant
		if grant == nil || grant.User != delegatedSession.User || grant.Tenant != "tenant" || grant.App != "app" || grant.Volume != "data" || grant.Prefix != "mydc-web-backups/" || grant.Revision == 0 || !grant.AccountEnabled || !grant.VolumePresent || !slices.Equal(grant.Operations, []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}) {
			t.Fatal("original RQ9 folder grant was widened or lost", grant)
		}
	}
	if _, err := delegated.PublicRead(ctx, peer, delegatedSession, "volume-file-grants", "foreign", query, ""); err == nil {
		t.Fatal("delegate read a foreign tenant's folder grants")
	}
	all := readNativePublicPage(t, ctx, delegated, peer, delegatedSession, "volume-file-grants", "tenant", control.PublicReadQuery{})
	if !reflect.DeepEqual(all.Rows, delegatePage.Rows) {
		t.Fatal("empty read selectors disclosed another user or Volume", all)
	}
}

func readNativePublicPage(t *testing.T, ctx context.Context, user userauth.Client, peer mydcp.Peer, session access.Session, method, tenant string, query control.PublicReadQuery) control.PublicReadPage {
	t.Helper()
	reply, err := user.PublicRead(ctx, peer, session, method, tenant, query, "")
	if err != nil || reply.PublicRead == nil || reply.PublicRead.Next != "" {
		t.Fatal("bounded native public read", method, reply, err)
	}
	return *reply.PublicRead
}

func nativePublicCLI(t *testing.T, ctx context.Context, root, method, tenant string, query control.PublicReadQuery) control.PublicReadPage {
	t.Helper()
	if method == "vault-usages" || method == "vault-approvals" {
		return nativeSecretReadCLI(t, ctx, root, method, tenant, query)
	}
	args := []string{"--tenant", tenant, "manage", method}
	for _, item := range []struct{ flag, value string }{{"--name", query.Name}, {"--app", query.App}, {"--node", query.Node}} {
		if item.value != "" {
			args = append(args, item.flag, item.value)
		}
	}
	raw, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
	var reply userauth.Reply
	if err != nil || json.Unmarshal(raw, &reply) != nil || reply.PublicRead == nil || reply.PublicRead.Method != method || reply.PublicRead.Tenant != tenant || reply.PublicRead.Next != "" {
		t.Fatal("actual CLI public read", method, err, string(diagnostic), string(raw))
	}
	return *reply.PublicRead
}

func verifyNativePublicAppReads(t *testing.T, ctx context.Context, r *Runtime, root string, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), document []byte, live bool) {
	t.Helper()
	input, err := deployment.ParseApp(document)
	if err != nil {
		t.Fatal(err)
	}
	tenant, app := "tenant", "app"
	task := deployment.ResourceKey("task", tenant, app, "web")
	target := read().State.Object(task)
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenantState, _ := catalog.Tenant(tenant)
	selected, err := user.Query(ctx, peer, session, "select-tenant", tenant)
	if err != nil || selected.TenantRevision != tenantState.Revision || !slices.Equal(selected.TenantAllowedNodes, tenantState.AllowedNodes) {
		t.Fatal("current allowed node CAS", selected, err)
	}
	version, err := user.ServerVersion(ctx, peer)
	if err != nil || version.Version == "" || version.Protocol != 1 {
		t.Fatal("responding Runtime version", version, err)
	}
	network := readNativePublicPage(t, ctx, user, peer, session, "network-users", tenant, control.PublicReadQuery{Name: "shared-services"})
	volume := readNativePublicPage(t, ctx, user, peer, session, "volume-users", tenant, control.PublicReadQuery{Name: "data", App: app})
	trust := readNativePublicPage(t, ctx, user, peer, session, "image-trust", tenant, control.PublicReadQuery{})
	if live && (len(network.Rows) != 1 || network.Rows[0].User == nil || network.Rows[0].User.EndpointPresent == nil || !*network.Rows[0].User.EndpointPresent) {
		t.Fatal("actual owned native endpoint evidence did not reach User network-users", network)
	}
	for method, page := range map[string]control.PublicReadPage{"network-users": network, "volume-users": volume, "image-trust": trust} {
		if live && len(page.Rows) != 1 || !live && len(page.Rows) != 0 {
			t.Fatal("actual app reference lifetime", method, live, page)
		}
		if method == "network-users" {
			continue // 'mydc network users' replaced the raw CLI read; the User page above is checked
		}
		if method == "volume-users" {
			// 'mydc volume users APP/VOLUME' replaced the raw read; it lists
			// the User row of each current reference.
			raw, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"--tenant", tenant, "volume", "users", app + "/data"}, nil)
			var users []control.PublicResourceUser
			if err != nil || json.Unmarshal(raw, &users) != nil {
				t.Fatal("actual CLI volume users", err, string(diagnostic), string(raw))
			}
			want := 0
			for _, row := range page.Rows {
				if row.User != nil {
					want++
				}
			}
			if len(users) != want {
				t.Fatal("CLI disagrees with current native references", method, users, page)
			}
			continue
		}
		cli := nativePublicCLI(t, ctx, root, method, tenant, map[string]control.PublicReadQuery{"volume-users": {Name: "data", App: app}, "image-trust": {}}[method])
		if cli.Total != page.Total {
			t.Fatal("CLI disagrees with current native references", method, cli, page)
		}
	}
	if trust.TenantRevision != tenantState.Revision || !reflect.DeepEqual(trust.Rules, tenantState.ImageSources) {
		t.Fatal("image trust lost exact tenant CAS/rules")
	}
	if live {
		versionHome := filepath.Join(root, "rq10-version-no-wallet")
		if err := os.MkdirAll(versionHome, 0700); err != nil {
			t.Fatal(err)
		}
		if entries, err := os.ReadDir(versionHome); err != nil || len(entries) != 0 {
			t.Fatal("sessionless CLI version requires a fresh empty home", err)
		}
		raw, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), versionHome, filepath.Join(root, "cli.yaml"), []string{"server-version"}, nil)
		var cliVersion userauth.ServerVersion
		if err != nil || json.Unmarshal(raw, &cliVersion) != nil || cliVersion.Version != "1" || cliVersion.Protocol != 1 {
			t.Fatal("actual sessionless CLI server-version", err, string(diagnostic), string(raw))
		}
		if _, err := os.Lstat(filepath.Join(versionHome, ".mydc", "wallet.bin")); !os.IsNotExist(err) {
			t.Fatal("sessionless server-version created a wallet", err)
		}
		for _, page := range []control.PublicReadPage{network, volume} {
			row := page.Rows[0].User
			if row == nil || row.Task != task || row.App != app || row.Service != "web" || row.Node != "node-a" || row.Generation != target.Generation || row.Revision != target.Revision || !row.Live || row.ContainerPresent == nil || !*row.ContainerPresent {
				t.Fatal("public reference lost actual original Task", row)
			}
		}
		if volume.Rows[0].User.Writable == nil || !*volume.Rows[0].User.Writable || volume.Rows[0].User.Consumer == "" {
			t.Fatal("actual Volume writer reservation missing")
		}
		book, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		apps, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		binding, ok := apps.Binding(deployment.ObjectRef{Key: task, Generation: target.Generation, Revision: target.Revision})
		if !ok {
			t.Fatal("actual Task lacks original Volume Binding")
		}
		matched := false
		for _, pin := range binding.Pins() {
			if pin.Scope.Tenant != tenant || pin.Scope.App != app || pin.Scope.ID != "data" {
				continue
			}
			// Volume is an exact generation-bearing selector. Reuse the
			// admitted pin instead of inventing a zero-generation scope.
			core, ok := book.Volume(pin.Scope)
			if !ok || len(core.Consumers()) != volume.Total {
				t.Fatal("Volume users differ from original pinned deletion/admission book", ok, volume.Total)
			}
			matched = true
		}
		if !matched {
			t.Fatal("original Binding does not pin the queried Volume")
		}
		image := trust.Rows[0].Image
		pinned, err := access.PinImage(input.Services["web"].Image)
		if err != nil || image == nil || image.Reference != pinned.Reference || image.App != app || image.Service != "web" || len(image.Rules) == 0 {
			t.Fatal("actual image trust source", image, err)
		}
	}
	for _, method := range []string{"vault-approvals", "vault-usages"} {
		query := control.PublicReadQuery{App: app}
		if method == "vault-usages" {
			query = control.PublicReadQuery{Name: "group"}
		}
		page := readNativePublicPage(t, ctx, user, peer, session, method, tenant, query)
		cli := nativePublicCLI(t, ctx, root, method, tenant, query)
		if cli.Total != page.Total {
			t.Fatal("Vault CLI differs from current source", method)
		}
		found := false
		for _, row := range page.Rows {
			if row.Approval != nil {
				a := row.Approval
				found = found || a.App == app && a.Group == "group" && slices.Contains(a.Services, "web") && slices.Contains(a.Nodes, "node-a") && a.ApprovedAt > 0 && a.ID != ""
			}
			if row.SecretUsage != nil {
				u := row.SecretUsage
				found = found || u.App == app && u.Service == "web" && u.Node == "node-a" && u.Live && len(u.Secrets) > 0
			}
		}
		if live && !found || !live && method == "vault-usages" && len(page.Rows) != 0 {
			t.Fatal("actual Vault approval/use lifetime", method, live, page)
		}
		raw, _ := json.Marshal(page)
		for _, private := range []string{"private-group-password", "VerifierRef", "Password", "Signature", "ProviderRef"} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatal("private Vault input in public read", private)
			}
		}
	}
	program, _, err := input.LifecycleProgram()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, script := range program.Scripts {
		if script.Ref == nil || seen[script.Ref.Name] {
			continue
		}
		seen[script.Ref.Name] = true
		page := readNativePublicPage(t, ctx, user, peer, session, "lifecycle-uses", tenant, control.PublicReadQuery{Name: script.Ref.Name})
		found := false
		for _, row := range page.Rows {
			use := row.Lifecycle
			found = found || use != nil && use.Kind == "app-binding" && use.App == app && use.Service == "web" && use.Node == "node-a" && use.Revision == script.Ref.Revision
		}
		if live && !found || !live && len(page.Rows) != 0 {
			t.Fatal("original named script use/return", live, page)
		}
		nativePublicCLI(t, ctx, root, "lifecycle-uses", tenant, control.PublicReadQuery{Name: script.Ref.Name})
	}
	verifyNativePublicDNS(t, ctx, r, user, peer, session, p, read, change, live)
	if !live {
		return
	}
	// Cordon metadata comes from the same original signed command that node
	// scheduling consumes. Cordon/uncordon preserve the live Task and its refs.
	members, err := p.Members(read().State)
	if err != nil {
		t.Fatal(err)
	}
	change("rq10-cordon", "cordon-node", members.Cordon("node-a").Revision, control.NodeSelection{ID: "node-a"})
	memberPage, err := user.MemberPage(ctx, peer, session, "")
	if err != nil {
		t.Fatal(err)
	}
	cordoned := false
	for _, node := range memberPage.NodeLifecycle {
		if node.Node.Member.ID == "node-a" {
			_, e := time.Parse(time.RFC3339, node.Scheduling.CordonedAt)
			cordoned = node.Scheduling.Enabled && node.Scheduling.CordonedBy == "admin" && e == nil
		}
	}
	if !cordoned {
		t.Fatal("member read lost original cordon actor/time")
	}
	nodeRaw, why, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"node", "show", "node-a"}, nil)
	var nodeCLI struct {
		Lifecycle *membership.NodeView `json:"lifecycle"`
	}
	if err != nil || json.Unmarshal(nodeRaw, &nodeCLI) != nil || nodeCLI.Lifecycle == nil || nodeCLI.Lifecycle.Scheduling.CordonedBy != "admin" || nodeCLI.Lifecycle.Scheduling.CordonedAt == "" {
		t.Fatal("actual CLI cordon actor/time", err, string(why), string(nodeRaw))
	}
	members, _ = p.Members(read().State)
	change("rq10-uncordon", "uncordon-node", members.Cordon("node-a").Revision, control.NodeSelection{ID: "node-a"})
	summary, err := user.NodeObservationPage(ctx, peer, session, "node-summary", tenant, "node-a", "")
	if err != nil || summary.NodeSummary == nil || len(summary.NodeSummary.Nodes) != 1 {
		t.Fatal("actual node observation read", err)
	}
	node := summary.NodeSummary.Nodes[0]
	if node.ObserveLimitSeconds != observability.MaxAge/1000 || node.ObservationMaxAge != observability.MaxAge || node.CordonedAt != "" || node.CordonedBy != "" {
		t.Fatal("node freshness/uncordon metadata", node)
	}
	if (node.ObservedAt == 0 || node.Stale) != (node.State == "unreachable") {
		t.Fatal("freshness status disagrees with exposed threshold", node)
	}
	if read().State.Object(task) != target {
		t.Fatal("read/cordon changed original Task")
	}
	verifyNativePublicReaderRevocation(t, ctx, r, root, user, peer, session, p, read, change)
}

func verifyNativePublicDNS(t *testing.T, ctx context.Context, r *Runtime, user userauth.Client, peer mydcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), live bool) {
	t.Helper()
	key := services.ManagedDNSKey("tenant", "shared-services")
	sources, err := p.ManagedDNS(read().State)
	if err != nil {
		t.Fatal(err)
	}
	source, exists := sources[key]
	if !exists {
		return
	}
	want := source.Definition
	if !live {
		want.Policy.Enabled = false
		change("rq10-disable-dns", "configure-network-dns", read().State.Object(key).Revision, want)
	}
	for {
		var found *control.DNSPolicyView
		for after := ""; ; {
			page, err := user.ResourcePage(ctx, peer, session, "tenant", after)
			if err != nil {
				t.Fatal("actual DNS resource page", err)
			}
			for _, row := range page.Resources {
				if row.Network != nil && row.Network.Logical == "shared-services" && row.Network.Node == "node-a" {
					found = row.DNS
				}
			}
			if page.ResourcesNext == "" {
				break
			}
			after = page.ResourcesNext
		}
		if found == nil || !reflect.DeepEqual(found.Policy, want.Policy) || found.Revision != read().State.Object(key).Revision {
			t.Fatal("full DNS policy or exact source CAS lost", found, want)
		}
		if live {
			raw, err := r.observeManaged(ctx, key, read())
			var actual ModuleObservation
			if err != nil || json.Unmarshal(raw, &actual) != nil || actual.DNS == nil {
				t.Fatal("original native DNS observation", err)
			}
			if found.Ready != nil && *found.Ready && actual.Ready && slices.Equal(found.Resolvers, actual.DNS.Resolvers) && len(found.Resolvers) > 0 {
				return
			}
		} else if (found.Ready == nil || !*found.Ready) && len(found.Resolvers) == 0 {
			// A newer disabled policy need not instantiate a native DNS view
			// after the original instance has already closed on node revocation.
			// Absence of current-source observation stays unknown, never Ready.
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("native DNS resource readiness", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func verifyNativePublicReaderRevocation(t *testing.T, ctx context.Context, r *Runtime, root string, admin userauth.Client, peer mydcp.Peer, adminSession access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	change("rq10-empty-tenant", "create-tenant", 0, control.TenantID{ID: "rq10-foreign"})
	// The real create/set-trust reducers supply the same revision returned to
	// a user editing the complete rule list; this tenant needs no native work.
	defaults := readNativePublicPage(t, ctx, admin, peer, adminSession, "image-trust", "rq10-foreign", control.PublicReadQuery{})
	if len(defaults.Rows) != 0 || len(defaults.Rules) != 1 || defaults.Rules[0] != (access.TrustRule{Registry: "docker.io", Repository: "**"}) || defaults.TenantRevision == 0 {
		t.Fatal("new tenant default trust/revision", defaults)
	}
	changedRules := []access.TrustRule{{Registry: "docker.io", Repository: "library/alpine"}}
	change("rq10-change-trust", "set-trust", defaults.TenantRevision, control.TrustAssignment{Tenant: "rq10-foreign", Rules: changedRules})
	changed := readNativePublicPage(t, ctx, admin, peer, adminSession, "image-trust", "rq10-foreign", control.PublicReadQuery{})
	if changed.TenantRevision <= defaults.TenantRevision || !reflect.DeepEqual(changed.Rules, changedRules) {
		t.Fatal("user trust read lost changed rule/CAS", changed)
	}
	key, err := identity.Create(filepath.Join(root, "rq10-reader-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	change("rq10-reader", "put-user", 0, access.User{ID: "rq10-reader", Username: "rq10-reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}})
	change("rq10-reader-role", "set-membership", 0, access.Membership{Tenant: "tenant", User: "rq10-reader", Role: access.Manager, Enabled: true})
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	mesh, err := mydcp.NewTransport(self, admin.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	reader := userauth.Client{Self: self, Mesh: mesh, Cluster: admin.Cluster, Peers: []mydcp.Peer{peer}}
	session, err := reader.Login(ctx, peer, "rq10-reader", key.Private)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"network-users", "volume-users", "vault-usages", "image-trust"} {
		query := map[string]control.PublicReadQuery{"network-users": {Name: "shared-services"}, "volume-users": {Name: "data", App: "app"}, "vault-usages": {Name: "group"}, "image-trust": {}}[method]
		readNativePublicPage(t, ctx, reader, peer, session, method, "tenant", query)
		if _, err := reader.PublicRead(ctx, peer, session, method, "rq10-foreign", query, ""); err == nil {
			t.Fatal("public read disclosed foreign realm", method)
		}
	}
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	membership, _ := catalog.Membership("tenant", "rq10-reader")
	change("rq10-revoke-reader", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: "rq10-reader", Role: access.Manager, Enabled: false})
	if _, err := reader.PublicRead(ctx, peer, session, "network-users", "tenant", control.PublicReadQuery{Name: "shared-services"}, ""); err == nil {
		t.Fatal("revoked manager retained public-read authority")
	}
}

// nativeVolumeShow is `mydc volume show APP/VOLUME -o json` as the fixture user.
func nativeVolumeShow(t *testing.T, ctx context.Context, root string, scope volumes.Scope) []byte {
	t.Helper()
	args := []string{"--tenant", scope.Tenant, "volume", "show", scope.App + "/" + scope.ID}
	raw, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
	if err != nil {
		t.Fatal("actual CLI volume show", err, string(diagnostic), string(raw))
	}
	return raw
}

// nativeRetainedSource checks the old copy a move left, as volume show lists it.
func nativeRetainedSource(t *testing.T, raw []byte, move, node, status string) {
	t.Helper()
	var view control.VolumeView
	if json.Unmarshal(raw, &view) != nil {
		t.Fatal("retained source read", string(raw))
	}
	for _, row := range view.Retained {
		if row.Move == move {
			if row.Node != node || row.State != status {
				t.Fatal("retained original source phase", row)
			}
			return
		}
	}
	t.Fatal(fmt.Sprintf("missing original retained source %s/%s (%s)", node, move, status))
}

func verifyNativeTunnelEventReader(t *testing.T, ctx context.Context, r *Runtime, root string, peer mydcp.Peer, read func() cluster.View, change func(string, string, uint64, any), after map[string]string) {
	t.Helper()
	name := "rq10-tunnel-reader"
	key, err := identity.Create(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	change(name, "put-user", 0, access.User{ID: name, Username: name, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}})
	change(name+"-role", "set-membership", 0, access.Membership{Tenant: "tenant", User: name, Role: access.Viewer, Enabled: true})
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	mesh, err := mydcp.NewTransport(self, r.controlPolicy.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	reader := userauth.Client{Self: self, Mesh: mesh, Cluster: r.controlPolicy.Cluster, Peers: []mydcp.Peer{peer}}
	session, err := reader.Login(ctx, peer, name, key.Private)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"tunnel-down", "tunnel-up"} {
		query := eventlog.Query{Tenant: "tenant", Node: "node-a", Kind: kind, After: after[kind], Limit: 100}
		page, err := reader.EventsPage(ctx, peer, session, query)
		if err != nil || len(page.Items) < 2 {
			t.Fatal("tenant reader lost actual TUN outage/recovery facts", page, err)
		}
		for _, item := range page.Items {
			if item.Kind != kind || item.Scope != "tenant" || item.Target.Tenant != "tenant" || item.Target.Network != "alpha" && item.Target.Network != "beta" || item.Target.PairID != "node-a/node-b" {
				t.Fatal("tunnel event disclosed unrelated tenant/network", item)
			}
		}
		foreign := query
		foreign.Tenant = "foreign"
		if _, err := reader.EventsPage(ctx, peer, session, foreign); err == nil {
			t.Fatal("reader selected another tenant's tunnel events")
		}
	}
	users, err := r.controlPolicy.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	membership, _ := users.Membership("tenant", name)
	change(name+"-revoke", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: name, Role: access.Viewer, Enabled: false})
	for _, kind := range []string{"tunnel-down", "tunnel-up"} {
		query := eventlog.Query{Tenant: "tenant", Node: "node-a", Kind: kind, After: after[kind], Limit: 100}
		if _, err := reader.EventsPage(ctx, peer, session, query); err == nil {
			t.Fatal("revoked reader retained tunnel events", kind)
		}
	}
}

// The existing cross-tenant native route fixture supplies the actual managed
// networks and bilateral approval/packet/closure path. Its source-only manager
// discovers the receiving member using this public page, then signs the real
// proposal without being able to read the receiver's resources.
func nativeRouteEndpointProposer(t *testing.T, ctx context.Context, r *Runtime, root, products string, change func(string, string, uint64, any)) func(string, string, uint8, uint16) {
	t.Helper()
	name := "rq10-route-reader"
	key, err := identity.Create(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key.Private) })
	change(name, "put-user", 0, access.User{ID: name, Username: name, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}})
	change(name+"-role", "set-membership", 0, access.Membership{Tenant: "tenant", User: name, Role: access.Manager, Enabled: true})
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(self.Private) })
	peer := mydcp.Peer{ID: "node-a", Endpoint: "192.0.2.1:44101", Policy: mydcp.Policy{Key: mydcp.Identity(r.Identity.Public), Respond: true}}
	mesh, err := mydcp.NewTransport(self, r.controlPolicy.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mesh.Close() })
	user := userauth.Client{Self: self, Mesh: mesh, Cluster: r.controlPolicy.Cluster, Peers: []mydcp.Peer{peer}}
	session, err := user.Login(ctx, peer, name, key.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := user.ResourcePage(ctx, peer, session, "other", ""); err == nil {
		t.Fatal("source manager read receiver resources")
	}
	home, profile := filepath.Join(root, name+"-home"), filepath.Join(root, "route-client.yaml")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	cli := func(args ...string) []byte {
		t.Helper()
		raw, why, err := runManagedCLICommand(ctx, filepath.Join(products, "mydc"), home, profile, args, nil)
		if err != nil {
			t.Fatal("sender endpoint CLI", args, err, string(why))
		}
		return raw
	}
	cli("wallet", "init")
	cli("login", "--username", name, "--method", "private-key", "--key-file", filepath.Join(root, name, "key.pem"))
	var fromCLI userauth.Reply
	if json.Unmarshal(cli("--tenant", "other", "manage", "route-endpoints"), &fromCLI) != nil || fromCLI.PublicRead == nil || len(fromCLI.PublicRead.Rows) == 0 {
		t.Fatal("source manager CLI endpoint discovery")
	}
	find := func(tenant, node string) control.RouteEndpoint {
		t.Helper()
		page := readNativePublicPage(t, ctx, user, peer, session, "route-endpoints", tenant, control.PublicReadQuery{})
		for _, row := range page.Rows {
			if endpoint := row.RouteEndpoint; endpoint != nil && endpoint.Node == node {
				return control.RouteEndpoint{Tenant: endpoint.Tenant, Network: endpoint.Network, Node: endpoint.Node, Pool: endpoint.Pool}
			}
		}
		t.Fatal("published receiving endpoint missing", tenant, node)
		return control.RouteEndpoint{}
	}
	return func(id, node string, protocol uint8, port uint16) {
		t.Helper()
		source, destination := find("tenant", "node-a"), find("other", node)
		proposal := control.RouteProposal{ID: id, Source: source, Destination: destination, Protocol: protocol, Ports: []tenancy.Ports{{First: port, Last: port}}}
		view, err := user.ResourcePage(ctx, peer, session, "tenant", "")
		if err != nil {
			t.Fatal(err)
		}
		raw, err := control.ChangeBytes("propose-route", name, view.NetworkRevision, proposal)
		if err != nil {
			t.Fatal(err)
		}
		var change control.Change
		if json.Unmarshal(raw, &change) != nil {
			t.Fatal("typed route proposal")
		}
		op, err := user.Prepare(ctx, peer, session, "rq10-propose-"+id, change)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := user.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("published endpoint proposal by source-only manager", reply, err)
		}
	}
}

// The Vault public reads moved to 'secret usages' and 'secret approvals'; the
// rows are rebuilt into the same page shape the callers compare.
func nativeSecretReadCLI(t *testing.T, ctx context.Context, root, method, tenant string, query control.PublicReadQuery) control.PublicReadPage {
	t.Helper()
	args := []string{"secret", "usages", query.Name}
	if method == "vault-approvals" {
		args = []string{"secret", "approvals"}
		if query.App != "" {
			args = append(args, "--app", query.App)
		}
	}
	if tenant == "" {
		args = append(args, "--all")
	} else {
		args = append([]string{"--tenant", tenant}, args...)
	}
	raw, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
	if err != nil {
		t.Fatal("actual CLI public read", method, err, string(diagnostic), string(raw))
	}
	page := control.PublicReadPage{Method: method, Tenant: tenant}
	if method == "vault-usages" {
		var uses []secrets.PublicUsage
		if json.Unmarshal(raw, &uses) != nil {
			t.Fatal("actual CLI secret usages", string(raw))
		}
		for i := range uses {
			page.Rows = append(page.Rows, control.PublicReadRow{SecretUsage: &uses[i]})
		}
		page.Total = len(page.Rows)
		return page
	}
	var list []secrets.PublicApproval
	if json.Unmarshal(raw, &list) != nil {
		t.Fatal("actual CLI secret approvals", string(raw))
	}
	for i := range list {
		page.Rows = append(page.Rows, control.PublicReadRow{Approval: &list[i]})
	}
	page.Total = len(page.Rows)
	return page
}
