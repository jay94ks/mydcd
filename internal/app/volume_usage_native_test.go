// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/moby/moby/client"
)

// The gate forwards the original SDK traffic unchanged. It delays one real
// Inspect only; it never supplies a Volume, readiness or usage response.
type volumeUsageGate struct {
	mu               sync.Mutex
	name             string
	entered, release chan struct{}
	when             func() bool
	creates          int
}

func (g *volumeUsageGate) arm(name string) (<-chan struct{}, func()) { return g.armWhen(name, nil) }
func (g *volumeUsageGate) armWhen(name string, when func() bool) (<-chan struct{}, func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.name, g.entered, g.release = name, make(chan struct{}), make(chan struct{})
	g.when = when
	var once sync.Once
	return g.entered, func() { once.Do(func() { close(g.release) }) }
}
func (g *volumeUsageGate) serve(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		g.mu.Lock()
		if q.Method == "POST" && strings.HasSuffix(q.URL.Path, "/volumes/create") {
			g.creates++
		}
		var release chan struct{}
		if g.name != "" && q.Method == "GET" && strings.HasSuffix(q.URL.Path, "/volumes/"+g.name) && (g.when == nil || g.when()) {
			g.name = ""
			release = g.release
			close(g.entered)
		}
		g.mu.Unlock()
		if release != nil {
			select {
			case <-release:
			case <-q.Context().Done():
				return
			}
		}
		next.ServeHTTP(w, q)
	})
}

func TestRealBoundaryRemoteVolumeUsageCLIAndCurrentAuthorization(t *testing.T) {
	runRealVolumeOwnerBoundary(t, false, false, false)
}

func TestRealBoundarySharedVolumeBackupRaftAndNative(t *testing.T) {
	runRealVolumeOwnerBoundary(t, true, false, false)
}

func TestRealBoundaryAutomaticVolumeBackupRaftAndNative(t *testing.T) {
	runRealVolumeOwnerBoundary(t, true, true, false)
}

func TestRealBoundaryAutomaticVolumeRestoreRaftAndNative(t *testing.T) {
	runRealVolumeOwnerBoundary(t, true, true, true)
}
func TestRealBoundaryVolumeDeleteCLIOriginalJournalAndSameDB(t *testing.T) {
	runRealVolumeOwnerBoundary(t, false, false, false, volumeOwnerDelete)
}

type volumeOwnerScenario uint8

const (
	volumeOwnerDelete volumeOwnerScenario = iota + 1
	volumeOwnerCreate
	volumeOwnerCreateCancel
	volumeOwnerCreateLostJournal
	volumeOwnerRestoreBudget
	volumeOwnerBackupIO
	volumeOwnerBackupIntentIO
	volumeOwnerBackupMount
	volumeOwnerMoveSource
	volumeOwnerMoveCommit
)

func TestRealBoundaryVolumeCreateLostJournalPreservesUnknown(t *testing.T) {
	runRealVolumeOwnerBoundary(t, false, false, false, volumeOwnerCreateLostJournal)
}

func TestRealBoundaryVolumeCreateCancellationAfterNativeDispatch(t *testing.T) {
	runRealVolumeOwnerBoundary(t, false, false, false, volumeOwnerCreateCancel)
}

func TestRealBoundaryVolumeCreateCLIUnknownRecoveryAndCancel(t *testing.T) {
	runRealVolumeOwnerBoundary(t, false, false, false, volumeOwnerCreate)
}

func runRealVolumeOwnerBoundary(t *testing.T, withBackups, automatic, withRestore bool, scenario ...volumeOwnerScenario) {
	if os.Geteuid() != 0 || os.Getenv("MYDC_DOCKER_TEST_OWNER") == "" {
		t.Skip("requires owned Docker prestate and root prebuilt binary")
	}
	binary := os.Getenv("MYDC_TEST_CLI")
	if !filepath.IsAbs(binary) {
		t.Fatal("explicit user-prebuilt CLI required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, rootErr := os.MkdirTemp("", "mydc-volume-owner-")
	if rootErr != nil {
		t.Fatal(rootErr)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("preserved original volume owner recovery root", root)
		} else if e := os.RemoveAll(root); e != nil {
			t.Error(e)
		}
	})
	key := func(name string) *identity.Identity {
		t.Helper()
		k, e := identity.Create(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { clear(k.Private) })
		return k
	}
	adminKey, readerKey := key("admin"), key("reader")
	configuration := func(id, endpoint string) config.Node {
		t.Helper()
		p, e := net.ListenPacket("udp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := p.LocalAddr().String()
		_ = p.Close()
		modules := "network: {enabled: false}\n workload: {enabled: false}\n ingress: {enabled: false}"
		if endpoint != "" {
			modules = fmt.Sprintf("network: {enabled: true, docker_socket: %q}\n workload: {enabled: true}\n ingress: {enabled: false}", endpoint)
		}
		raw := fmt.Sprintf("version: 1\nnode:\n id: %s\n listen: %q\n state_dir: %q\n identity_dir: %q\nmodules:\n %s\n", id, address, filepath.Join(root, id+"-state"), filepath.Join(root, id+"-key"), modules)
		name := filepath.Join(root, id+".yaml")
		if e = os.WriteFile(name, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		cfg, e := config.LoadNode(name)
		if e != nil {
			t.Fatal(e)
		}
		return cfg
	}
	cfgA := configuration("node-a", "")
	initialized, err := Initialize(ctx, cfgA, adminKey.Public, "init-usage")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Open(cfgA)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err = a.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	clusterID := initialized.Installation.Root.Cluster
	policy := control.Policy{Cluster: clusterID, BootstrapKey: adminKey.Public, TrustRoot: a.Identity.Public, Genesis: initialized.Installation.Genesis}
	peerA := mydcp.Peer{ID: cfgA.Node.ID, Endpoint: cfgA.Node.Listen, Policy: mydcp.Policy{Key: mydcp.Identity(a.Identity.Public), Respond: true}}
	var peersMu sync.RWMutex
	peers := map[mydcp.Identity]mydcp.Peer{peerA.Key: peerA}
	user := func() userauth.Client {
		t.Helper()
		self, e := identity.Ephemeral()
		if e != nil {
			t.Fatal(e)
		}
		mesh, e := mydcp.NewTransport(self, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) {
			peersMu.RLock()
			defer peersMu.RUnlock()
			p, ok := peers[k]
			return p, ok
		})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = mesh.Close(); clear(self.Private) })
		return userauth.Client{Mesh: mesh, Self: self, Cluster: clusterID, Peers: []mydcp.Peer{peerA}}
	}
	admin := user()
	enrolled, err := admin.Enroll(ctx, peerA, control.Enrollment{Schema: 1, RequestID: "enroll", User: access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: adminKey.Public, Enabled: true}}}}, adminKey.Private)
	if err != nil || enrolled.Result == nil || enrolled.Result.Code != state.Applied {
		t.Fatal("enroll", err)
	}
	session, err := admin.Login(ctx, peerA, "admin", adminKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	change := func(id, action string, expected uint64, value any) {
		t.Helper()
		raw, e := control.ChangeBytes(action, "admin", expected, value)
		if e != nil {
			t.Fatal(e)
		}
		var c control.Change
		_ = json.Unmarshal(raw, &c)
		op, e := admin.Prepare(ctx, peerA, session, id, c)
		if e != nil {
			t.Fatal(e)
		}
		reply, e := admin.Operation(ctx, peerA, op, false)
		if e != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal(action, reply.Result, e)
		}
	}
	read := func() cluster.View {
		t.Helper()
		v, e := a.Engine().Read(ctx, true)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	change("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"})
	change("other", "create-tenant", 0, control.TenantID{ID: "other"})
	change("reader", "put-user", 0, access.User{ID: "reader", Username: "reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: readerKey.Public, Enabled: true}}})
	change("reader-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: "reader", Role: access.Manager, Enabled: true})
	// Only node-b owns the native materialization. node-a has no native adapter.
	gate := new(volumeUsageGate)
	listener, err := net.Listen("unix", filepath.Join(root, "docker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(c, "unix", "/var/run/docker.sock")
	}}
	defer transport.CloseIdleConnections()
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: "docker"})
	proxy.Transport = transport
	server := &http.Server{Handler: gate.serve(proxy)}
	go server.Serve(listener)
	defer server.Close()
	cfgB := configuration("node-b", "unix://"+listener.Addr().String())
	nodeB, err := identity.Create(cfgB.Node.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(nodeB.Private)
	change("invite-b", "invite-node", 0, control.NodeInvitation{Peer: config.Peer{ID: "node-b", Key: nodeB.Actor(), Endpoint: cfgB.Node.Listen}, JoinID: "join-b"})
	invitation, err := admin.NodeInvitation(ctx, peerA, session, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Join(ctx, cfgB, invitation, clusterID, a.Identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if b != nil {
			_ = b.Close()
		}
	}()
	peerB := mydcp.Peer{ID: "node-b", Endpoint: cfgB.Node.Listen, Policy: mydcp.Policy{Key: mydcp.Identity(b.Identity.Public), Respond: true}}
	peersMu.Lock()
	peers[peerB.Key] = peerB
	peersMu.Unlock()
	catalog, err := policy.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	change("nodes", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{"node-b"}})
	scope := volumes.Scope{Cluster: clusterID, Tenant: "tenant", App: "app", ID: "data", Generation: 1}
	spec := volumes.NativeSpec{Schema: 1, Scope: scope, Node: "node-b", NodeKey: b.Identity.Public, Materialization: "initial", UID: 10001, GID: 10001, Mode: 0750, Retain: true}
	cleanup, err := engine.Open(ctx, "unix:///var/run/docker.sock", engine.Owner(clusterID, b.Identity.Public))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cleanup.Close() })
	filter := client.Filters{}.Add("label", "org.mydc.owner="+cleanup.Owner)
	before, err := cleanup.API.VolumeList(ctx, client.VolumeListOptions{Filters: filter})
	if err != nil || len(before.Items) != 0 {
		t.Fatal("owner prestate", err)
	}
	rawSpec, _ := json.Marshal(spec)
	expected, err := cleanup.Identity("volume", volumes.NativeKey(spec), reconcile.Resource{Present: true, Generation: 1, Spec: string(rawSpec)})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("nativeOwner=" + cleanup.Owner)
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		all, e := cleanup.API.VolumeList(clean, client.VolumeListOptions{Filters: filter})
		if e != nil {
			t.Error(e)
			return
		}
		for _, v := range all.Items {
			if !expected.Matches(v.Name, v.Labels) {
				t.Error("rollback identity mismatch")
				continue
			}
			if !t.Failed() {
				t.Error("product left owned volume")
			}
			if _, e = cleanup.API.VolumeRemove(clean, v.Name, client.VolumeRemoveOptions{}); e != nil {
				t.Error(e)
			}
		}
		left, e := cleanup.API.VolumeList(clean, client.VolumeListOptions{Filters: filter})
		if e != nil || len(left.Items) != 0 {
			t.Error("rollback original volume remains", e)
		}
	})
	if len(scenario) == 1 && (scenario[0] == volumeOwnerCreate || scenario[0] == volumeOwnerCreateCancel || scenario[0] == volumeOwnerCreateLostJournal) {
		verifyVolumeCreateBoundary(t, ctx, a, &b, cfgB, root, admin, peerA, session, policy, read, change, scope, cleanup, gate, scenario[0])
		return
	}
	nativeKey, err := b.nativeVolumes.Desired(spec, 1, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.nativeVolumes.Step(ctx, nativeKey); err != nil {
		t.Fatal(err)
	}
	ready, err := b.nativeVolumes.Ready(ctx, nativeKey, b.Identity.Private)
	if err != nil {
		t.Fatal(err)
	}
	change("volume", "create-volume", 0, ready)
	disk, err := cleanup.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	marker := []byte("retained volume usage fixture")
	if err = os.WriteFile(filepath.Join(disk.Volume.Mountpoint, "row"), marker, 0600); err != nil {
		t.Fatal(err)
	}
	if len(scenario) == 1 && scenario[0] == volumeOwnerDelete {
		verifyVolumeDeleteBoundary(t, ctx, a, &b, cfgB, root, admin, peerA, session, policy, read, change, ready, cleanup, gate)
		return
	}
	if withBackups {
		if err = os.Chown(filepath.Join(disk.Volume.Mountpoint, "row"), int(spec.UID), int(spec.GID)); err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(filepath.Join(disk.Volume.Mountpoint, "row"), 0640); err != nil {
			t.Fatal(err)
		}
		if automatic {
			selected := volumeOwnerScenario(0)
			if len(scenario) == 1 {
				selected = scenario[0]
			}
			verifyAutomaticBackupBoundary(t, ctx, a, &b, cfgB, root, admin, peerA, session, policy, read, change, ready, cleanup, gate, withRestore, selected)
			return
		}
		verifySharedBackupBoundary(t, ctx, a, &b, cfgB, root, admin, peerA, session, policy, read, change, ready, marker)
		return
	}
	reader := user()
	readerSession, err := reader.Login(ctx, peerA, "reader", readerKey.Private)
	if err != nil {
		t.Fatal(err)
	}
	selector := control.VolumeSelector{App: "app", ID: "data"}
	verify := func(reply userauth.Reply, e error) {
		t.Helper()
		if e != nil || reply.VolumeUsage == nil || !reply.VolumeUsage.Matches(ready) || reply.VolumeUsage.LogicalBytes != uint64(len(marker)) || reply.VolumeUsageIndex == 0 {
			t.Fatal("remote native usage", reply.VolumeUsage, e)
		}
	}
	reply, err := reader.VolumeUsage(ctx, peerA, readerSession, "tenant", selector)
	verify(reply, err)
	reply, err = admin.VolumeUsage(ctx, peerB, session, "tenant", selector)
	verify(reply, err)
	if reply.RelayedBy != b.Identity.Actor() {
		t.Fatal("original user request did not relay via worker")
	}
	if _, err = reader.VolumeUsage(ctx, peerA, readerSession, "other", selector); err == nil {
		t.Fatal("foreign tenant observed")
	}
	// An unrelated catalog change may advance the authority while a scan is
	// running. Return all authority metadata from the final validation view.
	metadataEntered, metadataRelease := gate.arm(ready.Owner.Native)
	defer metadataRelease()
	type usageAnswer struct {
		reply userauth.Reply
		err   error
	}
	metadataAnswer := make(chan usageAnswer, 1)
	go func() {
		reply, err := admin.VolumeUsage(ctx, peerA, session, "tenant", selector)
		metadataAnswer <- usageAnswer{reply, err}
	}()
	select {
	case <-metadataEntered:
	case answer := <-metadataAnswer:
		t.Fatal("observation failed before metadata gate", answer.err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	change("unrelated-catalog", "create-tenant", 0, control.TenantID{ID: "unrelated"})
	finalCatalogRevision := read().State.Object(control.CatalogKey).Revision
	metadataRelease()
	metadata := <-metadataAnswer
	verify(metadata.reply, metadata.err)
	if metadata.reply.RootRevision != finalCatalogRevision {
		t.Fatal("usage returned mixed authority views", metadata.reply.RootRevision, finalCatalogRevision)
	}
	nativeBody, _ := json.Marshal(ready)
	nativePeer, known := a.Mesh.Peer(mydcp.Identity(b.Identity.Public))
	if !known {
		t.Fatal("current member peer missing")
	}
	if _, err = cluster.CallManagement(ctx, a.Mesh, a.Identity, clusterID, nativePeer, cluster.ManagementRequest{Method: "volume-usage-permit", Latest: true, Input: nativeBody}); err == nil {
		t.Fatal("other member impersonated native owner")
	}
	entered, release := gate.arm(ready.Owner.Native)
	defer release()
	answer := make(chan error, 1)
	go func() { _, e := reader.VolumeUsage(ctx, peerA, readerSession, "tenant", selector); answer <- e }()
	select {
	case <-entered:
	case e := <-answer:
		t.Fatal("observation failed before actual Inspect gate", e)
	case <-ctx.Done():
		t.Fatal("real Inspect gate", ctx.Err())
	}
	catalog, err = policy.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	membership, _ := catalog.Membership("tenant", "reader")
	change("revoke-reader", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: "reader", Role: access.Manager, Enabled: false})
	release()
	var denied *userauth.Error
	if e := <-answer; !errors.As(e, &denied) || denied.Code != "denied" {
		t.Fatal("revoked in-flight observation published", e)
	}
	// The CLI logs in at the voter (a context has one endpoint, and only a
	// voter issues sessions); the leader collects the actual observation from
	// the nonvoter native owner.
	home := filepath.Join(root, "home")
	if err = os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "client.yaml")
	profileData := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n - {id: node-b, key: '%x', endpoint: '%s', voter: false}\n", clusterID, a.Identity.Public, cfgA.Node.Listen, b.Identity.Public, cfgB.Node.Listen)
	if err = os.WriteFile(profile, []byte(profileData), 0600); err != nil {
		t.Fatal(err)
	}
	selectedTenant := ""
	cli := func(args ...string) any {
		t.Helper()
		args = withTenant(selectedTenant, args)
		command := nativeCLICmd(ctx, binary, home, profile, args...)
		var out, diagnostic bytes.Buffer
		command.Stdout, command.Stderr = &out, &diagnostic
		if e := command.Run(); e != nil {
			t.Fatal("CLI", args, e, diagnostic.String())
		}
		var v any
		if out.Len() != 0 && json.Unmarshal(out.Bytes(), &v) != nil {
			t.Fatal("CLI JSON")
		}
		if bytes.Contains(out.Bytes(), []byte(disk.Volume.Mountpoint)) || bytes.Contains(out.Bytes(), marker) {
			t.Fatal("CLI leaked path/data")
		}
		return v
	}
	cli("wallet", "init")
	cli("--peer", "node-a", "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	listed := cli("--tenant", "tenant", "volume", "list")
	if rows, ok := listed.([]any); !ok || len(rows) != 1 {
		t.Fatal("CLI volume list", listed)
	}
	observed, _ := cli("--tenant", "tenant", "volume", "usage", "app/data").(map[string]any)
	if entries, _ := observed["Entries"].(float64); entries == 0 {
		t.Fatal(observed)
	}
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	b = nil
	b, err = Open(cfgB)
	if err != nil {
		t.Fatal("same owner DB reopen", err)
	}
	for {
		_, leader := b.Engine().Leader()
		if leader != "" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	reply, err = admin.VolumeUsage(ctx, peerA, session, "tenant", selector)
	verify(reply, err)
	if err = b.nativeVolumes.DeleteDesired(nativeKey, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err = b.nativeVolumes.Step(ctx, nativeKey); err != nil {
		t.Fatal(err)
	}
	if gone, e := b.nativeVolumes.Gone(ctx, nativeKey, 2, 1); e != nil || !gone {
		t.Fatal("original native removal", e)
	}
	t.Log("actual control/nonvoter native-owner MYDCP and private-key user/CLI list+usage; current scope and in-flight revoke; owner impersonation denied; no local/cached fallback; original signed materialization and same DB; observe-only private-free result; original nonforce removal/owner0/host rollback")
}
