// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func TestRealBoundaryManagedAppCreateReplyLossN2Recovery(t *testing.T) {
	// Existing real CLI/remote Vault/Task/Volume/retirement fixture, with a
	// response fault at the actual Engine boundary, not a replacement driver.
	runManagedAppOwner(t, true, true, true, true, managedAppReplyLossN2, true, true, false, true)
}

func TestRealBoundaryManagedAppCreateReplyLossControlHandoff(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppReplyLossHandoff, true, true, false, true)
}

type managedCreateReplyEvidence struct {
	ID, Name, Error          string
	Creates, Starts, Blocked int
	ReplyLost, InspectHeld   bool
}
type managedCreateReplyFault struct {
	mu                       sync.Mutex
	endpoint                 string
	owner, key               string
	evidence                 managedCreateReplyEvidence
	transport                *http.Transport
	forward                  *httputil.ReverseProxy
	stopOnly                 bool
	stopAfter                bool
	stopCalls                uint64
	stopID, stopName         string
	stopEntered, stopRelease chan struct{}
	stopOnce, releaseOnce    sync.Once
	networkOnly              bool
	networkID, networkName   string
	networkFailures          uint64
	usage                    *volumeUsageGate
	exec                     *managedExecReplyFault
}

func openManagedVolumeUsageGate(t *testing.T, root string) (*managedCreateReplyFault, *volumeUsageGate) {
	t.Helper()
	f := openManagedCreateReplyFault(t, root)
	g := &volumeUsageGate{}
	f.mu.Lock()
	f.usage = g
	f.mu.Unlock()
	return f, g
}

// Fail one original network Inspect at the real SDK transport boundary. Every
// other request/response is forwarded to Docker, including all native creates.
func openManagedNetworkReadFault(t *testing.T, root string) *managedCreateReplyFault {
	t.Helper()
	f := openManagedCreateReplyFault(t, root)
	f.mu.Lock()
	f.networkOnly = true
	f.mu.Unlock()
	return f
}

func (f *managedCreateReplyFault) failNetworkInspect(id, name string) {
	f.mu.Lock()
	f.networkID, f.networkName = id, name
	f.mu.Unlock()
}

func (f *managedCreateReplyFault) networkReadFailures() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.networkFailures
}

// Reuse the same owned Engine transport for an original Stop barrier. Every
// response/state still comes from Docker; this mode never loses Create replies.
func openManagedStopFault(t *testing.T, root string) *managedCreateReplyFault {
	t.Helper()
	f := openManagedCreateReplyFault(t, root)
	f.mu.Lock()
	f.stopOnly = true
	f.stopEntered, f.stopRelease = make(chan struct{}), make(chan struct{})
	f.mu.Unlock()
	t.Cleanup(f.releaseStop)
	return f
}

func (f *managedCreateReplyFault) holdStop(id, name string) {
	f.mu.Lock()
	f.stopID, f.stopName = id, strings.TrimPrefix(name, "/")
	f.mu.Unlock()
}

func (f *managedCreateReplyFault) holdStopResponse(id, name string) {
	f.mu.Lock()
	f.stopID, f.stopName, f.stopAfter = id, strings.TrimPrefix(name, "/"), true
	f.mu.Unlock()
}

func (f *managedCreateReplyFault) stoppedCalls() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCalls
}

func (f *managedCreateReplyFault) releaseStop() {
	f.releaseOnce.Do(func() { close(f.stopRelease) })
}

func openManagedCreateReplyFault(t *testing.T, root string) *managedCreateReplyFault {
	return openManagedCreateReplyFaultAt(t, root, "/var/run/docker.sock")
}

// Same real SDK response fault, with an explicit original private Engine for
// source/adoption fixtures. A private fixture never falls back to host Docker.
func openManagedCreateReplyFaultAt(t *testing.T, root, upstream string) *managedCreateReplyFault {
	t.Helper()
	if !filepath.IsAbs(upstream) || filepath.Clean(upstream) != upstream {
		t.Fatal("explicit original Engine socket required")
	}
	socket := filepath.Join(root, "engine-fault.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	f := &managedCreateReplyFault{endpoint: "unix://" + socket}
	f.transport = &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", upstream)
	}}
	target, _ := url.Parse("http://docker")
	f.forward = httputil.NewSingleHostReverseProxy(target)
	f.forward.Transport = f.transport
	server := &http.Server{Handler: f, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(l) }()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
		f.transport.CloseIdleConnections()
	})
	return f
}
func (f *managedCreateReplyFault) arm(owner, key string) {
	f.mu.Lock()
	f.owner, f.key = owner, key
	f.mu.Unlock()
}
func (f *managedCreateReplyFault) snapshot() managedCreateReplyEvidence {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.evidence
}
func (f *managedCreateReplyFault) releaseInspect() {
	f.mu.Lock()
	f.evidence.InspectHeld = false
	f.mu.Unlock()
}
func (f *managedCreateReplyFault) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	f.mu.Lock()
	if f.exec != nil {
		gate := f.exec
		f.mu.Unlock()
		gate.serve(f, w, req)
		return
	}
	if f.usage != nil {
		gate := f.usage
		f.mu.Unlock()
		gate.serve(f.forward).ServeHTTP(w, req)
		return
	}
	if f.networkOnly {
		name := path.Base(req.URL.Path)
		fail := req.Method == http.MethodGet && strings.Contains(req.URL.Path, "/networks/") && f.networkID != "" && (name == f.networkID || name == f.networkName)
		if fail {
			f.networkFailures++
		}
		f.mu.Unlock()
		if fail {
			http.Error(w, "owned target native network inspection unavailable", http.StatusServiceUnavailable)
			return
		}
		f.forward.ServeHTTP(w, req)
		return
	}
	if f.stopOnly {
		name := path.Base(path.Dir(req.URL.Path))
		stop := req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/stop") && strings.Contains(req.URL.Path, "/containers/") && f.stopID != "" && (name == f.stopID || name == f.stopName)
		after := f.stopAfter
		if stop {
			f.stopCalls++
		}
		f.mu.Unlock()
		if stop {
			if after {
				upstream := req.Clone(req.Context())
				upstream.RequestURI = ""
				upstream.URL.Scheme, upstream.URL.Host = "http", "docker"
				response, err := f.transport.RoundTrip(upstream)
				if err != nil {
					http.Error(w, "owned Stop upstream failed", http.StatusBadGateway)
					return
				}
				_, drainErr := io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
				_ = response.Body.Close()
				if drainErr != nil || response.StatusCode != http.StatusNoContent {
					http.Error(w, "owned Stop did not complete", http.StatusBadGateway)
					return
				}
			}
			f.stopOnce.Do(func() { close(f.stopEntered) })
			select {
			case <-f.stopRelease:
			case <-req.Context().Done():
				return
			}
			if after {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
		}
		f.forward.ServeHTTP(w, req)
		return
	}
	same := f.evidence.ID != "" && (path.Base(path.Dir(req.URL.Path)) == f.evidence.ID || path.Base(path.Dir(req.URL.Path)) == f.evidence.Name)
	if req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/json") && strings.Contains(req.URL.Path, "/containers/") && same && f.evidence.InspectHeld {
		f.evidence.Blocked++
		f.mu.Unlock()
		http.Error(w, "owned test Inspect held after lost Create reply", http.StatusServiceUnavailable)
		return
	}
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/start") && strings.Contains(req.URL.Path, "/containers/") && same {
		f.evidence.Starts++
	}
	owner, key := f.owner, f.key
	f.mu.Unlock()
	if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/containers/create") {
		f.forward.ServeHTTP(w, req)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, 2<<20+1))
	_ = req.Body.Close()
	defer clear(raw)
	if err != nil || len(raw) > 2<<20 {
		http.Error(w, "invalid owned test Create body", http.StatusBadRequest)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	var config container.Config
	if json.Unmarshal(raw, &config) != nil || owner == "" || config.Labels["org.sfc.owner"] != owner || config.Labels["org.sfc.key"] != key || config.Labels["org.sfc.kind"] != "container" {
		f.forward.ServeHTTP(w, req)
		return
	}
	f.mu.Lock()
	f.evidence.Creates++
	count := f.evidence.Creates
	f.mu.Unlock()
	if count != 1 {
		http.Error(w, "duplicate original Create attempt rejected by test", http.StatusConflict)
		return
	}
	upstream := req.Clone(req.Context())
	upstream.RequestURI = ""
	upstream.URL.Scheme, upstream.URL.Host = "http", "docker"
	response, err := f.transport.RoundTrip(upstream)
	if err != nil {
		f.mu.Lock()
		f.evidence.Error = "upstream Create transport failed"
		f.mu.Unlock()
		http.Error(w, "upstream test transport failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 8193))
	var created struct{ ID string }
	if response.StatusCode != http.StatusCreated || readErr != nil || len(body) > 8192 || json.Unmarshal(body, &created) != nil || len(created.ID) != 64 {
		f.mu.Lock()
		f.evidence.Error = "upstream did not confirm original Create"
		f.mu.Unlock()
		for k, v := range response.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(response.StatusCode)
		_, _ = w.Write(body)
		return
	}
	f.mu.Lock()
	f.evidence.ID, f.evidence.Name = created.ID, req.URL.Query().Get("name")
	f.evidence.ReplyLost, f.evidence.InspectHeld = true, true
	f.mu.Unlock()
	// Docker really returned 201. The SDK receives EOF; no synthetic success,
	// container state, journal completion or owner observation is supplied.
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		f.mu.Lock()
		f.evidence.Error = "failed to close owned Create response connection"
		f.mu.Unlock()
		return
	}
	_ = conn.Close()
}

func promoteManagedFaultProvider(t *testing.T, ctx context.Context, a, b *Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	for {
		d, err := p.Members(read().State)
		e, ok := d.Entry("node-b")
		if err == nil && ok && e.Phase == membership.Ready {
			change("fault-promote-b", "promote-node", e.Revision, control.NodeSelection{ID: "node-b"})
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("provider learner readiness", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	for {
		d, err := p.Members(read().State)
		e, ok := d.Entry("node-b")
		if err == nil && ok && e.Phase == membership.Active && e.Peer.Voter {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("provider voter promotion", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	installed, err := a.Engine().InstalledConfiguration(ctx, true)
	voters := 0
	for _, server := range installed.Configuration.Servers {
		if server.Suffrage == raft.Voter {
			voters++
		}
	}
	if err != nil || voters != 2 || len(a.vaultBackends) != 0 || len(b.vaultBackends) != 2 {
		t.Fatal("actual N2/provider boundary", voters, err)
	}
}

func prepareManagedHandoffControl(t *testing.T, ctx context.Context, root string, source *Runtime, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), names ...string) *Runtime {
	t.Helper()
	return prepareManagedHandoffControlAtReady(t, ctx, root, source, user, peer, session, p, read, change, nil, nil, names...)
}

// The optional hooks consume the same installed learner before its existing
// promotion; they do not create another runtime, source or native app fixture.
func prepareManagedHandoffControlAtReady(t *testing.T, ctx context.Context, root string, source *Runtime, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), configure func(*config.Node), ready func(*Runtime), names ...string) *Runtime {
	t.Helper()
	nodeID, suffix := "node-c", "c"
	if len(names) > 0 {
		nodeID, suffix = names[0], names[0]
	}
	before, err := source.Engine().InstalledConfiguration(ctx, true)
	if err != nil {
		t.Fatal("original handoff configuration", err)
	}
	wantVoters := 1
	for _, server := range before.Configuration.Servers {
		if server.Suffrage == raft.Voter {
			wantVoters++
		}
	}
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = nodeID, address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "control-"+suffix+"-state"), filepath.Join(root, "control-"+suffix+"-key")
	if configure != nil {
		configure(&cfg)
	}
	key, err := identity.Create(cfg.Node.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	change("fault-invite-"+suffix, "invite-node", 0, control.NodeInvitation{Peer: config.Peer{ID: nodeID, Key: key.Actor(), Endpoint: address}, JoinID: "fault-join-" + suffix})
	inv, err := user.NodeInvitation(ctx, peer, session, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := Join(ctx, cfg, inv, user.Cluster, source.Identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	for {
		d, err := p.Members(read().State)
		e, ok := d.Entry(nodeID)
		if err == nil && ok && e.Phase == membership.Ready {
			if ready != nil {
				ready(r)
			}
			change("fault-promote-"+suffix, "promote-node", e.Revision, control.NodeSelection{ID: nodeID})
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("handoff learner readiness", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	for {
		d, err := p.Members(read().State)
		e, ok := d.Entry(nodeID)
		if err == nil && ok && e.Phase == membership.Active && e.Peer.Voter {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("handoff voter promotion", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	installed, err := source.Engine().InstalledConfiguration(ctx, true)
	voters := 0
	for _, server := range installed.Configuration.Servers {
		if server.Suffrage == raft.Voter {
			voters++
		}
	}
	if err != nil || voters != wantVoters || len(installed.Configuration.Servers) != len(before.Configuration.Servers)+1 || len(r.vaultBackends) != 0 {
		t.Fatal("actual added handoff voter configuration", voters, "want", wantVoters, err)
	}
	return r
}

func verifyManagedCreateReplyFault(t *testing.T, ctx context.Context, f *managedCreateReplyFault, a, b **Runtime, c *Runtime, cfg config.Node, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool)) map[string]any {
	t.Helper()
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	wait("actual Create 201 reply lost and original journal Unknown", func() bool {
		evidence := f.snapshot()
		if evidence.Error != "" || evidence.Creates > 1 {
			t.Fatal("first native Create failure", evidence)
		}
		if !evidence.ReplyLost || evidence.Blocked == 0 {
			return false
		}
		row, err := (*a).workload.View(key)
		return err == nil && row.State.Pending != nil && row.State.Pending.Phase == reconcile.RecoveryRequired
	})
	evidence := f.snapshot()
	original, err := (*a).workload.View(key)
	if err != nil || original.State.Applied.Present || original.State.Pending == nil || original.State.Pending.ID != original.State.LastID || evidence.Creates != 1 || evidence.Starts != 0 {
		t.Fatal("original Unknown journal", err, evidence)
	}
	direct, err := engine.Open(ctx, "unix:///var/run/docker.sock", (*a).owner)
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	inspect := func() {
		t.Helper()
		got, err := direct.API.ContainerInspect(ctx, evidence.ID, client.ContainerInspectOptions{})
		if err != nil || got.Container.State == nil || got.Container.State.Running || got.Container.ID != evidence.ID || got.Container.Config.Labels["org.sfc.owner"] != (*a).owner || got.Container.Config.Labels["org.sfc.key"] != key {
			t.Fatal("actual original stopped object", err)
		}
	}
	inspect()
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	execution, _ := apps.Execution("tenant", "app")
	stage, _ := execution.Stage(key)
	if stage.Result == nil || stage.Observation != nil {
		t.Fatal("unobserved native effect became success")
	}
	request := deployment.ObjectRef{Key: key, Generation: stage.Result.Generation, Revision: stage.Result.Revision}
	binding, ok := apps.Binding(request)
	if !ok || len(binding.Pins()) != 1 || len(binding.Grants()) != 1 {
		t.Fatal("original shared input/writer reservation missing")
	}
	bridgeKey := deployment.ResourceKey("bridge", "tenant", "app", "app/node-a")
	bridge, err := (*a).network.View(bridgeKey)
	if err != nil || len(bridge.Consumers) == 0 {
		t.Fatal("Unknown returned original Bridge pin", err)
	}
	providerCfg, providerKey := (*b).installation.config, (*b).Identity.Public
	// Runtime's opening record precedes Join/PrepareAck. The signed durable
	// installation is the authority for the original ACK, not that snapshot.
	providerRecord, err := bootstrap.Read(providerCfg)
	if err != nil || providerRecord.Ack == nil || providerRecord.Ack.Key != providerKey {
		t.Fatal("original durable provider ACK", err)
	}
	ack := providerRecord.Ack
	if err := (*b).Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := (*a).Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if c == nil {
		if err := (*b).Close(); err != nil {
			t.Fatal(err)
		}
		*b = nil
	}
	t.Cleanup(func() {
		if *b != nil {
			if err := (*b).Close(); err != nil {
				t.Error(err)
			}
			*b = nil
		}
	})
	if c == nil {
		limited, stop := context.WithTimeout(ctx, 2*time.Second)
		_, err = user.AppOperation(limited, peer, session, "tenant", control.AppOperationRequest{App: "app", ID: "rollout"})
		stop()
		if err == nil {
			t.Fatal("minority app query claimed fresh quorum")
		}
	} else if !(*a).Engine().IsLeader() {
		t.Fatal("handoff must terminate the actual original SDK leader")
	}
	if err := (*a).Close(); err != nil {
		t.Fatal(err)
	}
	*a = nil
	leaderID := ""
	if c == nil {
		*b, err = Open(providerCfg)
		if err != nil {
			t.Fatal("same provider voter DB", err)
		}
	} else {
		for !(*b).Engine().IsLeader() && !c.Engine().IsLeader() {
			select {
			case <-ctx.Done():
				t.Fatal("new quorum leader", ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		leader := *b
		if c.Engine().IsLeader() {
			leader = c
		}
		leaderID = leader.installation.record.Root.Self.ID
		peers := map[sfcp.Identity]sfcp.Peer{peer.Key: peer}
		remote := user
		for _, member := range []*Runtime{*b, c} {
			m := sfcp.Peer{ID: member.installation.record.Root.Self.ID, Endpoint: member.installation.record.Endpoint, Policy: sfcp.Policy{Key: sfcp.Identity(member.Identity.Public), Respond: true}}
			peers[m.Key] = m
			remote.Peers = append(remote.Peers, m)
		}
		remote.Mesh, err = sfcp.NewTransport(user.Self, user.Cluster, func(k sfcp.Identity) (sfcp.Peer, bool) { p, ok := peers[k]; return p, ok })
		if err != nil {
			t.Fatal(err)
		}
		defer remote.Mesh.Close()
		selected := peers[sfcp.Identity(leader.Identity.Public)]
		originalOperation, _ := apps.Inventory("tenant", "app")
		before, _ := originalOperation.Active()
		reply, err := remote.AppOperation(ctx, selected, session, "tenant", control.AppOperationRequest{App: "app", ID: "rollout"})
		if err != nil || reply.AppOperation == nil || !reply.AppOperation.Found || !reply.AppOperation.Current || reply.AppOperation.Operation.Plan != before.Plan || reply.AppOperation.Operation.Epoch != before.Epoch || reply.AppOperation.Operation.Submitter != before.Submitter {
			t.Fatal("new control lost original accepted app", err)
		}
		// A real new commit proves control continues while the native owner and
		// original issuer are stopped; this is not merely a local stale read.
		raw, _ := control.ChangeBytes("create-tenant", session.User, 0, control.TenantID{ID: "handoff-current"})
		var change control.Change
		_ = json.Unmarshal(raw, &change)
		op, err := remote.Prepare(ctx, selected, session, "fault-new-leader-change", change)
		if err != nil {
			t.Fatal(err)
		}
		applied, err := remote.Operation(ctx, selected, op, false)
		if err != nil || applied.Result == nil || applied.Result.Code != state.Applied {
			t.Fatal("new control cannot commit", err)
		}
	}
	*a, err = Open(cfg)
	if err != nil {
		t.Fatal("same owner DB", err)
	}
	if _, err := (*a).InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	if c != nil && (*a).Engine().IsLeader() {
		t.Fatal("original owner must recover under the successor control")
	}
	if resumed, err := (*b).ResumeInstallation(ctx); err != nil || (*b).Identity.Public != providerKey || !reflect.DeepEqual(resumed.Ack, ack) {
		t.Fatal("same provider identity/ACK", err)
	}
	if len((*a).vaultBackends) != 0 || len((*b).vaultBackends) != 2 {
		t.Fatal("provider credentials moved to consumer")
	}
	again, err := (*a).workload.View(key)
	if err != nil || again.State.LastID != original.State.LastID || !reflect.DeepEqual(again.State.Pending, original.State.Pending) || again.State.Applied != original.State.Applied {
		t.Fatal("same DB replaced Unknown", err)
	}
	current, err := (*a).network.View(bridgeKey)
	if err != nil || !reflect.DeepEqual(current.Consumers, bridge.Consumers) {
		t.Fatal("same DB lost original bridge pins", err)
	}
	apps, err = p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	resumedBinding, ok := apps.Binding(request)
	if !ok || resumedBinding.Digest() != binding.Digest() || !reflect.DeepEqual(resumedBinding.Pins(), binding.Pins()) || !reflect.DeepEqual(resumedBinding.Grants(), binding.Grants()) {
		t.Fatal("same DB replaced shared binding")
	}
	inspect()
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	trust := append([]access.TrustRule(nil), tenant.ImageSources...)
	change("fault-revoke-image-source", "set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Remove: trust})
	f.releaseInspect()
	if err := (*a).workload.Step(ctx, key); err == nil {
		t.Fatal("untrusted original stopped Task was activated")
	}
	inspect()
	afterDenial, err := (*a).workload.View(key)
	if err != nil || afterDenial.State.LastID != original.State.LastID || !reflect.DeepEqual(afterDenial.State.Pending, original.State.Pending) || f.snapshot().Creates != 1 || f.snapshot().Starts != 0 {
		t.Fatal("denial replaced/dispatched original native work", err, f.snapshot())
	}
	catalog, _ = p.Catalog(read().State)
	tenant, _ = catalog.Tenant("tenant")
	change("fault-restore-image-source", "set-trust", tenant.Revision, control.TrustChange{Tenant: "tenant", Add: trust})
	wait("same original container after explicit trust restore", func() bool {
		status, err := (*a).workload.Status(ctx, key)
		if f.snapshot().Creates != 1 {
			t.Fatal("second Create attempted")
		}
		return err == nil && status.Ready && status.NativeID == evidence.ID
	})
	settled, err := (*a).workload.View(key)
	if err != nil || settled.State.Pending != nil || settled.State.LastID != original.State.LastID || settled.State.Applied != original.State.Pending.Target || f.snapshot().Starts != 1 {
		t.Fatal("original native settlement changed identity", err)
	}
	voters := 2
	if c != nil {
		voters = 3
	}
	t.Logf("actual owned Docker Create 201 reply lost; original A2 Unknown/Secret/writer/Bridge pins survived original control stop and same owner DB recovery; voters=%d successor=%s; current trust blocked Start, explicit restore recovered exact ID with one Create/Start", voters, leaderID)
	return map[string]any{"unknown": evidence, "before": original.State, "after": settled.State, "task": request, "binding": binding.Digest(), "quorum_voters": voters, "handoff_leader": leaderID, "provider_key": providerKey, "original_bridge_pins": bridge.Consumers}
}
