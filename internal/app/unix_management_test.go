// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// U0 final native integration: private temporary node DB/keys, loopback UDP,
// private Unix socket. The cleanup closes clients/runtime, releases the owned
// listeners and removes only this test root. No global socket/kernel/Docker
// changes, external provider or retained E4 recovery state are involved.
func TestU0UnixUserAuthOriginalOperationAndSameDB(t *testing.T) {
	root, err := os.MkdirTemp("", "sfc-u0-auth-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(admin.Private) })
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	c := config.Node{Version: 1, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	c.Node.ID, c.Node.Listen, c.Node.IdentityDir, c.Node.StateDir = "node", address, filepath.Join(root, "node-key"), filepath.Join(root, "state")
	c.Node.ManagementSocket = filepath.Join(root, "management.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	initialized, err := Initialize(ctx, c, admin.Public, "init-u0")
	if err != nil {
		t.Fatal(err)
	}
	cluster := initialized.Installation.Root.Cluster
	var runtime *Runtime
	start := func() {
		t.Helper()
		runtime, err = Open(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = runtime.InstallConfiguration(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runtime.Mesh.ListenUnix(c.Node.ManagementSocket); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if runtime != nil {
			_ = runtime.Close()
		}
	})
	wait := func() {
		t.Helper()
		for {
			if runtime.Engine().IsLeader() {
				if _, err := runtime.Engine().Read(ctx, true); err == nil {
					return
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	start()
	wait()
	node := runtime.Identity
	unixPeer := sfcp.Peer{ID: "node", Endpoint: "unix://" + c.Node.ManagementSocket, Policy: sfcp.Policy{Key: sfcp.Identity(node.Public), Respond: true}}
	remotePeer := unixPeer
	remotePeer.Endpoint = "sfcp://" + address
	newClient := func(peer sfcp.Peer) userauth.Client {
		t.Helper()
		self, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := sfcp.NewTransport(self, cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return peer, key == peer.Key })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = mesh.Close(); clear(self.Private) })
		return userauth.Client{Mesh: mesh, Self: self, Cluster: cluster, Peers: []sfcp.Peer{peer}}
	}
	local := newClient(unixPeer)
	intent := control.Enrollment{Schema: 1, RequestID: "u0-enrollment", User: access.User{ID: "operator", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}
	if reply, err := local.Enroll(ctx, unixPeer, intent, admin.Private); err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
		t.Fatal("Unix enrollment", reply.Code, err)
	}
	session, err := local.Login(ctx, unixPeer, "operator", admin.Private)
	if err != nil {
		t.Fatal("challenge/proof must retain one real TLS binding", err)
	}
	if reply, err := local.Whoami(ctx, unixPeer, session); err != nil || reply.User.ID != "operator" {
		t.Fatal("Unix session", reply, err)
	}
	change, err := control.ChangeBytes("create-tenant", "operator", 0, control.TenantID{ID: "apps"})
	if err != nil {
		t.Fatal(err)
	}
	var mutation control.Change
	if err := json.Unmarshal(change, &mutation); err != nil {
		t.Fatal(err)
	}
	original, err := local.Prepare(ctx, unixPeer, session, "u0-original-operation", mutation)
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := local.Operation(ctx, unixPeer, original, false)
	if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
		t.Fatal("same management core", reply.Code, err)
	}
	result, err := json.Marshal(reply.Result)
	if err != nil {
		t.Fatal(err)
	}
	// QUIC still uses the same handler and the new shared challenge exchange.
	remote := newClient(remotePeer)
	remoteSession, err := remote.Login(ctx, remotePeer, "operator", admin.Private)
	if err != nil {
		t.Fatal("remote authentication regressed", err)
	}
	if reply, err := remote.Tenants(ctx, remotePeer, remoteSession); err != nil || len(reply.Tenants) != 1 || reply.Tenants[0].ID != "apps" {
		t.Fatal("same catalog through QUIC", reply, err)
	}
	if err := local.Mesh.Close(); err != nil {
		t.Fatal(err)
	}
	if err := remote.Mesh.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime = nil
	start()
	wait()
	mesh, err := sfcp.NewTransport(local.Self, cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return unixPeer, key == unixPeer.Key })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mesh.Close() })
	local.Mesh = mesh
	recovered, err := local.Result(ctx, unixPeer, session, original)
	if err != nil || recovered.Result == nil {
		t.Fatal("original result after same DB reopen", recovered.Code, err)
	}
	afterResult, _ := json.Marshal(recovered.Result)
	after, _ := json.Marshal(original)
	if !bytes.Equal(before, after) || !bytes.Equal(result, afterResult) {
		t.Fatal("original signed request or result changed")
	}
	// Drop real encrypted reply bytes after an authenticated connection has
	// prepared ONE command. The real daemon still commits it in its actual DB.
	// This proves post-send Unknown/reconnect/result over the Unix adapter, not
	// just a synthetic transport error or a timeout reclassified as non-execution.
	proxyPath := filepath.Join(root, "reply-loss.sock")
	drop, dropped := u0UnixReplyProxy(t, proxyPath, c.Node.ManagementSocket)
	proxyPeer := unixPeer
	proxyPeer.Endpoint = "unix://" + proxyPath
	uncertain := newClient(proxyPeer)
	grant, err := uncertain.Login(ctx, proxyPeer, "operator", admin.Private)
	if err != nil {
		t.Fatal("reply-loss fixture login", err)
	}
	change, err = control.ChangeBytes("create-tenant", "operator", 0, control.TenantID{ID: "uncertain"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(change, &mutation); err != nil {
		t.Fatal(err)
	}
	uncertainIntent, err := uncertain.Prepare(ctx, proxyPeer, grant, "u0-unknown-original", mutation)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "private-cli")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := userauth.StageOperation(home, uncertain, uncertainIntent); err != nil {
		t.Fatal(err)
	}
	drop.Store(true)
	faultCtx, faultCancel := context.WithTimeout(ctx, time.Second)
	_, fault := uncertain.Operation(faultCtx, proxyPeer, uncertainIntent, false)
	faultCancel()
	var transport *userauth.Error
	if !errors.As(fault, &transport) || transport.Phase != sfcp.Unknown || dropped.Load() == 0 {
		t.Fatal("post-send reply loss was not Unknown", fault)
	}
	view, err := runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := (control.Policy{Cluster: cluster, BootstrapKey: admin.Public, TrustRoot: runtime.Identity.Public, Genesis: initialized.Installation.Genesis}).Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := catalog.Tenant("uncertain"); !exists {
		t.Fatal("fixture did not commit the unknown command")
	}
	drop.Store(false)
	resolved, err := uncertain.Result(ctx, proxyPeer, grant, uncertainIntent)
	if err != nil || !resolved.Found || resolved.Result == nil || resolved.Result.Code != state.Applied {
		t.Fatal("unknown original result after reconnect", resolved.Code, err)
	}
	if err := userauth.RecordOperationResult(home, uncertain, grant, uncertainIntent, *resolved.Result); err != nil {
		t.Fatal(err)
	}
	retained, err := userauth.LoadOperation(home, uncertain, grant, uncertainIntent.RequestID)
	if err != nil || retained.Result == nil || *retained.Result != *resolved.Result || !bytes.Equal(control.OperationBytes(retained.Operation), control.OperationBytes(uncertainIntent)) || !bytes.Equal(retained.Operation.Signature, uncertainIntent.Signature) {
		t.Fatal("Unknown reconciliation replaced original", err)
	}
}

// Raw Unix relay: TLS/challenge/frames still terminate at the actual product
// daemon/client. The only injected fault is discarding selected reply bytes.
func u0UnixReplyProxy(t *testing.T, path, target string) (*atomic.Bool, *atomic.Uint64) {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	var drop atomic.Bool
	var dropped atomic.Uint64
	var wg sync.WaitGroup
	var mu sync.Mutex
	var connections []net.Conn
	closing := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			client, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			upstream, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: target})
			if err != nil {
				_ = client.Close()
				continue
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				_ = client.Close()
				_ = upstream.Close()
				return
			}
			connections = append(connections, client, upstream)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer client.Close()
				defer upstream.Close()
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close(); close(copied) }()
				buffer := make([]byte, 32<<10)
				for {
					n, err := upstream.Read(buffer)
					if n > 0 {
						if drop.Load() {
							dropped.Add(uint64(n))
						} else if _, err := io.CopyN(client, bytes.NewReader(buffer[:n]), int64(n)); err != nil {
							break
						}
					}
					if err != nil {
						break
					}
				}
				_ = client.Close()
				_ = upstream.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		closing = true
		for _, conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return &drop, &dropped
}
