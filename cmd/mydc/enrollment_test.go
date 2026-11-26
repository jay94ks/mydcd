// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func TestRealManagedEnrollmentCLIAndSameRoot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	if err := os.Mkdir(filepath.Join(root, "home"), 0700); err != nil {
		t.Fatal(err)
	}
	invoke, loadCredentials := fixtureWallet(t, filepath.Join(root, "home"))
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(admin.Private)
	wrongKey, err := identity.Create(filepath.Join(root, "wrong"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wrongKey.Private)
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	c := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	c.Node.ID, c.Node.Listen = "node-a", address
	c.Node.StateDir, c.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node-key")
	initialized, err := app.Initialize(ctx, c, admin.Public, "init-one")
	if err != nil {
		t.Fatal(err)
	}
	if !initialized.AwaitingAdmin || initialized.Users != 0 || initialized.Tenants != 0 {
		t.Fatal("implicit initial account/tenant")
	}
	runtime, err := app.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if runtime != nil {
			_ = runtime.Close()
		}
	}()
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	clusterID := initialized.Installation.Root.Cluster
	profilePath := filepath.Join(root, "client.yaml")
	profile := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n  - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", clusterID, initialized.Installation.Root.Self.Key, address)
	if err = os.WriteFile(profilePath, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(want int, args ...string) string {
		t.Helper()
		var out, diag bytes.Buffer
		code := invoke(append([]string{"--config", profilePath}, args...), &out, &diag)
		if code != want {
			t.Fatal("CLI exit", args, code, want, out.String(), diag.String())
		}
		if strings.Contains(out.String(), "Signature") || strings.Contains(out.String(), "Seed") || strings.Contains(out.String(), "PRIVATE KEY") {
			t.Fatal("private state printed")
		}
		return out.String()
	}
	policy := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public}
	read := func() cluster.View {
		t.Helper()
		v, err := runtime.Engine().Read(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	call(3, "login", "--username", "operator", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	call(3, "enroll-admin", "--user-id", "admin-one", "--username", "operator", "--key-file", filepath.Join(root, "wrong", "key.pem"), "--request-id", "enroll-one")
	// Claim the RIGHT bootstrap key while supplying a wrong signature, a
	// different connection challenge, or a different TLS identity binding.
	eph, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(eph.Private)
	rootPeer := mydcp.Peer{ID: "node-a", Endpoint: address, Policy: mydcp.Policy{Key: mydcp.Identity(initialized.Installation.Root.Self.Key), Respond: true}}
	proofMesh, err := mydcp.NewTransport(eph, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return rootPeer, k == rootPeer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer proofMesh.Close()
	conn, err := proofMesh.Dial(ctx, rootPeer)
	if err != nil {
		t.Fatal(err)
	}
	intent := control.Enrollment{Schema: 1, RequestID: "enroll-one", User: access.User{ID: "admin-one", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}}}
	body, _ := json.Marshal(userauth.Request{Schema: 1, Method: "enroll-admin", UserKey: admin.Public, Enrollment: &intent, Nonce: [32]byte{1}})
	for i := 0; i < 3; i++ {
		key, challenge, signer := eph.Public, conn.PeerChallenge(), admin.Private
		if i == 0 {
			signer = wrongKey.Private
		}
		if i == 1 {
			challenge = [32]byte{99}
		}
		if i == 2 {
			key = [32]byte{99}
		}
		envelope, _ := json.Marshal(userauth.Envelope{Body: body, Signature: ed25519.Sign(signer, userauth.EnrollmentBytes(clusterID, key, challenge, body))})
		digest := sha256.Sum256(envelope)
		stream, err := conn.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.User, Kind: 1, Request: proofMesh.NextRequest(), Fields: []mydcp.Field{{Tag: 1, Required: true, Value: envelope}, {Tag: 2, Required: true, Value: digest[:]}}}); err != nil {
			t.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			t.Fatal("request EOF", err)
		}
		frame, err := mydcp.ReadFrame(stream, 128<<10)
		stream.CancelRead(0)
		_ = stream.Close()
		if err != nil {
			t.Fatal(err)
		}
		var reply userauth.Reply
		if json.Unmarshal(frame.Fields[0].Value, &reply) != nil || reply.Code != "denied" {
			t.Fatal("bootstrap proof binding bypass", i)
		}
	}
	before := read()
	first := call(0, "enroll-admin", "--user-id", "admin-one", "--username", "operator", "--key-file", filepath.Join(root, "admin", "key.pem"), "--request-id", "enroll-one")
	after := read()
	if after.State.Index() != before.State.Index()+1 {
		t.Fatal("enrollment did not commit exactly once")
	}
	second := call(0, "enroll-admin", "--user-id", "admin-one", "--username", "operator", "--key-file", filepath.Join(root, "admin", "key.pem"), "--request-id", "enroll-one")
	var a, b struct{ Result state.Result }
	if json.Unmarshal([]byte(first), &a) != nil || json.Unmarshal([]byte(second), &b) != nil || a.Result != b.Result || read().State.Index() != after.State.Index() {
		t.Fatal("original enrollment replay changed receipt/state")
	}
	call(3, "enroll-admin", "--user-id", "another-admin", "--username", "other", "--key-file", filepath.Join(root, "admin", "key.pem"), "--request-id", "new-enrollment")
	cat, err := policy.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	users, tenants := cat.Counts()
	if users != 1 || tenants != 0 || cat.AwaitingAdmin() {
		t.Fatal("bootstrap anchor not consumed")
	}
	peer := mydcp.Peer{ID: "node-a", Endpoint: address, Policy: mydcp.Policy{Key: mydcp.Identity(initialized.Installation.Root.Self.Key), Respond: true}}
	// The enrollment anchor proves that one fact, not legacy node management.
	anchor, err := identity.FromSeed(admin.Private.Seed())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(anchor.Private)
	mesh, err := mydcp.NewTransport(anchor, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	escape := state.Command{Actor: admin.Actor(), Epoch: 1, RequestID: "bootstrap-escape", Key: "network/escape", Value: "forbidden"}
	encoded, _ := state.EncodeCommand(escape)
	if _, err = cluster.CallManagement(ctx, mesh, anchor, clusterID, peer, cluster.ManagementRequest{Method: "submit", Latest: true, Command: encoded}); err == nil {
		t.Fatal("managed bootstrap key gained legacy management")
	}
	if read().State.Object(escape.Key).Present {
		t.Fatal("bootstrap escape changed state")
	}
	call(0, "login", "--username", "operator", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
	call(0, "whoami")
	client := userauth.Client{Cluster: clusterID, Peers: []mydcp.Peer{peer}}
	stored, err := loadCredentials(client, "operator")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(stored.Self.Private)
	client.Self = stored.Self
	client.Mesh, err = mydcp.NewTransport(client.Self, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Mesh.Close()
	raw, _ := control.ChangeBytes("create-tenant", stored.Session.User, 0, control.TenantID{ID: "tenant-one"})
	var change control.Change
	_ = json.Unmarshal(raw, &change)
	op, err := client.Prepare(ctx, peer, stored.Session, "first-tenant", change)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.Operation(ctx, peer, op, false)
	if err != nil || created.Result == nil || created.Result.Code != state.Applied {
		t.Fatal("explicit first tenant", created.Code, err)
	}
	cat, err = policy.Catalog(read().State)
	tenant, found := cat.Tenant("tenant-one")
	if err != nil || !found || len(tenant.ImageSources) != 1 || tenant.ImageSources[0].Registry != "docker.io" || tenant.ImageSources[0].Repository != "**" {
		t.Fatal("tenant did not initialize Docker Hub exactly once", err)
	}
	// All query adapters consume one committed catalog/root view. No native
	// workload is required to prove empty-page, metadata and denial wire shapes.
	queryView := read()
	for _, method := range []string{"whoami", "registries", "lifecycles", "node-storage", "resources", "volumes", "volume-backups", "volume-restores", "vault", "apps", "app-uploads"} {
		tenantID := "tenant-one"
		if method == "whoami" || method == "node-storage" {
			tenantID = ""
		}
		reply, queryErr := client.Query(ctx, peer, stored.Session, method, tenantID)
		if queryErr != nil || reply.Code != "ok" || reply.RootRevision != queryView.State.Object(control.CatalogKey).Revision {
			t.Fatal("actual query adapter", method, reply.Code, queryErr)
		}
		raw, marshalErr := json.Marshal(reply)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		rootField, rootKey := "", ""
		switch method {
		case "registries":
			rootField, rootKey = "RegistriesRootRevision", control.RegistriesKey
		case "lifecycles":
			rootField, rootKey = "LifecycleRootRevision", control.LifecycleKey
		case "node-storage":
			rootField, rootKey = "NodeStorageRootRevision", control.NodeStorageKey
		case "resources":
			rootField, rootKey = "ResourcesRootRevision", control.ResourcesKey
		case "volumes", "volume-backups", "volume-restores":
			rootField, rootKey = "VolumesRootRevision", control.VolumesKey
		case "vault":
			rootField, rootKey = "VaultRootRevision", control.VaultKey
		case "apps", "app-uploads":
			rootField, rootKey = "AppsRootRevision", control.AppsKey
		}
		if rootKey != "" {
			var revision uint64
			if value, exists := fields[rootField]; exists {
				if err = json.Unmarshal(value, &revision); err != nil {
					t.Fatal(err)
				}
			}
			if revision != queryView.State.Object(rootKey).Revision {
				t.Fatal("query root changed", method, revision)
			}
		}
		if strings.Contains(string(raw), "\"Resources\":null") || strings.Contains(string(raw), "\"Volumes\":null") {
			t.Fatal("empty pages lost omitempty")
		}
	}
	if denied, e := client.RegistryPage(ctx, peer, stored.Session, "", ""); e == nil || denied.Code != "denied" {
		t.Fatal("missing tenant accepted", denied.Code, e)
	}
	if denied, e := client.ResourcePage(ctx, peer, stored.Session, "tenant-one", strings.Repeat("a", 513)); e == nil || denied.Code != "denied" {
		t.Fatal("oversized cursor accepted", denied.Code, e)
	}
	if err = runtime.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime = nil
	runtime, err = app.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	// Configuration installation can precede the new local Raft election.
	// Wait for the actual current-state barrier, without resubmitting a command.
	for {
		if _, e := runtime.Engine().Read(ctx, true); e == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	call(0, "whoami")
	call(0, "enroll-admin", "--user-id", "admin-one", "--username", "operator", "--key-file", filepath.Join(root, "admin", "key.pem"), "--request-id", "enroll-one")
	cat, err = policy.Catalog(read().State)
	users, tenants = cat.Counts()
	if err != nil || users != 1 || tenants != 1 {
		t.Fatal("same DB lost original account/tenant", err)
	}
}
