// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// The lab steps for a private registry whose CA is a builtin Secret under a
// password Group, on a cluster with no Vault, through bind: the builtin
// verifier holder approves once it is an enabled issuer.
func TestBuiltinRegistryCABind(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	invoke, loadCredentials := fixtureWallet(t, home)
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(admin.Private)
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := socket.LocalAddr().String()
	_ = socket.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-a", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "state"), filepath.Join(root, "node")
	init, err := app.Initialize(ctx, cfg, admin.Public, "init-builtin-ca")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	clusterID := init.Installation.Root.Cluster
	p := control.Policy{Cluster: clusterID, BootstrapKey: admin.Public, TrustRoot: runtime.Identity.Public, Genesis: init.Installation.Genesis}
	peer := sfcp.Peer{ID: "node-a", Endpoint: address, Policy: sfcp.Policy{Key: sfcp.Identity(runtime.Identity.Public), Respond: true}}
	profile := filepath.Join(root, "client.yaml")
	if err = os.WriteFile(profile, []byte(fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", clusterID, peer.Key, address)), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(want int, args ...string) {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if code := invoke(append([]string{"--config", profile}, args...), &out, &diagnostic); code != want {
			t.Fatal("CLI", args, "exit", code, "want", want, out.String(), diagnostic.String())
		}
	}
	t.Setenv("SFC_NONINTERACTIVE", "1")
	cmd := func(want int, args ...string) string {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if code := cli.Execute(newRoot(&globals{}), append([]string{"-y"}, args...), cli.Env{In: strings.NewReader(""), Out: &out, Err: &diagnostic}); code != want {
			t.Fatal("CLI", args, "exit", code, "want", want, out.String(), diagnostic.String())
		}
		return out.String() + diagnostic.String()
	}
	saveTestContext(t, home, "lab", "admin", "sfcp://"+address, clusterID, "node-a", runtime.Identity.Public)
	t.Setenv("SFC_WALLET_PASSWORD_FILE", fixtureWalletPasswordFile(t))
	call(0, "enroll-admin", "--user-id", "admin", "--username", "admin", "--key-file", filepath.Join(root, "admin/key.pem"), "--request-id", "enroll-ca")
	call(0, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin/key.pem"))
	c := &userauth.Client{Cluster: clusterID, Peers: []sfcp.Peer{peer}}
	stored, err := loadCredentials(*c, "admin")
	if err != nil {
		t.Fatal(err)
	}
	c.Self = stored.Self
	if c.Mesh, err = sfcp.NewTransport(c.Self, clusterID, func(k sfcp.Identity) (sfcp.Peer, bool) { return peer, k == peer.Key }); err != nil {
		t.Fatal(err)
	}
	defer c.Mesh.Close()
	read := func() state.State {
		t.Helper()
		for {
			v, e := runtime.Engine().Read(ctx, true)
			if e == nil {
				return v.State
			}
			select {
			case <-ctx.Done():
				t.Fatal(e)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	apply := func(id, action string, expected uint64, payload any) {
		t.Helper()
		raw, e := control.ChangeBytes(action, stored.Session.User, expected, payload)
		if e != nil {
			t.Fatal(e)
		}
		var change control.Change
		_ = json.Unmarshal(raw, &change)
		op, e := c.Prepare(ctx, peer, stored.Session, id, change)
		if e != nil {
			t.Fatal(e)
		}
		reply, e := c.Operation(ctx, peer, op, false)
		if e != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal(action, e, reply.Result)
		}
	}
	apply("tenant", "create-tenant", 0, control.TenantID{ID: "regtest"})
	catalog, _ := p.Catalog(read())
	tenant, _ := catalog.Tenant("regtest")
	apply("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("regtest", tenant.AllowedNodes, []string{"node-a"}))
	file := func(name, value string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), name)
		if e := os.WriteFile(path, []byte(value), 0o600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	secret := func(want int, args ...string) string {
		t.Helper()
		return cmd(want, append(append([]string{"secret"}, args...), "--tenant", "regtest")...)
	}
	secret(0, "init", "regroot")
	secret(0, "group", "create", "reg", "--parent", "regroot")
	secret(0, "group", "password", "reg", "--password-file", file("pw", "private-builtin-group-password"))
	secret(0, "create", "regca", "--parent", "reg", "--key", "ca.crt")
	secret(0, "put", "regca", "--file", "ca.crt="+file("ca.crt", "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"))
	secret(0, "acl", "regca", "--allow-user", "admin")
	cmd(0, "--tenant", "regtest", "registry", "external", "add", "regpriv", "--authority", "192.168.1.102:5443", "--repository", "regtest/**", "--ca", "regca")
	bind := []string{"--tenant", "regtest", "registry", "external", "bind", "regpriv", "--node", "node-a"}
	// With no approval server, then with no tenant quota on the node, the
	// Group plan is denied and the message names both.
	if out := cmd(1, bind...); !strings.Contains(out, "secret issuer enable") || !strings.Contains(out, "tenant quota set") {
		t.Fatal("denied bind gives no hint", out)
	}
	cmd(0, "secret", "issuer", "enable", "node-a")
	cmd(1, bind...)
	cmd(0, "tenant", "quota", "set", "regtest", "node-a", "--cpu", "1", "--memory", "512MiB")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	_, _ = writer.WriteString("private-builtin-group-password")
	_ = writer.Close()
	if out := cmd(0, append(bind, "--group-password-fd", fmt.Sprintf("regtest/reg=%d", reader.Fd()))...); !strings.Contains(out, "reads through node-a") {
		t.Fatal("bind", out)
	}
}
