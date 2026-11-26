// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/tests/vaultfixture"
	"gopkg.in/yaml.v3"
)

func TestRealBoundaryManagedRemoteAppInputs(t *testing.T) {
	testRealManagedAppOwner(t, true, true, true, true, true, true, false, true)
}

func prepareRemoteInputProvider(t *testing.T, ctx context.Context, root string, consumer *Runtime, user userauth.Client, source mydcp.Peer, session access.Session, read func() cluster.View, change func(string, string, uint64, any), v *vaultfixture.Vault, native bool, dockerEndpoint string, configure ...func(*config.Node)) *Runtime {
	t.Helper()
	u, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := u.LocalAddr().String()
	_ = u.Close()
	path := filepath.Join(root, "provider-node.yaml")
	doc := fmt.Sprintf("version: 1\nnode: {id: node-b, listen: %q, state_dir: %q, identity_dir: %q}\nmodules: {network: {enabled: false}, workload: {enabled: false}, ingress: {enabled: false}}\n", address, filepath.Join(root, "provider-state"), filepath.Join(root, "provider-key"))
	if native {
		doc = strings.Replace(doc, "network: {enabled: false}, workload: {enabled: false}", "network: {enabled: true, docker_socket: 'unix:///var/run/docker.sock'}, workload: {enabled: true}", 1)
		if dockerEndpoint != "" {
			doc = strings.Replace(doc, "'unix:///var/run/docker.sock'", fmt.Sprintf("%q", dockerEndpoint), 1)
		}
	}
	if err = os.WriteFile(path, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadNode(path)
	if err != nil {
		t.Fatal(err)
	}
	installManagedVault(t, &cfg, root, v)
	for _, configure := range configure {
		configure(&cfg)
	}
	if len(configure) != 0 {
		raw, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal("save original configured provider", err)
		}
	}
	key, err := identity.Create(cfg.Node.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	change("invite-input-provider", "invite-node", 0, control.NodeInvitation{Peer: config.Peer{ID: "node-b", Key: key.Actor(), Endpoint: address}, JoinID: "join-input-provider"})
	inv, err := user.NodeInvitation(ctx, source, session, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := Join(ctx, cfg, inv, user.Cluster, consumer.Identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	if len(consumer.vaultBackends) != 0 || len(r.vaultBackends) != 2 {
		t.Fatal("consumer must have no installed Vault credentials")
	}
	return r
}

func verifyRemoteInputBoundary(t *testing.T, ctx context.Context, consumer, provider *Runtime, user userauth.Client, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	execution, _ := apps.Execution("tenant", "app")
	stage, _ := execution.Stage(deployment.ResourceKey("task", "tenant", "app", "web"))
	ref := deployment.ObjectRef{Key: stage.Command.Key, Generation: stage.Result.Generation, Revision: stage.Result.Revision}
	b, ok := apps.Binding(ref)
	if !ok {
		t.Fatal("missing original remote consumer binding")
	}
	request := control.AppBindingRequest{Task: ref, Digest: b.Digest(), At: time.Now().Unix()}
	permit, err := consumer.appInputPermit(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	q := control.AppInputFetch{Schema: 1, Consumer: consumer.Identity.Public, Binding: request, ReadSet: permit.ReadSet, MinimumIndex: permit.CommandIndex, Realm: "tenant", Secret: "data"}
	vault, err := p.Vault(read().State)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := vault.Trees["tenant"].WriteProfile("values")
	value, err := consumer.fetchAppInputLeaf(ctx, q, profile)
	if err != nil || !bytes.Equal(value.Values["DB_PASSWORD"], []byte("private-db-value")) {
		t.Fatal("actual remote protected read", err)
	}
	for _, v := range value.Values {
		clear(v)
	}
	bad := q
	bad.Secret = "not-selected"
	if _, err = consumer.fetchAppInputLeaf(ctx, bad, profile); err == nil {
		t.Fatal("unapproved leaf returned")
	}
	bad = q
	bad.ReadSet[0] ^= 1
	if _, err = consumer.fetchAppInputLeaf(ctx, bad, profile); err == nil {
		t.Fatal("stale read set returned")
	}
	// A user transport cannot impersonate the Task owner, even with a public
	// valid binding/read-set copied from the accepted application.
	peer, _ := consumer.Mesh.Peer(mydcp.Identity(provider.Identity.Public))
	public, _ := json.Marshal(q)
	rogue, err := mydcp.NewTransport(user.Self, user.Cluster, func(k mydcp.Identity) (mydcp.Peer, bool) { return peer, k == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	defer rogue.Close()
	s, err := rogue.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.FetchSecret(ctx, public); err == nil {
		t.Fatal("user obtained node private value")
	}
	profile.Enabled = false
	profile.Revision = 0
	change("disable-remote-value-provider", "vault-set-profile", vault.Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: profile})
	if _, err = consumer.fetchAppInputLeaf(ctx, q, profile); err == nil {
		t.Fatal("disabled provider returned values")
	}
	vault, _ = p.Vault(read().State)
	profile, _ = vault.Trees["tenant"].WriteProfile("values")
	profile.Enabled = true
	profile.Revision = 0
	change("restore-remote-value-provider", "vault-set-profile", vault.Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: profile})
	if _, err = consumer.fetchAppInputLeaf(ctx, q, profile); err == nil {
		t.Fatal("provider revision change reused stale read set")
	}
	request.At = time.Now().Unix()
	permit, err = consumer.appInputPermit(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	q.Binding = request
	q.ReadSet = permit.ReadSet
	q.MinimumIndex = permit.CommandIndex
	value, err = consumer.fetchAppInputLeaf(ctx, q, profile)
	if err != nil {
		t.Fatal("current restored provider read", err)
	}
	for _, v := range value.Values {
		clear(v)
	}
	snapshot, err := state.Encode(read().State)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range [][]byte{[]byte("private-db-value"), []byte(base64.StdEncoding.EncodeToString([]byte("private-db-value")))} {
		if bytes.Contains(snapshot, needle) {
			t.Fatal("private value entered shared state")
		}
	}
	t.Log("actual remote Vault read into consumer without credentials; user/other leaf/stale provider denied; original Task/input scope and public-only shared metadata preserved")
}
