// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func verifyRealVaultReplacementWriter(t *testing.T, ctx context.Context, root string, originalCfg config.Node, original *app.Runtime, user userauth.Client, source mydcp.Peer, session access.Session, current func() control.Vault, read func() state.State, apply func(string, string, uint64, any, state.Code) control.UserOperation, v *ownedVault, oldToken string, puts *atomic.Int32, id string, value []byte) {
	t.Helper()
	w, ok := current().Trees["tenant"].Write(id)
	if !ok || w.Status() != "Unknown" || w.Writer.Key != original.Identity.Public || puts.Load() != 1 {
		t.Fatal("original real provider Unknown")
	}
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	cfg := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{"network": {}, "workload": {}, "ingress": {}}}
	cfg.Node.ID, cfg.Node.Listen = "node-b", address
	cfg.Node.StateDir, cfg.Node.IdentityDir = filepath.Join(root, "replacement-state"), filepath.Join(root, "replacement-key")
	key, err := identity.Create(cfg.Node.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	var issued struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	v.api("POST", "auth/token/create", map[string]any{"policies": []string{"mydc-app-writer"}, "no_default_policy": true, "ttl": "5m"}, &issued, v.admin)
	if issued.Auth.Token == "" {
		t.Fatal("replacement provider credential")
	}
	tokenPath := filepath.Join(root, "replacement-provider-token")
	if err := os.WriteFile(tokenPath, []byte(issued.Auth.Token), 0600); err != nil {
		t.Fatal(err)
	}
	local := originalCfg.Vaults[0]
	local.TokenFile = tokenPath
	cfg.Vaults = []config.VaultBackend{local}
	apply("replacement-invite", "invite-node", 0, control.NodeInvitation{Peer: config.Peer{ID: "node-b", Key: key.Actor(), Endpoint: address}, JoinID: "replacement-join"}, state.Applied)
	inv, err := user.NodeInvitation(ctx, source, session, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	b, installed, err := app.Join(ctx, cfg, inv, user.Cluster, original.Identity.Public)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if b != nil {
			if err := b.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	peer := mydcp.Peer{ID: "node-b", Endpoint: address, Policy: mydcp.Policy{Key: mydcp.Identity(key.Public), Respond: true}}
	remote := user
	remote.Peers = append(append([]mydcp.Peer(nil), user.Peers...), peer)
	remote.Mesh, err = mydcp.NewTransport(user.Self, user.Cluster, func(k mydcp.Identity) (mydcp.Peer, bool) {
		if k == peer.Key {
			return peer, true
		}
		return source, k == source.Key
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Mesh.Close()
	profile, _ := current().Trees["tenant"].WriteProfile("values")
	profile.Node, profile.Key, profile.Revision = "node-b", key.Public, 0
	apply("replacement-profile", "vault-set-profile", current().Trees["tenant"].Revision(), control.VaultProfile{Realm: "tenant", Profile: profile}, state.Applied)
	// The old provider credential is really revoked at Vault. Control remains
	// the existing quorum; writer placement and control leadership are distinct.
	v.api("POST", "auth/token/revoke", map[string]any{"token": oldToken}, nil, v.admin)
	if _, err := user.WriteVault(ctx, source, session, userauth.SecretRequest{Realm: "tenant", ID: id, Mode: "recover"}); err == nil {
		t.Fatal("old writer remained authorized")
	}
	if _, err := remote.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "tenant", ID: id, Mode: "execute", Values: map[string][]byte{"key": []byte("must-not-overwrite")}}); err == nil {
		t.Fatal("replacement writer was allowed a new PUT for original Unknown")
	}
	recovered, err := remote.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "tenant", ID: id, Mode: "recover"})
	if err != nil || recovered.VaultObservation == nil {
		t.Fatal("replacement original read-back", err)
	}
	fact := *recovered.VaultObservation
	if fact.Outcome != reconcile.EffectApplied || fact.Writer != w.Writer || !reflect.DeepEqual(fact.Request, w.Request) || fact.Operation != w.Journal.LastID || fact.Observer.Key != key.Public || fact.Observer.Node != "node-b" || fact.ProviderRevision != 1 || !ed25519.Verify(key.Public[:], secrets.WriteObservationBytes(fact), fact.Signature) || puts.Load() != 1 {
		t.Fatal("replacement changed original intent/result or issued a PUT")
	}
	apply("replacement-observe", "vault-observe-write", current().Trees["tenant"].Revision(), control.VaultObserve{Observation: fact}, state.Applied)
	stored, _ := current().Trees["tenant"].Write(id)
	if stored.Status() != "StoredUnreferenced" || stored.Writer != w.Writer || stored.Journal.LastID != w.Journal.LastID {
		t.Fatal("replacement falsely published/rebound original")
	}
	apply("replacement-publish", "vault-publish-write", current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: id, Epoch: w.Request.Epoch, ObjectRevision: w.ExpectedObjectRevision}, state.Applied)
	if err := b.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b = nil
	b, err = app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if resumed, err := b.ResumeInstallation(ctx); err != nil || !reflect.DeepEqual(resumed.Ack, installed.Ack) {
		t.Fatal("same replacement DB/key/ACK", err)
	}
	post, err := remote.WriteVault(ctx, peer, session, userauth.SecretRequest{Realm: "tenant", ID: id, Mode: "recover"})
	if err != nil || post.VaultObservation == nil || !bytes.Equal(secrets.WriteObservationBytes(*post.VaultObservation), secrets.WriteObservationBytes(fact)) || !bytes.Equal(post.VaultObservation.Signature, fact.Signature) || puts.Load() != 1 {
		t.Fatal("replacement restart lost original result", err)
	}
	public, err := state.Encode(read())
	if err != nil || bytes.Contains(public, value) || bytes.Contains(public, []byte("must-not-overwrite")) || bytes.Contains(public, []byte(oldToken)) || bytes.Contains(public, []byte(issued.Auth.Token)) {
		t.Fatal("private provider input/credential entered shared state", err)
	}
	final, _ := current().Trees["tenant"].Write(id)
	object, _ := current().Trees["tenant"].Object(w.Request.Object)
	if final.Status() != "Published" || final.Writer != w.Writer || !reflect.DeepEqual(final.Request, w.Request) || object.Reference.Revision != 1 || final.Observation.Observer.Key != key.Public {
		t.Fatal("original fixed version/reference not retained")
	}
	t.Log("real original PUT succeeded once with response loss; shared/local Unknown and Snapshot/same DB preserved original; independently admitted Runtime B with separate Vault credential/current profile recovered only original provider receipt; old credential revoked/old node denied and replacement execute denied; signed replacement observer/current CAS publication retained original writer/ID/operation/version; same B DB/key/ACK recovered identical signed result with PUT count1 and no private shared fields")
}
