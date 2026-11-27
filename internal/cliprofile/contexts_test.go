// SPDX-License-Identifier: Apache-2.0

package cliprofile

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPeer(t *testing.T, cluster byte, key byte, id, endpoint string) PeerIdentity {
	t.Helper()
	e, err := ParseEndpoint(endpoint, false)
	if err != nil {
		t.Fatal(err)
	}
	return PeerIdentity{Cluster: [32]byte{cluster}, Key: [32]byte{key}, ID: id, Endpoint: e}
}

func TestStoreSavesContextsAndTrustPrivatelyAndStrictly(t *testing.T) {
	home := t.TempDir()
	if _, err := OpenStore(home, false); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	st, err := OpenStore(home, true)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if c, err := st.Load(); err != nil || c.Version != 1 || len(c.Contexts) != 0 {
		t.Fatal(c, err)
	}
	if _, err := st.Resolve(""); !errors.Is(err, ErrNoContext) {
		t.Fatal(err)
	}
	cluster := [32]byte{5}
	id := hex.EncodeToString(cluster[:])
	trust, err := TrustNode(Trust{Version: 1, Cluster: id}, testPeer(t, 5, 8, "node-a", "sfcp://127.0.0.1:7443"), "fingerprint", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if trust, err = TrustNode(trust, testPeer(t, 5, 8, "node-a", "unix:///run/sfcdp.sock"), "fingerprint", time.Now()); err != nil || len(trust.Nodes) != 1 || len(trust.Nodes[0].Endpoints) != 2 {
		t.Fatal("same key at a second endpoint", trust, err)
	}
	if _, err = TrustNode(trust, testPeer(t, 5, 9, "node-a", "sfcp://127.0.0.1:7443"), "fingerprint", time.Now()); !errors.Is(err, ErrTrust) {
		t.Fatal("changed key for a trusted node", err)
	}
	if _, err = TrustNode(trust, testPeer(t, 6, 9, "node-x", "sfcp://127.0.0.1:7443"), "fingerprint", time.Now()); !errors.Is(err, ErrTrust) {
		t.Fatal("node of another cluster", err)
	}
	// A session issuer named by a trusted node that relayed a login.
	if trust, err = TrustNode(trust, testPeer(t, 5, 10, "node-b", "sfcp://10.0.0.2:7443"), "relayed-login", time.Now()); err != nil || len(trust.Nodes) != 2 || trust.Nodes[1].How != "relayed-login" {
		t.Fatal("relayed-login trust", err)
	}
	if _, err = TrustNode(trust, testPeer(t, 5, 11, "node-c", "sfcp://10.0.0.3:7443"), "told", time.Now()); !errors.Is(err, ErrTrust) {
		t.Fatal("unknown trust kind", err)
	}
	if err = st.SaveTrust(trust); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Version: 1, Current: "prod", Contexts: map[string]Context{"prod": {Endpoint: "unix:///run/sfcdp.sock", Cluster: id, User: "alice", Tenant: "shop"}}}
	if err = st.Save(cfg); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.yaml", filepath.Join("trust", id+".yaml")} {
		info, err := os.Stat(filepath.Join(home, ".sfc", name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal(name, info, err)
		}
	}
	s, err := st.Resolve("")
	if err != nil || s.ClusterName != "prod" || s.Peer != "node-a" || s.Tenant != "shop" || s.Username != "alice" || s.Cluster != cluster {
		t.Fatal(s, err)
	}
	if s.VerifyPeer(testPeer(t, 5, 8, "node-a", "unix:///run/sfcdp.sock")) != nil || s.VerifyPeer(testPeer(t, 5, 9, "node-a", "unix:///run/sfcdp.sock")) == nil {
		t.Fatal("peer verification")
	}

	// A context whose endpoint has no trusted node does not resolve.
	cfg.Contexts["moved"] = Context{Endpoint: "sfcp://10.0.0.1:7443", Cluster: id}
	if err = st.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = st.Resolve("moved"); !errors.Is(err, ErrTrust) || !strings.Contains(err.Error(), "context trust moved") {
		t.Fatal(err)
	}

	for _, bad := range []Config{
		{Version: 2},
		{Version: 1, Current: "missing"},
		{Version: 1, Contexts: map[string]Context{"default": cfg.Contexts["prod"]}},
		{Version: 1, Contexts: map[string]Context{"x": {Endpoint: "unix:///run/sfcdp.sock", Cluster: "AB" + id[2:]}}},
		{Version: 1, Contexts: map[string]Context{"x": {Endpoint: "sfcp://127.0.0.1:7443/path", Cluster: id}}},
		{Version: 1, Contexts: map[string]Context{"x": {Endpoint: "unix:///run/sfcdp.sock", Cluster: id, User: "a b"}}},
	} {
		if st.Save(bad) == nil {
			t.Fatal("invalid config saved", bad)
		}
	}
	if err = os.WriteFile(filepath.Join(home, ".sfc", "config.yaml"), []byte("version: 1\nunknown: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = st.Load(); err == nil {
		t.Fatal("unknown field accepted")
	}
	if err = st.RemoveTrust(id); err != nil || st.RemoveTrust(id) != nil {
		t.Fatal(err)
	}
	if t2, err := st.Trust(id); err != nil || len(t2.Nodes) != 0 {
		t.Fatal(t2, err)
	}
}

func TestOpenStoreRefusesSharedDirectory(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".sfc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(home, true); err == nil {
		t.Fatal("group/world readable ~/.sfc accepted")
	}
}
