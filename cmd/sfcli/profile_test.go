// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cliprofile"
)

// testContext saves context "prod" (current) for cluster {5} with node-a
// trusted at sfcp://127.0.0.1:7443 and node-b elsewhere.
func testContext(t *testing.T, home string) {
	t.Helper()
	store, err := cliprofile.OpenStore(home, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cluster := [32]byte{5}
	id := hex.EncodeToString(cluster[:])
	trust := cliprofile.Trust{Version: 1, Cluster: id}
	for i, n := range []struct{ id, endpoint string }{{"node-a", "sfcp://127.0.0.1:7443"}, {"node-b", "sfcp://127.0.0.1:7444"}} {
		e, _ := cliprofile.ParseEndpoint(n.endpoint, false)
		if trust, err = cliprofile.TrustNode(trust, cliprofile.PeerIdentity{Cluster: cluster, Key: [32]byte{byte(8 + i)}, ID: n.id, Endpoint: e}, "out-of-band", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err = store.SaveTrust(trust); err != nil {
		t.Fatal(err)
	}
	c := cliprofile.Config{Version: 1, Current: "prod", Contexts: map[string]cliprofile.Context{
		"prod": {Endpoint: "sfcp://127.0.0.1:7443", Cluster: id, User: "alice", Tenant: "shop"},
	}}
	if err = store.Save(c); err != nil {
		t.Fatal(err)
	}
}

func TestResolveCommandProfileUsesCurrentContextAndItsTrust(t *testing.T) {
	home := t.TempDir()
	if _, err := resolveCommandProfile(home, "", "", ""); !errors.Is(err, cliprofile.ErrNoContext) {
		t.Fatal("missing store is not 'no context'", err)
	}
	testContext(t, home)
	selected, err := resolveCommandProfile(home, "", "", "")
	if err != nil || selected.Context != "prod" || selected.Target.Peer != "node-a" || selected.Target.Tenant != "shop" || len(selected.Client.Peers) != 2 || selected.Client.Peers[0].Endpoint != "127.0.0.1:7443" {
		t.Fatal(selected, err)
	}
	if selected, err = resolveCommandProfile(home, "prod", "", "other"); err != nil || selected.Target.Tenant != "other" {
		t.Fatal("--tenant did not replace the context's tenant", selected.Target.Tenant, err)
	}
	if _, err = resolveCommandProfile(home, "missing", "", ""); !errors.Is(err, cliprofile.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestResolveCommandProfileExplicitFileNeverFallsBack(t *testing.T) {
	home := t.TempDir()
	testContext(t, home)
	file := filepath.Join(t.TempDir(), "client.yaml")
	cluster, key := [32]byte{6}, [32]byte{8}
	text := "version: 1\nauth: user\ncluster: '" + hex.EncodeToString(cluster[:]) + "'\npeers:\n  - {id: old, key: '" + hex.EncodeToString(key[:]) + "', endpoint: '127.0.0.1:9000', voter: true}\n"
	if err := os.WriteFile(file, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	selected, err := resolveCommandProfile(home, "", file, "actual-tenant")
	if err != nil || selected.Client.Cluster != hex.EncodeToString(cluster[:]) || selected.Target.Tenant != "actual-tenant" || selected.Context != "" {
		t.Fatal(selected, err)
	}
	if _, err := resolveCommandProfile(home, "prod", file, ""); !errors.Is(err, cliprofile.ErrSelection) {
		t.Fatal("context and file together", err)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveCommandProfile(home, "", file, ""); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("missing explicit file used the current context", err)
	}
}
